package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/requestutils"
	"github.com/VITObelgium/fakes3pp/usererror"
	"github.com/VITObelgium/fakes3pp/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
)

const L_AUTH_TYPE = "AuthType"
const L_AKID = "AKID"  // Access Key ID

//Authentication middleware is responsible for the following:
//Add the authentication type to the access log
//Verify signature and its expiry as part of authentication
//Add Access Key Id to access log
//Add Session token to request context
//Add Region to request context (as it is in parts that might be cleaned up)
//Cleanup the request to not have lingering parts that could cause issues with request downstream.
func AWSAuthN(keyStorage utils.PrivateKeyKeeper, e service.ErrorReporter, backendManager interfaces.BackendManager) Middleware {
    return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var shouldContinue bool
			if IsPresignedAWSRequest(r) {
				shouldContinue = handleAuthNPresigned(w, r, keyStorage, e, backendManager)
			} else {
				shouldContinue = handleAuthNNormal(w, r, keyStorage, e, backendManager)
			}
			if shouldContinue {
				next(w, r)
			}
		}
	}
}

//Authenticate a presigned request see responsibilities AWSAuthN
func handleAuthNPresigned(w http.ResponseWriter, r *http.Request, keyStorage utils.PrivateKeyKeeper, e service.ErrorReporter, backendManager interfaces.BackendManager) bool {
	requestctx.AddAccessLogInfo(r, "s3", slog.String(L_AUTH_TYPE, "QueryString"))

	var isValid bool
	var expires time.Time

	var secretDeriver = func(accessKeyId string) (secretAccessKey string, err error) {
		return credentials.CalculateSecretKey(accessKeyId, keyStorage)
	}

	presignedUrl, err := presign.MakePresignedUrl(r)
	if err != nil {
		err := fmt.Errorf("could not get presigned url: %w", err)
		e.WriteErrorResponse(r.Context(), w, service.ErrAWSInternalError, err)
		return false
	}
	isValid, creds, expires, err:= presignedUrl.GetPresignedUrlDetails(r.Context(), secretDeriver)
	if err != nil {
		err := fmt.Errorf("error geting details of presigned url: %w", err)
		e.WriteErrorResponse(r.Context(), w, service.ErrAWSInternalError, err)
		return false
	}
	requestctx.AddAccessLogInfo(r, "s3", slog.String(L_AKID, creds.AccessKeyID))
	requestctx.SetSessionToken(r, creds.SessionToken)

	addRegionToSession(r, backendManager)

	// If url has gone passed expiry time (under user control)
	if expires.Before(time.Now().UTC()) {
		slog.InfoContext(r.Context(), "Encountered expired URL", "expires", expires)
		userErr := usererror.New(errors.New("expired URL"), "Expired URL")
		e.WriteErrorResponse(r.Context(), w, service.ErrAWSInvalidSignature, userErr)
		return false
	}

	if !isValid {
		e.WriteErrorResponse(r.Context(), w, service.ErrAWSAccessDenied, errors.New("failed authentication S3 signature"))
		return false
	}

	//Then make sure query parameters are no longer passed otherwise you can get 'InvalidAccessKeyId'
	queryPart := fmt.Sprintf("?%s", r.URL.RawQuery)
	r.RequestURI = strings.Replace(r.RequestURI, queryPart, "", 1)
	r.URL.RawQuery = ""

	cleanHeadersThatAreNotSignedInAuthHeader(r)
	r.Header.Add(constants.AmzContentSHAKey, constants.EmptyStringSHA256)

	return true
}

func IsPresignedAWSRequest(r *http.Request) (bool){
	queryValues := r.URL.Query()
	if queryValues.Has("Signature") && queryValues.Has("x-amz-security-token") && queryValues.Has("AWSAccessKeyId") {
		return true
	}
	if queryValues.Has("X-Amz-Algorithm") && queryValues.Has("X-Amz-Signature") {
		return true
	}
	return false
}

func addRegionToSession(r *http.Request, backendManager interfaces.BackendManager) {
	targetBackendId := requestutils.GetRegionFromRequest(r, backendManager.GetDefaultBackend())
	requestctx.SetTargetRegion(r, targetBackendId)
	requestctx.AddAccessLogInfo(r, "s3", slog.String("TargetRegion", targetBackendId))
}

//Authenticate a normal request see responsibilities AWSAuthN
func handleAuthNNormal(w http.ResponseWriter, r *http.Request, keyStorage utils.PrivateKeyKeeper, e service.ErrorReporter, backendManager interfaces.BackendManager) bool {
	if r.Header.Get(constants.AuthorizationHeader) == "" {
		requestctx.AddAccessLogInfo(r, "s3", slog.String("AuthType", "-"))
	} else {
		requestctx.AddAccessLogInfo(r, "s3", slog.String("AuthType", "AuthHeader"))
	}

	accessKeyId, sessionToken, err := getCredentialsFromRequest(r)
	if err != nil {
		err := fmt.Errorf("could not get credentials from request: %w", err)
		e.WriteErrorResponse(r.Context(), w, service.ErrAuthorizationHeaderMalformed, err)
		return false
	}
	requestctx.AddAccessLogInfo(r, "s3", slog.String(L_AKID, accessKeyId))
	requestctx.SetSessionToken(r, sessionToken)

	addRegionToSession(r, backendManager)

	secretAccessKey, err := credentials.CalculateSecretKey(accessKeyId, keyStorage)
	if err != nil {
		err := fmt.Errorf("could not calculate secret key: %w", err)
		e.WriteErrorResponse(r.Context(), w, service.ErrAWSInternalError, err)
		return false
	}
	backupContentLength := r.ContentLength
	//There is no use of passing the headers that are set by a proxy and which we haven't verified.
	cleanHeadersThatAreNotSignedInAuthHeader(r)
	clonedReq := r.Clone(r.Context())
	creds := aws.Credentials{
		AccessKeyID: accessKeyId,
		SecretAccessKey: secretAccessKey,
		SessionToken: sessionToken,
	}
	err = presign.SignWithCreds(r.Context(), clonedReq, creds, "ThisShouldNotBeUsedForSigv4Requests258")
	if err != nil {
		err := fmt.Errorf("could not sign request: %w", err)
		e.WriteErrorResponse(r.Context(), w, service.ErrAWSInternalError, err)
		return false
	}
	calculatedSignature := clonedReq.Header.Get(constants.AuthorizationHeader) 
	passedSignature := r.Header.Get(constants.AuthorizationHeader)
	//Cleaning could have removed content length
	r.ContentLength = backupContentLength

	if calculatedSignature != passedSignature {
		slog.DebugContext(
			r.Context(),
			"Invalid signature", 
			"calculated", calculatedSignature, 
			"received", passedSignature,
		)
		e.WriteErrorResponse(r.Context(), w, service.ErrAWSInvalidSignature, nil)
		return false
	}
	return true
}

//For requests the access key and token are send over the wire
func getCredentialsFromRequest(r *http.Request) (accessKeyId, sessionToken string, err error) {
	sessionToken = r.Header.Get(constants.AmzSecurityTokenKey)
	accessKeyId, err = requestutils.GetSignatureCredentialPartFromRequest(r, requestutils.CredentialPartAccessKeyId)
	return
}

//cleanHeadersThatAreNotSignedInAuthHeader removes headers which are potentially added along the way
//
func cleanHeadersThatAreNotSignedInAuthHeader(req *http.Request) {
	signedHeaders := getSignedHeadersFromRequest(req)

	presign.CleanHeadersTo(req.Context(), req, signedHeaders)
}

const signedHeadersPrefix = "SignedHeaders="

func getSignedHeadersFromRequest(req *http.Request) (signedHeaders map[string]string) {
	signedHeaders = map[string]string{}
	ah := req.Header.Get(constants.AuthorizationHeader)
	if ah == "" {
		return
	}
	authorizationParts := strings.Split(ah, ", ")
	if len(authorizationParts) != 3 {
		slog.WarnContext(req.Context(), "Signature not as expected", "got", ah)
	}
	signedHeadersPart := authorizationParts[1]
	if !strings.HasPrefix(signedHeadersPart, signedHeadersPrefix) {
		slog.WarnContext(req.Context(), "Signature did not have expected signed headers prefix", "got", ah)
	}
	signedHeadersPart = signedHeadersPart[len(signedHeadersPrefix):]
	for _, signedHeader := range strings.Split(signedHeadersPart, ";") {
		signedHeaders[signedHeader] = ""
	}
	return signedHeaders
}