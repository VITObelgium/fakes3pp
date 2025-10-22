package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/requestctx/authtypes"
	"github.com/VITObelgium/fakes3pp/requestutils"
	"github.com/VITObelgium/fakes3pp/usererror"
	"github.com/VITObelgium/fakes3pp/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/golang-jwt/jwt/v5"
)

const L_AKID = "AKID"  // Access Key ID

//Authentication middleware is responsible for the following:
//Add the authentication type to the access log
//Verify signature and its expiry as part of authentication
//Add Access Key Id to access log
//Add Session token to request context
//Add Region to request context (as it is in parts that might be cleaned up)
//Cleanup the request to not have lingering parts that could cause issues with request downstream.
func AWSAuthN(keyStorage utils.KeyPairKeeper, e service.ErrorReporter, backendManager interfaces.BackendManager, presignOptions *AuthenticationOptions) Middleware {
    return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var shouldContinue bool
			if IsPresignedAWSRequest(r) {
				shouldContinue = handleAuthNPresigned(w, r, keyStorage, e, backendManager, presignOptions)
			} else {
				shouldContinue = handleAuthNNormal(w, r, keyStorage, e, backendManager)
			}
			if shouldContinue {
				next(w, r)
			}
		}
	}
}

func cleanRemovableQueryParameters(r *http.Request, presignAuthOptions *AuthenticationOptions) {
	urlVals := r.URL.Query()
	
	for urlValKey, _ := range urlVals {
		for _, keyToRemove := range presignAuthOptions.RemovableQueryParams {
			matchedString := keyToRemove.FindString(urlValKey)
			if matchedString != "" {
				slog.DebugContext(r.Context(), "Found key that should be removed", "keyToRemoveRegex", keyToRemove, "matched", matchedString)
				urlVals.Del(urlValKey)
			}
		}
	}
	r.URL.RawQuery = urlVals.Encode()
}

//Authenticate a presigned request see responsibilities AWSAuthN
func handleAuthNPresigned(w http.ResponseWriter, r *http.Request, keyStorage utils.KeyPairKeeper, e service.ErrorReporter, backendManager interfaces.BackendManager, presignAuthOptions *AuthenticationOptions) bool {
	requestctx.SetAuthType(r, authtypes.AuthTypeQueryString)
	cleanRemovableQueryParameters(r, presignAuthOptions)

	var isValid bool
	var expires time.Time

	var secretDeriver = func(accessKeyId string) (secretAccessKey string, err error) {
		return credentials.CalculateSecretKey(accessKeyId, keyStorage)
	}
	var toCheck *http.Request = r

	if r.URL.Query().Get(constants.HeadAsGet) != "" {
		defer func(){
			//Always remove the Proxy query parameter
			urlVals := r.URL.Query()
			urlVals.Del(constants.HeadAsGet)
			r.URL.RawQuery = urlVals.Encode()
		}()
		if strings.ToLower(r.URL.Query().Get(constants.HeadAsGet)) == "true" && r.Method == http.MethodHead {
			toCheck = r.Clone(r.Context())
			toCheck.Method = http.MethodGet
		}
	}

	presignedUrl, err := presign.MakePresignedUrl(toCheck)
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

	err = makeSureSessionTokenIsForAccessKey(creds.SessionToken, creds.AccessKeyID, keyStorage.GetJwtKeyFunc(), presignAuthOptions)
	if err != nil {
		err := fmt.Errorf("error when making sure session token corresponds to used credential pair: %w", err)
		e.WriteErrorResponse(r.Context(), w, service.ErrAuthorizationHeaderMalformed, err)
		return false
	}

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

	err = cleanHeadersThatAreNotSignedInAuthHeader(r)
	if err != nil {
		slog.InfoContext(
			r.Context(), 
			"Encountered error when cleaning non-signed headers (likely unimportant for presigned request)", 
			"error", err,
		)
	}
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
func handleAuthNNormal(w http.ResponseWriter, r *http.Request, keyStorage utils.KeyPairKeeper, e service.ErrorReporter, backendManager interfaces.BackendManager) bool {
	if r.Header.Get(constants.AuthorizationHeader) == "" {
		requestctx.SetAuthType(r, authtypes.AuthTypeNone)
	} else {
		requestctx.SetAuthType(r, authtypes.AuthTypeAuthHeader)
	}

	accessKeyId, sessionToken, err := getCredentialsFromRequest(r)
	if err != nil {
		err := fmt.Errorf("could not get credentials from request: %w", err)
		e.WriteErrorResponse(r.Context(), w, service.ErrAuthorizationHeaderMalformed, err)
		return false
	}
	requestctx.AddAccessLogInfo(r, "s3", slog.String(L_AKID, accessKeyId))
	requestctx.SetSessionToken(r, sessionToken)

	err = makeSureSessionTokenIsForAccessKey(sessionToken, accessKeyId, keyStorage.GetJwtKeyFunc(), nil)
	if err != nil {
		err := fmt.Errorf("error when making sure session token corresponds to used credential pair: %w", err)
		e.WriteErrorResponse(r.Context(), w, service.ErrAuthorizationHeaderMalformed, err)
		return false
	}

	addRegionToSession(r, backendManager)

	secretAccessKey, err := credentials.CalculateSecretKey(accessKeyId, keyStorage)
	if err != nil {
		err := fmt.Errorf("could not calculate secret key: %w", err)
		e.WriteErrorResponse(r.Context(), w, service.ErrAWSInternalError, err)
		return false
	}
	backupContentLength := r.ContentLength
	//There is no use of passing the headers that are set by a proxy and which we haven't verified.
	err = cleanHeadersThatAreNotSignedInAuthHeader(r)
	if err != nil {
		ue := usererror.New(
			fmt.Errorf("could not clean not signed headers %v", r.Header), "Invalid authorization header",
		)
		e.WriteErrorResponse(r.Context(), w, service.ErrAuthorizationHeaderMalformed, ue)
		return false
	}
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
	slog.DebugContext(r.Context(), "ContentLength after manipualation", "ContentLength", r.ContentLength)


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

//Make sure the provided session token matches the used credentials
//If not return an error
func makeSureSessionTokenIsForAccessKey(sessionToken, accessKeyId string, keyFunc jwt.Keyfunc, authOptions *AuthenticationOptions) (invalidToken error) {
	var parserOptions []jwt.ParserOption
	if authOptions != nil {
		parserOptions = authOptions.GetParserOptions()
	}
	claims, err := credentials.ExtractTokenClaims(sessionToken, keyFunc, parserOptions...)
	if err != nil {
		return err
	}
	if claims.AccessKeyID == accessKeyId {
		return nil
	}
	if strings.ToUpper(os.Getenv("DEPRECATED_ALLOW_LEGACY_CREDENTIALS")) == "YES" {
		slog.Warn("RELYING ON DEPRECATED BEHAVIOR", "claims", claims.AccessKeyID, "creds", accessKeyId)
		return nil
	}
	return fmt.Errorf("mismatch between session token and access key i:d %s <> %s", claims.AccessKeyID, accessKeyId)
}

//For requests the access key and token are send over the wire
func getCredentialsFromRequest(r *http.Request) (accessKeyId, sessionToken string, err error) {
	sessionToken = r.Header.Get(constants.AmzSecurityTokenKey)
	accessKeyId, err = requestutils.GetSignatureCredentialPartFromRequest(r, requestutils.CredentialPartAccessKeyId)
	return
}

//cleanHeadersThatAreNotSignedInAuthHeader removes headers which are potentially added along the way
func cleanHeadersThatAreNotSignedInAuthHeader(req *http.Request) (error) {
	slog.DebugContext(req.Context(), "Headers before manipualation", "Headers", req.Header)

	signedHeaders, err := getSignedHeadersFromRequest(req)
	if err != nil {
		return err
	}
	addSignedHeadersToRequestCtx(req, signedHeaders)

	presign.CleanHeadersTo(req.Context(), req, signedHeaders, presign.CleanerOptions{})
	return nil
}

func addSignedHeadersToRequestCtx(r *http.Request, signedHeaders map[string]string) {
	headerlist := make([]string, 0)
	for headerName, _ := range signedHeaders {
		headerlist = append(headerlist, textproto.CanonicalMIMEHeaderKey(headerName))
	}
	requestctx.SetSignedHeaders(r, headerlist)
}

const signedHeadersPrefix = "SignedHeaders="

func getSignedHeadersFromRequest(req *http.Request) (signedHeaders map[string]string, err error) {
	//TODO: ideally this should also take care of signed headers in the presigned url
	// at the moment host header is the only signed header known to be set so does not
	// seem critical
	signedHeaders = map[string]string{}
	ah := req.Header.Get(constants.AuthorizationHeader)
	if ah == "" {
		return signedHeaders, errors.New("no authorization header")
	}
	authorizationParts := strings.Split(ah, ",")
	if len(authorizationParts) != 3 {
		return signedHeaders, usererror.New(
			fmt.Errorf("signature not as expected; got: %s", ah),
			"Authorization header has invalid structure",
		)
	}
	signedHeadersPart := strings.TrimLeft(authorizationParts[1], " ")
	if !strings.HasPrefix(signedHeadersPart, signedHeadersPrefix) {
		return signedHeaders, usererror.New(
			fmt.Errorf("signature did not have expected signed headers prefix; got: %s", ah),
			"Authorization header has invalid structure",
		)
	}
	signedHeadersPart = signedHeadersPart[len(signedHeadersPrefix):]
	for _, signedHeader := range strings.Split(signedHeadersPart, ";") {
		signedHeaders[signedHeader] = ""
	}
	return signedHeaders, nil
}