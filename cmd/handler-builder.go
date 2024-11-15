package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/VITObelgium/fakes3pp/requestutils"
	"github.com/google/uuid"
)

type handlerBuilderI interface {
	//Takes S3ApiAction and whether it is a presigned request
	Build(S3ApiAction, bool) http.HandlerFunc
}

// A handler builder builds http handlers
type handlerBuilder struct {
	//How proxying is done to the backend
	proxyFunc func(context.Context, http.ResponseWriter, *http.Request)
}

var justProxied handlerBuilderI = handlerBuilder{proxyFunc: justProxy}


//For requests the access key and token are send over the wire
func getCredentialsFromRequest(r *http.Request) (accessKeyId, sessionToken string, err error) {
	sessionToken = r.Header.Get(constants.AmzSecurityTokenKey)
	accessKeyId, err = requestutils.GetSignatureCredentialPartFromRequest(r, requestutils.CredentialPartAccessKeyId)
	return
}

const signedHeadersPrefix = "SignedHeaders="

func getSignedHeadersFromRequest(ctx context.Context, req *http.Request) (signedHeaders map[string]string) {
	signedHeaders = map[string]string{}
	ah := req.Header.Get(constants.AuthorizationHeader)
	if ah == "" {
		return
	}
	authorizationParts := strings.Split(ah, ", ")
	if len(authorizationParts) != 3 {
		slog.Warn("Signature not as expected", "got", ah, xRequestIDStr, getRequestID(ctx))
	}
	signedHeadersPart := authorizationParts[1]
	if !strings.HasPrefix(signedHeadersPart, signedHeadersPrefix) {
		slog.Warn("Signature did not have expected signed headers prefix", "got", ah, xRequestIDStr, getRequestID(ctx))
	}
	signedHeadersPart = signedHeadersPart[len(signedHeadersPrefix):]
	for _, signedHeader := range strings.Split(signedHeadersPart, ";") {
		signedHeaders[signedHeader] = ""
	}
	return signedHeaders
}


var s3ProxyKeyFunc func (t *jwt.Token) (interface{}, error)

func initializeS3ProxyKeyFunc(publicKeyFile string) error{
	pk, err := PublickKeyFromPemFile(publicKeyFile)
	if err != nil {
		return err
	}
	s3ProxyKeyFunc = func (t *jwt.Token) (interface{}, error) {

		return pk, nil
	}
	return nil
}

//cleanHeadersThatAreNotSignedInAuthHeader removes headers which are potentially added along the way
//
func cleanHeadersThatAreNotSignedInAuthHeader(ctx context.Context, req *http.Request) {
	signedHeaders := getSignedHeadersFromRequest(ctx, req)

	presign.CleanHeadersTo(ctx, req, signedHeaders)
}



// Authorize an S3 action
// maxExpiryTime is an upperbound for the expiry of the session token
func authorizeS3Action(ctx context.Context, sessionToken string, action S3ApiAction, w http.ResponseWriter, r *http.Request, maxExpiryTime time.Time) (allowed bool) {
	allowed = false
	sessionClaims, err := ExtractTokenClaims(sessionToken, s3ProxyKeyFunc)
	if err != nil {
		slog.Info("Could not get claims from session token", "error", err, xRequestIDStr, getRequestID(ctx))
		writeS3ErrorResponse(ctx, w, ErrS3InvalidSecurity, nil)
		return
	}
	expiresJwt, err := sessionClaims.GetExpirationTime()
	if err != nil {
		slog.Warn("Could not get expires claim from session token", "error", err, "claims", sessionClaims, xRequestIDStr, getRequestID(ctx))
		writeS3ErrorResponse(ctx, w, ErrS3InvalidSecurity, nil)
		return
	}
	if expiresJwt.Time.Before(maxExpiryTime) {
		slog.Warn("Credentials are passed expiry", "error", err, "claims", sessionClaims, "cutoff", maxExpiryTime, "expires", expiresJwt, xRequestIDStr, getRequestID(ctx))
		writeS3ErrorResponse(ctx, w, ErrS3InvalidSignature, errors.New("expired credentials"))
		return
	}

	policySessionData := GetPolicySessionDataFromClaims(sessionClaims)
	policyStr, err := pm.GetPolicy(sessionClaims.RoleARN, policySessionData)
	if err != nil {
		slog.Error("Could not get policy for temporary credentials", "error", err, xRequestIDStr, getRequestID(ctx), "role_arn", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	slog.Info("Policy retrieved", "policy", policyStr, xRequestIDStr, getRequestID(ctx))
	pe, err := NewPolicyEvaluatorFromStr(policyStr)
	if err != nil {
		slog.Error("Could not create policy generator", "error", err, xRequestIDStr, getRequestID(ctx), "policy", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	iamActions, err := newIamActionsFromS3Request(action, r, policySessionData)
	if err != nil {
		slog.Error("Could not get IAM actions from request", "error", err, xRequestIDStr, getRequestID(ctx), "policy", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	isAllowed, reason, err := pe.EvaluateAll(iamActions)
	if err != nil {
		slog.Error("Could not evaluate policy", "error", err, xRequestIDStr, getRequestID(ctx), "policy", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}

	if isAllowed {
		slog.Debug("Allowed access", "reason", reason, xRequestIDStr, getRequestID(ctx))
		return true
	} else {
		slog.Info("Denied access", "reason", reason, "actions", iamActions, xRequestIDStr, getRequestID(ctx))
		writeS3ErrorResponse(ctx, w, ErrS3AccessDenied, nil)
		return false
	}
}

// The cutoff of expiry time lies in the past because we allow presigned urls
// to outlive the credentials lifetime. So if we allow 2 hours of grace time
// then the cutoff we use to check validity is 2 hours ago.
func getCutoffForPresignedUrl() time.Time {
	return time.Now().UTC().Add(
		-getSignedUrlGraceTimeSeconds(),
	)
}


func (hb handlerBuilder) Build(action S3ApiAction, presigned bool) (http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request) {
		//At the final end discard what is being sent.
		//If not some clients might not check the response that is being sent and hang untill timeout
		//An example is boto3 where urllib3 won't check the response if it is still sending data
		if r.Body != nil {
			defer r.Body.Close()
		}

		//First make sure signature if valid
		ctx := buildContextWithRequestID(r)

		var loggedAction string = string(action)
		if presigned {
			loggedAction = fmt.Sprintf("%s<presigned>", loggedAction)
		}
		logRequest(ctx, loggedAction, r)

		if presigned {
			//bool to track whether signature was ok
			var isValid bool
			var expires time.Time

			signingKey, err := getSigningKey()
			if err != nil {
				slog.Error("Could not get signing key", "error", err)
				writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
				return
			}

			var secretDeriver = func(accessKeyId string) (secretAccessKey string, err error) {
				return CalculateSecretKey(accessKeyId, signingKey), nil
			}

			presignedUrl, err := presign.MakePresignedUrl(r)
			if err != nil {
				slog.Error("Could not get presigned url", "error", err, xRequestIDStr, getRequestID(ctx))
				writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
				return
			}
			isValid, creds, expires, err:= presignedUrl.GetPresignedUrlDetails(ctx, secretDeriver)
			if err != nil {
				slog.Error("Error geting details of presigned url", "error", err, xRequestIDStr, getRequestID(ctx))
				writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
				return
			}

			// If url has gone passed expiry time (under user control)
			if expires.Before(time.Now().UTC()) {
				slog.Info("Encountered expired URL", "expires", expires, xRequestIDStr, getRequestID(ctx))
				writeS3ErrorResponse(ctx, w, ErrS3InvalidSignature, errors.New("expired URL"))
				return
			}
			
			if isValid{
				//Then make sure query parameters are no longer passed otherwise you can get 'InvalidAccessKeyId'
				queryPart := fmt.Sprintf("?%s", r.URL.RawQuery)
				r.RequestURI = strings.Replace(r.RequestURI, queryPart, "", 1)
				r.URL.RawQuery = ""

				cleanHeadersThatAreNotSignedInAuthHeader(ctx, r)

				//To have a valid signature
				r.Header.Add(constants.AmzContentSHAKey, constants.EmptyStringSHA256)
				if authorizeS3Action(ctx, creds.SessionToken, action, w, r, getCutoffForPresignedUrl()){
					hb.proxyFunc(ctx, w, r)
				}
				return
			}
			slog.Info("Invalid S3 signature", xRequestIDStr, getRequestID(ctx))
			writeS3ErrorAccessDeniedResponse(ctx, w)
			return
	
		} else {
			accessKeyId, sessionToken, err := getCredentialsFromRequest(r)
			if err != nil {
				slog.Info("Could not get credentials from request", "error", err, xRequestIDStr, getRequestID(ctx))
				writeS3ErrorResponse(ctx, w, ErrS3InvalidAccessKeyId, err)
				return
			}
			signingKey, err := getSigningKey()
			if err != nil {
				slog.Error("Could not get signing key", "error", err, xRequestIDStr, getRequestID(ctx))
				writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
				return
			}
			secretAccessKey := CalculateSecretKey(accessKeyId, signingKey)
			backupContentLength := r.ContentLength
			//There is no use of passing the headers that are set by a proxy and which we haven't verified.
			cleanHeadersThatAreNotSignedInAuthHeader(ctx, r)
			clonedReq := r.Clone(ctx)
			creds := aws.Credentials{
				AccessKeyID: accessKeyId,
				SecretAccessKey: secretAccessKey,
				SessionToken: sessionToken,
			}
			err = presign.SignWithCreds(ctx, clonedReq, creds)
			if err != nil {
				slog.Error("Could not sign request", "error", err, xRequestIDStr, getRequestID(ctx))
				writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
				return
			}
			calculatedSignature := clonedReq.Header.Get(constants.AuthorizationHeader) 
			passedSignature := r.Header.Get(constants.AuthorizationHeader)
			if calculatedSignature == passedSignature {
				slog.Info("Valid signature", xRequestIDStr, getRequestID(ctx))
				//Cleaning could have removed content length
				r.ContentLength = backupContentLength
				//Authn done time to perform authorization				
				if authorizeS3Action(ctx, creds.SessionToken, action, w, r, time.Now().UTC()){
					hb.proxyFunc(ctx, w, r)
				}
				return
			} else {
				slog.Debug(
					"Invalid signature", 
					xRequestIDStr, getRequestID(ctx), 
					"calculated", calculatedSignature, 
					"received", passedSignature,
				)
				writeS3ErrorResponse(ctx, w, ErrS3InvalidSignature, nil)
				return
			}
		}
	}
}

type RequestID string
const xRequestID RequestID = "X-Request-ID"
const xRequestIDStr string = string(xRequestID)
const dummyRequestID string = "00000000-0000-0000-0000-000000000000"

func buildContextWithRequestID(req *http.Request) (context.Context) {
	id := uuid.New()
	return buildContextWithChosenRequestId(req, id.String())
}

func buildContextWithChosenRequestId(req *http.Request, requestId string) (context.Context) {
	if reqID, ok := req.Header[http.CanonicalHeaderKey(xRequestIDStr)]; ok {
		return context.WithValue(req.Context(), xRequestID, reqID)
	}
	return context.WithValue(req.Context(), xRequestID, requestId)
}


func getRequestID(ctx context.Context) (string) {
	val := ctx.Value(xRequestID)
	s, ok := val.(string)
	if !ok {
		slog.Info(
			fmt.Sprintf("Invalid type for %s that is a programming error if not an invocation by tests", xRequestID),
		)
		return dummyRequestID
	}
	return s
}

//Log request information with the api action if apiAction is unknown just
//leave as an empty string.
func logRequest(ctx context.Context, apiAction string, r *http.Request) {
	slog.Info(
		"Request start", 
		"action", apiAction, 
		"method", r.Method,
		"host", r.Host,
		"url", r.URL.String(), 
		xRequestIDStr, getRequestID(ctx),
		"headers", r.Header,
	)
}

func justProxy(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	reTargetRequest(r)
	err := signRequest(ctx, r)
	if err != nil {
		slog.Error("Could not sign request with permanent credentials", "error", err, xRequestIDStr, getRequestID(ctx))
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}

	client := &http.Client{}
	slog.Debug("Going to perform request", "method", r.Method, "host", r.Host, "url", r.URL, "headers", r.Header, xRequestIDStr, getRequestID(ctx))
	resp, err := client.Do(r)
	if err != nil {
		slog.Error("Error making request", "error", err, xRequestIDStr, getRequestID(ctx))
		return
	}
	defer resp.Body.Close()

	slog.Debug("Response status", "status", resp.StatusCode, xRequestIDStr, getRequestID(ctx))
	for hk, hvs := range resp.Header {
		for _, hv := range hvs {
			w.Header().Add(hk, hv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	i, err := io.Copy(w, resp.Body)
	if err != nil {
		slog.Error("Context had error", "error", err, "context_error", ctx.Err(), xRequestIDStr, getRequestID(ctx))
	} else {
		slog.Info("End of proxying", "bytes", i, "error", err, xRequestIDStr, getRequestID(ctx), "status", resp.Status, "headers", resp.Header)
	}
}

// Take a request that is signed but strip signature and point it to new target.
// Drop the old signature (Authorization header)
// Adapt Host to the new target
// We also have to clear RequestURI and set URL appropriately as explained in
// https://stackoverflow.com/questions/19595860/http-request-requesturi-field-when-making-request-in-go
func reTargetRequest(r *http.Request) {
	// Old signature
	r.Header.Del("Authorization")
	// Old session token
	r.Header.Del(constants.AmzSecurityTokenKey)
	r.Header.Del("Host")
	r.Header.Add("Host", s3TargetHost)
	r.Host = s3TargetHost
	origRawQuery := r.URL.RawQuery
	slog.Info("Stored orig RawQuery", "raw_query", origRawQuery)

	u, err := url.Parse(fmt.Sprintf("https://%s%s", s3TargetHost, r.RequestURI))
    if err != nil {
        panic(err)
    }
		r.RequestURI = ""
	r.RemoteAddr = ""
    r.URL = u

	r.URL.RawQuery = origRawQuery
	slog.Info("RawQuery that is put in place", "raw_query", r.URL.RawQuery)
}

func signRequest(ctx context.Context, req *http.Request) error{
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")

	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	}

	return presign.SignWithCreds(ctx, req, creds)
}

