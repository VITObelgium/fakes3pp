package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/requestutils"
)

type handlerBuilderI interface {
	//Takes S3ApiAction and whether it is a presigned request
	Build(S3ApiAction, bool) http.HandlerFunc
}

// A handler builder builds http handlers
type handlerBuilder struct {
	//How proxying is done to the backend
	proxyFunc func(context.Context, http.ResponseWriter, *http.Request, string)
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
		slog.WarnContext(ctx, "Signature not as expected", "got", ah)
	}
	signedHeadersPart := authorizationParts[1]
	if !strings.HasPrefix(signedHeadersPart, signedHeadersPrefix) {
		slog.WarnContext(ctx, "Signature did not have expected signed headers prefix", "got", ah)
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
func authorizeS3Action(ctx context.Context, sessionToken, targetRegion string, action S3ApiAction, w http.ResponseWriter, r *http.Request, maxExpiryTime time.Time) (allowed bool) {
	allowed = false
	sessionClaims, err := ExtractTokenClaims(sessionToken, s3ProxyKeyFunc)
	if err != nil {
		slog.InfoContext(ctx, "Could not get claims from session token", "error", err)
		writeS3ErrorResponse(ctx, w, ErrS3InvalidSecurity, nil)
		return
	}
	expiresJwt, err := sessionClaims.GetExpirationTime()
	if err != nil {
		slog.WarnContext(ctx, "Could not get expires claim from session token", "error", err, "claims", sessionClaims)
		writeS3ErrorResponse(ctx, w, ErrS3InvalidSecurity, nil)
		return
	}
	if expiresJwt.Time.Before(maxExpiryTime) {
		slog.WarnContext(ctx, "Credentials are passed expiry", "error", err, "claims", sessionClaims, "cutoff", maxExpiryTime, "expires", expiresJwt)
		writeS3ErrorResponse(ctx, w, ErrS3InvalidSignature, errors.New("expired credentials"))
		return
	}

	policySessionData := GetPolicySessionDataFromClaims(sessionClaims)
	policySessionData.RequestedRegion = targetRegion
	policyStr, err := pm.GetPolicy(sessionClaims.RoleARN, policySessionData)
	if err != nil {
		slog.ErrorContext(ctx, "Could not get policy for temporary credentials", "error", err, "role_arn", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	slog.InfoContext(ctx, "Policy retrieved", "policy", policyStr)
	pe, err := NewPolicyEvaluatorFromStr(policyStr)
	if err != nil {
		slog.ErrorContext(ctx, "Could not create policy generator", "error", err, "policy", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	iamActions, err := newIamActionsFromS3Request(action, r, policySessionData)
	if err != nil {
		slog.ErrorContext(ctx, "Could not get IAM actions from request", "error", err, "policy", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	isAllowed, reason, err := pe.EvaluateAll(iamActions)
	if err != nil {
		slog.ErrorContext(ctx, "Could not evaluate policy", "error", err, "policy", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}

	if isAllowed {
		slog.DebugContext(ctx, "Allowed access", "reason", reason)
		return true
	} else {
		slog.InfoContext(ctx, "Denied access", "reason", reason, "actions", iamActions)
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
		ctx := requestctx.NewContextFromHttpRequest(r)

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
				slog.ErrorContext(ctx, "Could not get signing key", "error", err)
				writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
				return
			}

			var secretDeriver = func(accessKeyId string) (secretAccessKey string, err error) {
				return CalculateSecretKey(accessKeyId, signingKey), nil
			}

			presignedUrl, err := presign.MakePresignedUrl(r)
			if err != nil {
				slog.ErrorContext(ctx, "Could not get presigned url", "error", err)
				writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
				return
			}
			isValid, creds, expires, err:= presignedUrl.GetPresignedUrlDetails(ctx, secretDeriver)
			if err != nil {
				slog.ErrorContext(ctx, "Error geting details of presigned url", "error", err)
				writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
				return
			}

			// If url has gone passed expiry time (under user control)
			if expires.Before(time.Now().UTC()) {
				slog.InfoContext(ctx, "Encountered expired URL", "expires", expires)
				writeS3ErrorResponse(ctx, w, ErrS3InvalidSignature, errors.New("expired URL"))
				return
			}
			
			if isValid{
				targetBackendId := requestutils.GetRegionFromRequest(r, globalBackendsConfig.defaultBackend)
				//Then make sure query parameters are no longer passed otherwise you can get 'InvalidAccessKeyId'
				queryPart := fmt.Sprintf("?%s", r.URL.RawQuery)
				r.RequestURI = strings.Replace(r.RequestURI, queryPart, "", 1)
				r.URL.RawQuery = ""

				cleanHeadersThatAreNotSignedInAuthHeader(ctx, r)

				//To have a valid signature
				r.Header.Add(constants.AmzContentSHAKey, constants.EmptyStringSHA256)
				if authorizeS3Action(ctx, creds.SessionToken, targetBackendId, action, w, r, getCutoffForPresignedUrl()){
					hb.proxyFunc(ctx, w, r, targetBackendId)
				}
				return
			}
			slog.InfoContext(ctx, "Invalid S3 signature")
			writeS3ErrorAccessDeniedResponse(ctx, w)
			return
	
		} else {
			accessKeyId, sessionToken, err := getCredentialsFromRequest(r)
			if err != nil {
				slog.InfoContext(ctx, "Could not get credentials from request", "error", err)
				writeS3ErrorResponse(ctx, w, ErrS3InvalidAccessKeyId, err)
				return
			}
			signingKey, err := getSigningKey()
			if err != nil {
				slog.ErrorContext(ctx, "Could not get signing key", "error", err)
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
			err = presign.SignWithCreds(ctx, clonedReq, creds, "ThisShouldNotBeUsedForSigv4Requests258")
			if err != nil {
				slog.ErrorContext(ctx, "Could not sign request", "error", err)
				writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
				return
			}
			calculatedSignature := clonedReq.Header.Get(constants.AuthorizationHeader) 
			passedSignature := r.Header.Get(constants.AuthorizationHeader)
			if calculatedSignature == passedSignature {
				slog.DebugContext(ctx, "Valid signature")
				//Cleaning could have removed content length
				r.ContentLength = backupContentLength

	            targetRegion := requestutils.GetRegionFromRequest(r, globalBackendsConfig.defaultBackend)

				//Authn done time to perform authorization				
				if authorizeS3Action(ctx, creds.SessionToken, targetRegion, action, w, r, time.Now().UTC()){
					hb.proxyFunc(ctx, w, r, targetRegion)
				}
				return
			} else {
				slog.DebugContext(
					ctx,
					"Invalid signature", 
					"calculated", calculatedSignature, 
					"received", passedSignature,
				)
				writeS3ErrorResponse(ctx, w, ErrS3InvalidSignature, nil)
				return
			}
		}
	}
}

//Log request information with the api action if apiAction is unknown just
//leave as an empty string.
func logRequest(ctx context.Context, apiAction string, r *http.Request) {
	slog.InfoContext(
		ctx, 
		"Request start", 
		"action", apiAction, 
		"method", r.Method,
		"host", r.Host,
		"url", r.URL.String(), 
		"headers", r.Header,
	)
}

func justProxy(ctx context.Context, w http.ResponseWriter, r *http.Request, targetBackendId string) {
	err := reTargetRequest(ctx, r, targetBackendId)
	if err == errInvalidBackendErr {
		slog.WarnContext(ctx, "Invalid region was specified in the request", "error", err, "backendId", targetBackendId)
		writeS3ErrorResponse(ctx, w, ErrS3InvalidRegion, nil)
		return
	} else if err != nil {
		slog.ErrorContext(ctx, "Could not re-target request with permanent credentials", "error", err, "backendId", targetBackendId)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	creds, err := getBackendCredentials(targetBackendId)
	if err != nil {
		slog.ErrorContext(ctx, "Could not get credentials for request", "error", err, "backendId", targetBackendId)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	err = presign.SignWithCreds(ctx, r, creds, targetBackendId)
	if err != nil {
		slog.ErrorContext(ctx, "Could not sign request with permanent credentials", "error", err, "backendId", targetBackendId)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}

	client := &http.Client{}
	slog.DebugContext(ctx, "Going to perform request", "method", r.Method, "host", r.Host, "url", r.URL, "headers", r.Header)
	resp, err := client.Do(r)
	if err != nil {
		slog.ErrorContext(ctx, "Error making request", "error", err)
		return
	}
	defer resp.Body.Close()

	slog.DebugContext(ctx, "Response status", "status", resp.StatusCode)
	for hk, hvs := range resp.Header {
		for _, hv := range hvs {
			w.Header().Add(hk, hv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	i, err := io.Copy(w, resp.Body)
	if err != nil {
		slog.ErrorContext(ctx, "Context had error", "error", err, "context_error", ctx.Err())
	} else {
		slog.InfoContext(ctx, "End of proxying", "bytes", i, "error", err, "status", resp.Status, "headers", resp.Header)
	}
}

// Take a request that is signed but strip signature and point it to new target.
// Drop the old signature (Authorization header)
// Adapt Host to the new target
// We also have to clear RequestURI and set URL appropriately as explained in
// https://stackoverflow.com/questions/19595860/http-request-requesturi-field-when-making-request-in-go
func reTargetRequest(ctx context.Context, r *http.Request, backendId string) (error) {
	// Old signature
	r.Header.Del("Authorization")
	// Old session token
	r.Header.Del(constants.AmzSecurityTokenKey)
	r.Header.Del("Host")
	endpoint, err := getBackendEndpoint(backendId)
	if err != nil {
		return err
	}
	r.Header.Add("Host", endpoint.getHost())
	r.Host = endpoint.getHost()
	origRawQuery := r.URL.RawQuery
	slog.DebugContext(ctx, "Stored orig RawQuery", "raw_query", origRawQuery)

	u, err := url.Parse(fmt.Sprintf("%s%s", endpoint.getBaseURI(), r.RequestURI))
    if err != nil {
        return err
    }
	r.RequestURI = ""
	r.RemoteAddr = ""
    r.URL = u

	r.URL.RawQuery = origRawQuery
	slog.DebugContext(ctx, "RawQuery that is put in place", "raw_query", r.URL.RawQuery)
	return nil
}