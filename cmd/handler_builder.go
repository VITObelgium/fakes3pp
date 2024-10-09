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
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	jwt "github.com/golang-jwt/jwt/v5"

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
 

const signAlgorithm = "AWS4-HMAC-SHA256"
const expectedAuthorizationStartWithCredential = "AWS4-HMAC-SHA256 Credential="

const credentialPartAccessKeyId = 0
// const credentialPartDate = 1
const credentialPartRegionName = 2
const credentialPartServiceName = 3
const credentialPartType = 4

// Gets a part of the Credential value that is passed via the authorization header
//
func getSignatureCredentialPartFromRequest(r *http.Request, credentialPart int) (string, error) {
	authorizationHeader := r.Header.Get("Authorization")
	var credentialString string
	var err error
	if authorizationHeader != "" {
		credentialString, err = getSignatureCredentialStringFromRequestAuthHeader(authorizationHeader)
		if err != nil {
			return "", err
		}
	} else {
		qParams := r.URL.Query()
		credentialString, err = getSignatureCredentialStringFromRequestQParams(qParams)
		if err != nil {
			return "", err
		}
	}
	return getCredentialPart(credentialString, credentialPart)
}

// Gets a part of the Credential value that is passed via the authorization header
func getSignatureCredentialStringFromRequestAuthHeader(authorizationHeader string) (string, error) {
	if authorizationHeader == "" {
		return "", fmt.Errorf("programming error should use empty authHeader to get credential part")
	}
	if !strings.HasPrefix(authorizationHeader, expectedAuthorizationStartWithCredential) {
		return "", fmt.Errorf("invalid authorization header: %s", authorizationHeader)
	}
	authorizationHeaderTrimmed := authorizationHeader[len(expectedAuthorizationStartWithCredential):]
	return authorizationHeaderTrimmed, nil
}

func getSignatureCredentialStringFromRequestQParams(qParams url.Values) (string, error) {
	queryAlgorithm := qParams.Get("X-Amz-Algorithm")
	if queryAlgorithm != signAlgorithm {
		return "", fmt.Errorf("no Authorization header nor x-amz-algorithm query parameter present: %v", qParams)
	}
	queryCredential := qParams.Get("X-Amz-Credential")
	if queryCredential == "" {
		return "", fmt.Errorf("empty X-Amz-Credential parameter: %v", qParams)
	}
	return queryCredential, nil
}

func getCredentialPart(credentialString string, credentialPart int) (string, error) {
	authorizationHeaderCredentialParts := strings.Split(
		strings.Split(credentialString, ", ")[0],
		"/",
	)
	if authorizationHeaderCredentialParts[credentialPartServiceName] != "s3" {
		return "", errors.New("authorization header was not for S3")
	}
	if authorizationHeaderCredentialParts[credentialPartType] != "aws4_request" {
		return "", errors.New("authorization header was not a supported sigv4")
	}
	return authorizationHeaderCredentialParts[credentialPart], nil
}

//For requests the access key and token are send over the wire
func getCredentialsFromRequest(r *http.Request) (accessKeyId, sessionToken string, err error) {
	sessionToken = r.Header.Get(AmzSecurityTokenKey)
	accessKeyId, err = getSignatureCredentialPartFromRequest(r, credentialPartAccessKeyId)
	return
}

const signedHeadersPrefix = "SignedHeaders="

func getSignedHeadersFromRequest(ctx context.Context, req *http.Request) (signedHeaders map[string]string) {
	signedHeaders = map[string]string{}
	ah := req.Header.Get(authorizationHeader)
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

var cleanableHeaders = map[string]bool{
	"accept-encoding": true,
	"x-forwarded-for": true,
	"x-forwarded-host": true,
	"x-forwarded-port": true,
	"x-forwarded-proto": true,
	"x-forwarded-server": true,
	"x-real-ip": true,
	"amz-sdk-invocation-id": true, //Added by AWS SDKs after signing
	"amz-sdk-request": true, //Added by AWS SDKs after signing
	"content-length": true,
}

func isCleanable(headerName string) bool {
	value, ok := cleanableHeaders[strings.ToLower(headerName)]
	if ok && value {
		return true
	}
	return false
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

//CleanHeaders removes headers which are potentially added along the way
//
func CleanHeaders(ctx context.Context, req *http.Request) {
	var cleaned = []string{}
	var skipped = []string{}
	var signed = []string{}
	signedHeaders := getSignedHeadersFromRequest(ctx, req)

	allHeadersInRequest := []string{}
	for hearderName := range req.Header {
		allHeadersInRequest = append(allHeadersInRequest, hearderName)
	}

	for _, header := range allHeadersInRequest {
		_, ok := signedHeaders[strings.ToLower(header)]
		if ok {
			signed = append(signed, header)
			continue
		}
		if isCleanable(header) {
			//If content-length is to be cleaned it should
			//also be <=0 otherwise it is taken in the signature
			//-1 means unknown so let's fall back to that
			if strings.ToLower(header) == "content-length" {
				req.ContentLength = -1
			}
			req.Header.Del(header)
			cleaned = append(cleaned, header)
		} else {
			skipped = append(skipped, header)
		}
	}
	slog.Info("Cleaning of headers done", xRequestIDStr, getRequestID(ctx), "cleaned", cleaned, "skipped", skipped, "signed", signed)
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

	policyStr, err := pm.GetPolicy(sessionClaims.RoleARN, PolicyTemplateDataFromClaims(sessionClaims))
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
	iamActions, err := NewIamActionsFromS3Request(action, r)
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
			var sessionToken string
			var expires time.Time
			if r.URL.Query().Get("Signature") != "" && r.URL.Query().Get("x-amz-security-token") != "" && r.URL.Query().Get("AWSAccessKeyId") != "" {
				accessKeyId := r.URL.Query().Get("AWSAccessKeyId")
				sessionToken = r.URL.Query().Get("x-amz-security-token")
				signingKey, err := getSigningKey()
				if err != nil {
					slog.Error("Could not get signing key", "error", err)
					writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
					return
				}
				secretAccessKey := CalculateSecretKey(accessKeyId, signingKey)
				creds := aws.Credentials{
					AccessKeyID: accessKeyId,
					SecretAccessKey: secretAccessKey,
					SessionToken: sessionToken,
				}
				isValid, err = HasS3PresignedUrlValidSignature(r, creds)
				if err != nil {
					slog.Error("Encountered error validating S3 presigned url", "error", err, xRequestIDStr, getRequestID(ctx))
					writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
					return
				}
				expires, err = GetS3PresignedUrlExpiresTime(r)
				if err != nil {
					slog.Info("Encountered error when getting expires time", "error", err, xRequestIDStr, getRequestID(ctx))
					writeS3ErrorResponse(ctx, w, ErrS3InvalidSignature, nil)
					return
				}
				// If url has gone passed expiry time (under user control)
				if expires.Before(time.Now().UTC()) {
					slog.Info("Encountered expired URL", "expires", expires, xRequestIDStr, getRequestID(ctx))
					writeS3ErrorResponse(ctx, w, ErrS3InvalidSignature, errors.New("expired URL"))
					return
				}

			} else {
				//Presigned with sigv4
				slog.Info("sigv4 signature", xRequestIDStr, getRequestID(ctx))
				u := ReqToURI(r)
				sessionToken = r.URL.Query().Get("X-Amz-Security-Token")
				if sessionToken == "" {
					slog.Info("Unsupported sigv4 with permanent credentials", xRequestIDStr, getRequestID(ctx))
					writeS3ErrorResponse(ctx, w, ErrS3InternalError, errors.New("not implemented sigv4"))
					return
				}
				err := CheckPresignedUrl(ctx, u, sessionToken)
				if err != nil {
					body := "Forbidden"
					if strings.HasPrefix(fmt.Sprint(err), "Expired") {
						body = "Expired"
					}
					slog.Info("Invalid presigned url", "body", body, "error", err, xRequestIDStr, getRequestID(ctx))
					w.WriteHeader(http.StatusForbidden)
					WriteButLogOnError(ctx, w, []byte(body))
					return
				} else {
					isValid = true
				}

			}
			
			if isValid{
				//Then make sure query parameters are no longer passed otherwise you can get 'InvalidAccessKeyId'
				queryPart := fmt.Sprintf("?%s", r.URL.RawQuery)
				r.RequestURI = strings.Replace(r.RequestURI, queryPart, "", 1)
				r.URL.RawQuery = ""

				CleanHeaders(ctx, r)

				//To have a valid signature
				r.Header.Add("X-Amz-Content-Sha256", EmptyStringSHA256)
				if authorizeS3Action(ctx, sessionToken, action, w, r, getCutoffForPresignedUrl()){
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
			CleanHeaders(ctx, r)
			clonedReq := r.Clone(ctx)
			creds := aws.Credentials{
				AccessKeyID: accessKeyId,
				SecretAccessKey: secretAccessKey,
				SessionToken: sessionToken,
			}
			err = SignWithCreds(ctx, clonedReq, creds)
			if err != nil {
				slog.Error("Could not sign request", "error", err, xRequestIDStr, getRequestID(ctx))
				writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
				return
			}
			calculatedSignature := clonedReq.Header.Get(authorizationHeader) 
			passedSignature := r.Header.Get(authorizationHeader)
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

func ReqToURI(r *http.Request) string {
	return fmt.Sprintf("https://%s%s", r.Host, r.URL.String())
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
	ReTargetRequest(r)
	err := SignRequest(ctx, r)
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
func ReTargetRequest(r *http.Request) {
	// Old signature
	r.Header.Del("Authorization")
	// Old session token
	r.Header.Del(AmzSecurityTokenKey)
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

func SignRequest(ctx context.Context, req *http.Request) error{
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")

	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	}

	return SignWithCreds(ctx, req, creds)
}

func SignWithCreds(ctx context.Context, req *http.Request, creds aws.Credentials) error{
	var signingTime time.Time
	amzDate := req.Header.Get(AmzDateKey)
	if amzDate == "" {
		signingTime = time.Now()
	} else {
		var err error
		signingTime, err = XAmzDateToTime(amzDate)
		if err != nil {
			slog.Error("Could not handle X-amz-date", AmzDateKey, amzDate, "error", err)
			signingTime = time.Now()
		}	
	}

	return SignRequestWithCreds(ctx, req, -1, signingTime, creds)
}

//If presigned url is valid return nil otherwise error why it is invalid
//It also verifies whether the URL was valid at time of checking
func CheckPresignedUrl(ctx context.Context, presignedUrlToCheck, sessionToken string) (error) {
	u, err := url.Parse(presignedUrlToCheck)
    if err != nil {
        return err
    }
	XAmzDate := u.Query().Get("X-Amz-Date")
	signDate, err := XAmzDateToTime(XAmzDate)
	if err != nil {
		return fmt.Errorf("InvalidSignature: could not process signature date %s due to %s", XAmzDate, err)
	}
	XAmzExpires := u.Query().Get("X-Amz-Expires")
	expirySeconds, err := strconv.Atoi(XAmzExpires)
	if err != nil {
		return fmt.Errorf("InvalidSignature: could not get Expire seconds(X-Amz-Expires) %s: %s", XAmzExpires, err)
	}

	expiryTime := signDate.Add(time.Duration(expirySeconds) * time.Second)
	now := time.Now()
	if expiryTime.Before(now) {
		return fmt.Errorf("ExpiredUrl: url expired on %s but the time is %s", expiryTime, now)
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	var signedUri string
	if err != nil {
		return fmt.Errorf("InvalidSignature: could not create request: %s", err)
	}
	if sessionToken != "" {
		accessKeyId, err := getSignatureCredentialPartFromRequest(req, credentialPartAccessKeyId)
		if err != nil{
			return err
		}
		key, err := getSigningKey()
		if err != nil {
			return err
		}
		secretKey := CalculateSecretKey(accessKeyId, key)
	
		creds := aws.Credentials{
			AccessKeyID: accessKeyId,
			SecretAccessKey: secretKey,
			SessionToken: sessionToken,
		}
		signedUri, _, err = PreSignRequestWithCreds(ctx, req, expirySeconds, signDate, creds)
		if err != nil {
			return fmt.Errorf("InvalidSignature: encountered error trying to sign a similar req: %s", err)
		}
	} else {
		signedUri, _, err = PreSignRequestWithServerCreds(req, expirySeconds, signDate)
		if err != nil {
			return fmt.Errorf("InvalidSignature: encountered error trying to sign a similar req: %s", err)
		}
	}

	if s, err := haveSameSigv4Signature(signedUri, presignedUrlToCheck); !s || err != nil {
		return fmt.Errorf("InvalidSignature: got 2 different signatures:\n%s\n%s", signedUri, presignedUrlToCheck)
	}
	return nil
}