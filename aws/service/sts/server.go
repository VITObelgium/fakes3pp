package sts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service"
	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/oidc"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/VITObelgium/fakes3pp/utils"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/minio/mux"
)


type STSServer struct{
	//The Key material that is used for signing JWT tokens.
	jwtKeyMaterial utils.KeyPairKeeper

	fqdns []string

	port  int

	//The TLS certificate used to encrypt traffic with if omitted HTTP server will be spawned
	tlsCertFilePath string

	//The TLS key used to encrypt traffic with if omitted HTTP server will be spawned
	tlsKeyFilePath string

	//The verifier for OIDC IDP tokens
	oidcVerifier oidc.OIDCVerifier

	pm *iam.PolicyManager

	maxAllowedDuration time.Duration
}

func (s *STSServer) GetIssuer() string {
	return s.fqdns[0]
}

func (s *STSServer) GetListenHost() string {
	return s.fqdns[0]
}

func NewSTSServer(
	jwtPrivateRSAKeyFilePath string,
	serverPort int,
	fqdns []string,
	tlsCertFilePath string,
	tlsKeyFilePath string,
	oidcConfigFilePath string,
	pm *iam.PolicyManager,
	maxDurationSeconds int,
) (s server.Serverable, err error) {
	return newSTSServer(
		jwtPrivateRSAKeyFilePath,
		serverPort,
		fqdns,
		tlsCertFilePath,
		tlsKeyFilePath,
		oidcConfigFilePath,
		pm,
		maxDurationSeconds,
	)
}

func newSTSServer(
	jwtPrivateRSAKeyFilePath string,
	serverPort int,
	fqdns []string,
	tlsCertFilePath string,
	tlsKeyFilePath string,
	oidcConfigFilePath string,
	pm *iam.PolicyManager,
	maxDurationSeconds int,
) (s *STSServer, err error) {
	key, err := utils.NewKeyStorage(jwtPrivateRSAKeyFilePath)
	if err != nil {
		return nil, err
	}
	oidcVerifier, err := oidc.NewOIDCVerifierFromConfigFile(oidcConfigFilePath)
	if err != nil {
		return nil, err
	}
	s = &STSServer{
		jwtKeyMaterial: key,
		fqdns: fqdns,
		port: serverPort,
		tlsCertFilePath: tlsCertFilePath,
		tlsKeyFilePath: tlsKeyFilePath,
		oidcVerifier: oidcVerifier,
		pm: pm,
		maxAllowedDuration: time.Duration(maxDurationSeconds) * time.Second,
	}
	return s, nil
}

func (s *STSServer) GetPort() (int) {
	return s.port
}

func (s *STSServer) GetTls() (bool, string, string) {
	enabled := true
	if s.tlsCertFilePath == "" {
		slog.Debug("Disabling TLS", "reason", "no certFile provided")
		enabled = false
	} else if s.tlsKeyFilePath == "" {
		slog.Debug("Disabling TLS", "reason", "no keyFile provided")
		enabled = false
	}
	return enabled, s.tlsCertFilePath, s.tlsKeyFilePath
}

func (s *STSServer) RegisterRoutes(router *mux.Router) error {
	stsRouter := router.NewRoute().PathPrefix(server.SlashSeparator).Subrouter()

	stsRouter.Methods(http.MethodPost).HandlerFunc(s.processSTSPost)

	stsRouter.PathPrefix("/").HandlerFunc(justLog)
	return nil
}

func justLog(w http.ResponseWriter, r *http.Request) {
	slog.InfoContext(r.Context(), "Unknown/Unsupported type of operation")
}

//Generic processing of POST. For an API request that handle a POST
//The parameters can be as form data which hinders from routing more
//fine-grained
func (s *STSServer) processSTSPost(w http.ResponseWriter, r *http.Request) {
	//At the final end discard what is being sent.
	//If not some clients might not check the response that is being sent and hang untill timeout
	//An example is boto3 where urllib3 won't check the response if it is still sending data
	if r.Body != nil {
		defer r.Body.Close()
	}

	ctx := r.Context()
	// Parse the incoming form data.
	if err := parseForm(r); err != nil {
		slog.DebugContext(ctx, "parseForm returned error, should be benign", "error", err)
	}

	if r.Form.Get(stsVersion) != stsAPIVersion {
		writeSTSErrorResponse(ctx, w, ErrSTSMissingParameter, fmt.Errorf("invalid STS API version %s, expecting %s", r.Form.Get("Version"), stsAPIVersion))
		return
	}

	switch r.Form.Get(stsAction) {
	case webIdentity:
		s.assumeRoleWithWebIdentity(ctx, w, r)
	default:
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, fmt.Errorf("unsupported action %s", r.Form.Get(stsAction)))
	}
}

func parseForm(r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	for k, v := range r.PostForm {
		if _, ok := r.Form[k]; !ok {
			r.Form[k] = v
		}
	}
	return nil
}

type stsClaims map[string]interface{}

// An assumeRoleWithWebIdentity is an API call that happens anonymously but where a token is send as part of the API
// Call. That token will be exchanged for credentials.
// Request parameters that we support:
// - DurationSeconds 
// - RoleArn
// - RoleSessionName
// - WebIdentityToken following the structure 
func (s *STSServer)assumeRoleWithWebIdentity(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	claims := stsClaims{}
	defer slog.InfoContext(ctx, "Auditlog", "claims", claims)

	token := r.Form.Get(stsWebIdentityToken)

	claimsMap, err := credentials.ExtractOIDCTokenClaims(token, s.oidcVerifier.GetKeyFunc())
	if err != nil {
		slog.InfoContext(ctx, "Encountered error extracting claims", "error", err)
		userErr := fmt.Errorf("invalid webidentity token. If issue persist and need support share ID %s", requestctx.GetRequestID(ctx))
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, userErr)
		return
	}
	subject, err := claimsMap.GetSubject()
	if subject == "" || err != nil {
		slog.ErrorContext(ctx, "Error extracting subject from oidc jwt token", "error", err, "subject", subject)
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
			errors.New("STS JWT Token has `sub` claim missing, `sub` claim is mandatory"))
		return
	}
	issuer, err := claimsMap.GetIssuer()
	if issuer == "" || err != nil {
		slog.ErrorContext(ctx, "Error extracting issuer from oidc jwt token", "error", err, "issuer", issuer)
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
			errors.New("STS JWT Token has `iss` claim missing, `iss` claim is mandatory"))
		return
	}
	subFromToken := fmt.Sprintf("%s:%s", issuer, subject)
	subFromTokenSha1 := utils.Sha1sum(subFromToken)
	slog.InfoContext(ctx, "User hash calculated", "subject", subFromToken, "hash", subFromTokenSha1)


	expiry, err := claimsMap.GetExpirationTime()
	if err != nil {
		slog.ErrorContext(ctx, "Error extracting expiry time from oidc jwt token", "error", err, "token", token)
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
			errors.New("STS JWT Token has `sub` claim missing, `exp` claim is mandatory"))
		return
	}
	paramDurationSeconds := r.Form.Get(stsDurationSeconds)
	if paramDurationSeconds == "" {
		paramDurationSeconds = "3600"
	}
	durationSecondsInt, err := strconv.Atoi(paramDurationSeconds)
	if err != nil {
		slog.ErrorContext(ctx, "Error converting duration seconds", "error", err)
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
			fmt.Errorf("invalid %s", stsDurationSeconds))
		return
	}

	duration, err := s.calculateFinalDurationSeconds(durationSecondsInt, expiry)
	if err != nil {
		slog.ErrorContext(ctx, "Error calculating final duration seconds", "error", err)
		slog.DebugContext(ctx, "Error calculating final duration seconds", "error", err, "token", token)
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	roleArn := r.Form.Get(stsRoleArn)
	if !s.pm.DoesPolicyExist(roleArn) {
		slog.InfoContext(ctx, "Error retrieving policy", "role_arn", roleArn, "error", err)
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, fmt.Errorf("invalid value for %s: %s", stsRoleArn, roleArn))
		return
	}
	
	newToken := s.newProxyIssuedToken(subject, issuer, roleArn, *duration, claimsMap.Tags)

	cred, err := credentials.NewAWSCredentials(newToken, *duration, s.jwtKeyMaterial)

	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}


	var encodedSuccessResponse []byte

	webIdentityResponse := &AssumeRoleWithWebIdentityResponse{
		Result: WebIdentityResult{
			Credentials:                 *cred,
			SubjectFromWebIdentityToken: subFromToken,
		},
	}
	webIdentityResponse.ResponseMetadata.RequestID = requestctx.GetRequestID(ctx)
	encodedSuccessResponse = service.EncodeResponse(ctx, webIdentityResponse)

	service.WriteSuccessResponseXML(ctx, w, encodedSuccessResponse)
}

func (s *STSServer)newProxyIssuedToken(subject, issuer, roleARN string, expiry time.Duration, tags session.AWSSessionTags) (token *jwt.Token) {
	return credentials.CreateRS256PolicyToken(s.GetIssuer(), issuer, subject, roleARN, expiry, tags)
}

func (s *STSServer) calculateFinalDurationSeconds(apiProvidedDuration int, jwtExpiry *jwt.NumericDate) (*time.Duration, error) {
	now := time.Now().UTC()

	//We take same minimum as AWS does: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
	minimalExpiryTime := now.Add(15 * time.Minute)
	if jwtExpiry.Before(now) {
		//We allow the usage of refresh tokens so the token just needs to be valid
		//at exchange time.
		return nil, errors.New("provided OIDC token had already expired")
	}
	providedExpiryTime := now.Add(time.Duration(apiProvidedDuration) * time.Second)
	if providedExpiryTime.Before(minimalExpiryTime) {
		return nil, errors.New("provided expiry time is before minimal time of 15 minutes")
	}
	var finalDuration time.Duration = time.Duration(apiProvidedDuration) * time.Second
	if finalDuration > s.maxAllowedDuration {
		//TODO: make sure this resulst in a Bad request rather than an internal server error
		slog.Debug("Provided duration exceeds maximum of seconds", "providedDuration", finalDuration, "allowedDuration", s.maxAllowedDuration)
		return nil, fmt.Errorf("provided duration seconds exceed the maximum of %d seconds", s.maxAllowedDuration)
	}
	return &finalDuration, nil
}
