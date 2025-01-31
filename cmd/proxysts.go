// Copyright (c) 2024 VITObelgium
//
// This file was inspired by https://github.com/minio/minio/blob/master/cmd/sts-handlers.go
// which has the following copyright notic:
//
// Copyright (c) 2015-2021 MinIO, Inc.
//
// # That file was part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/VITObelgium/fakes3pp/requestctx"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/minio/mux"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const proxysts = "proxysts"

var pm PolicyManager

func initializePolicyManager() {
	pm = *NewPolicyManager(
		NewLocalPolicyRetriever(viper.GetString(rolePolicyPath)),
	)
	err := pm.PreWarm()
	if err != nil{
		panic(err)
	}
}

// proxystsCmd represents the proxysts command
var proxystsCmd = &cobra.Command{
	Use:   proxysts,
	Short: "A brief description of your command",
	Long: `Spawn a server process that listens for requests and takes API calls
	that follow the STS API. There are only few supporte`,
	Run: func(cmd *cobra.Command, args []string) {
		BindEnvVariables(proxysts)
		configFile := viper.GetString(stsOIDCConfigFile)
		slog.Info("Loading OIDC config", "file", stsOIDCConfigFile)
		err := loadOidcConfigFile(configFile)
		if err != nil {
			slog.Error("Could not load OIDC config", "error", err)
			panic(fmt.Sprintf("Could not load OIDC config %s", err))
		}
		initializePolicyManager()
		stsProxy()
	},
}

func getProxyProtocol() string {
	secure := viper.GetBool(secure)
	if secure{
		slog.Debug("Got proxy protocol", "procotol", "https", "secure", secure)
		return "https"
	} else {
		slog.Debug("Got proxy protocol", "procotol", "http", "secure", secure)
		return "http"
	}
}

func awaitServerOnPort(port int, secure bool) error {
	attempts := 100
	if secure{
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s://localhost:%d/ping", getProxyProtocol(), port), nil)
	var lastErr error
	i := 0
	for i < attempts{
		i += 1
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("server not listening on port %d after %d checks, last err %s", port, attempts, lastErr)
}

func createAndStartStsProxy() (*sync.WaitGroup, *http.Server, error) {
	stsProxyDone := &sync.WaitGroup{}
	stsProxyDone.Add(1)
	portNr := viper.GetInt(stsProxyPort)
	certFile := viper.GetString(stsProxyCertFile)
	keyFile := viper.GetString(stsProxyKeyFile)
	secure := viper.GetBool(secure)
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()

	registerStsRouter(router)
	listenAddress := fmt.Sprintf(":%d", portNr)
	slog.Info("Started listening", "port", portNr)

	srv := &http.Server{Addr: listenAddress}
	srv.Handler = middleware.NewMiddlewarePrefixedHandler(
		router, 
		middleware.LogMiddleware(slog.LevelInfo, middleware.NewPingPongHealthCheck(slog.LevelDebug),),
	)
	
	// Start proxy in the background but manage waitgroup
	go func() {
		defer stsProxyDone.Done()
		var err error
		if secure {
			slog.Info("Starting ListenAndServeTLS", "secure", secure)
			err = srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			slog.Info("Starting ListenAndServe", "secure", secure)
			err = srv.ListenAndServe()
		}

		if err != http.ErrServerClosed {
			slog.Error(err.Error())
		}
	}()

	err := awaitServerOnPort(portNr, secure)
	if err != nil {
		stsProxyDone.Done()
		return nil, nil, err
	}

	return stsProxyDone, srv, nil
}

func stsProxy() {
	proxyDone, _, err := createAndStartStsProxy()
	if err != nil {
		panic(err)
	}
	proxyDone.Wait()
	
}

func registerStsRouter(router *mux.Router) {
	stsRouter := router.NewRoute().PathPrefix(SlashSeparator).Subrouter()

	stsRouter.Methods(http.MethodPost).HandlerFunc(processSTSPost)

	stsRouter.PathPrefix("/").HandlerFunc(justLog)
}

func newProxyIssuedToken(subject, issuer, roleARN string, expiry time.Duration, tags session.AWSSessionTags) (token *jwt.Token) {
	return createRS256PolicyToken(stsProxyIssuer, issuer, subject, roleARN, expiry, tags)
}

func calculateFinalDurationSeconds(apiProvidedDuration int, jwtExpiry *jwt.NumericDate) (*time.Duration, error) {
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
	if finalDuration > getMaxStsDuration() {
		return nil, fmt.Errorf("provided duration seconds exceed the maximum of %d seconds", getMaxStsDurationSeconds())
	}
	return &finalDuration, nil
}

//Generic processing of POST. For an API request that handle a POST
//The parameters can be as form data which hinders from routing more
//fine-grained
func processSTSPost(w http.ResponseWriter, r *http.Request) {
	//At the final end discard what is being sent.
	//If not some clients might not check the response that is being sent and hang untill timeout
	//An example is boto3 where urllib3 won't check the response if it is still sending data
	if r.Body != nil {
		defer r.Body.Close()
	}

	ctx := requestctx.NewContextFromHttpRequest(r)
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
		assumeRoleWithWebIdentity(ctx, w, r)
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
func assumeRoleWithWebIdentity(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	claims := stsClaims{}
	defer slog.InfoContext(ctx, "Auditlog", "claims", claims)

	token := r.Form.Get(stsWebIdentityToken)

	claimsMap, err := ExtractOIDCTokenClaims(token)
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
	subFromTokenSha1 := sha1sum(subFromToken)
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

	duration, err := calculateFinalDurationSeconds(durationSecondsInt, expiry)
	if err != nil {
		slog.ErrorContext(ctx, "Error calculating final duration seconds", "error", err)
		slog.DebugContext(ctx, "Error calculating final duration seconds", "error", err, "token", token)
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	roleArn := r.Form.Get(stsRoleArn)
	if !pm.DoesPolicyExist(roleArn) {
		slog.InfoContext(ctx, "Error retrieving policy", "role_arn", roleArn, "error", err)
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, fmt.Errorf("invalid value for %s: %s", stsRoleArn, roleArn))
		return
	}
	
	newToken := newProxyIssuedToken(subject, issuer, roleArn, *duration, claimsMap.Tags)

	cred, err := credentials.NewAWSCredentials(newToken, *duration, getSigningKey)

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
	encodedSuccessResponse = encodeResponse(ctx, webIdentityResponse)

	writeSuccessResponseXML(ctx, w, encodedSuccessResponse)
}

func init() {
	rootCmd.AddCommand(proxystsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// proxystsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// proxystsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
