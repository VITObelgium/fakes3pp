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
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	s3proxy "github.com/VITObelgium/fakes3pp/aws/service/s3"
	stsproxy "github.com/VITObelgium/fakes3pp/aws/service/sts"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/VITObelgium/fakes3pp/testutils"
	"github.com/VITObelgium/fakes3pp/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

const testRegion1 = "tst-1"
const testRegion2 = "eu-test-2"

var defaultBakendIdAlmostE2ETests = testRegion2
var backendTestRegions = []string{testRegion1, testRegion2}
var testingBucketNameBackenddetails = "backenddetails"
var fakeTestBackendPorts = map[string]int{
	testRegion1: 5000,
	testRegion2: 5001,
}
var fakeTestBackendHostnames = map[string]string{
	testRegion1: "localhost",
	testRegion2: "localhost",
}
var testingRegionTxtObjectKey = "region.txt"
var fakeTestBackends = map[string]string{
	testRegion1: "http://localhost:5000",
	testRegion2: "http://localhost:5001",
}

var testingBackendsConfig = []byte(fmt.Sprintf(`
# This is a test file check backend-config.yaml if you want to create a configuration
s3backends:
  - region: %s
    credentials:
      inline:
        aws_access_key_id: fake_key_id
        aws_secret_access_key: fake_secret
    endpoint: %s
  - region: %s
    credentials:
      inline:
        aws_access_key_id: fake_key_id_otc
        aws_secret_access_key: fake_secret_otc
        aws_session_token: fakeSessionTokOtc1
    endpoint: %s
    capabilities: ["StreamingUnsignedPayloadTrailer"]
default: %s
`, testRegion1, fakeTestBackends[testRegion1], testRegion2, fakeTestBackends[testRegion2], defaultBakendIdAlmostE2ETests))

var testFakeIssuer string = "https://localhost/auth/realms/testing"

var testProviderFakeTesting string = fmt.Sprintf(`
  testing:
    realm: testing
    public_key: "MIIBCgKCAQEAoncey4tgLAI2zZj6CGZTCnhOW9hxtv+QJ/1qDTqYKyZecSahk4a9duUVRUT0wZUZRZgba/mYZg/9ypuz4C/elf2iMgnHRmBCJmQy1eQGa+RirzmnDpFeo/1bCeWLXd4gg+HT5NFoJKl79O1ZX9TXa9mExZsK7/+1WoZeWH0u9YP50+ULMmeFReAH9SzytJVx8fD2Ir1dEsrQFM5dYPP1liYFidUwD5Q5STHqAEoOkOPMhduUjyGRLEy66sPM1o9Iw3GcN1IdPVKVEkuX9QcM/AJCVtSbES5MDYqysJXAeF3a0ucHMwE9ND+mqPZD9tUQ9zbw0dULdCyI0zac/c6HEwIDAQAB"
    token-service: https://localhost/auth/realms/testing/protocol/openid-connect
    account-service: https://localhost/auth/realms/testing/account
    tokens-not-before: 0
    iss: %s`, testFakeIssuer)

var testConfigFakeTesting string = fmt.Sprintf("providers:%s", testProviderFakeTesting)

func TestMain(m *testing.M) {
	if os.Getenv("DEBUG_LOCAL_TEST") == "" {
		envFiles = "../etc/.env"
		loadEnvVarsFromDotEnv()
		initConfig()
		initializeTestLogging()
	}
	// For testing allow short duration for STS sessions
	err := os.Setenv("FAKES3PP_STS_MINIMAL_DURATION_SECONDS", "1")
	if err != nil {
		panic(fmt.Sprintf("Error when preparing env for test: %s", err))
	}
	m.Run()
}

func setupSuiteProxyS3(
	t testing.TB, opts server.ServerOpts,
) (func(t testing.TB), *s3proxy.S3Server) {
	s := buildS3Server()
	s3ProxyDone, s3ProxySrv, err := server.CreateAndStart(s, opts)
	if err != nil {
		t.Errorf("Could not spawn fake STS server %s", err)
	}
	s3server, ok := s.(*s3proxy.S3Server)
	if !ok {
		t.Error("Cannot be created S3 server is not an s3 server")
		t.FailNow()
	}

	// Return a function to teardown the test
	return func(t testing.TB) {
		if err := s3ProxySrv.Shutdown(context.Background()); err != nil {
			panic(err)
		}
		// wait for goroutines started in startHttpServer() to stop
		s3ProxyDone.Wait()
	}, s3server
}

func setupSuiteProxySTS(
	t testing.TB, opts server.ServerOpts,
) (func(t testing.TB), *stsproxy.STSServer) {
	s := buildSTSServer()
	stsProxyDone, stsProxySrv, err := server.CreateAndStart(s, opts)
	if err != nil {
		t.Errorf("Could not spawn fake STS server %s", err)
	}
	stsserver, ok := s.(*stsproxy.STSServer)
	if !ok {
		t.Error("Cannot be created S3 server is not an s3 server")
		t.FailNow()
	}

	// Return a function to teardown the test
	return func(t testing.TB) {
		if err := stsProxySrv.Shutdown(context.Background()); err != nil {
			panic(err)
		}
		// wait for goroutines started in startHttpServer() to stop
		stsProxyDone.Wait()
	}, stsserver
}

func stageYamlFileContent(t testing.TB, viperKey, content string) (filename string) {
	filename = testutils.TempYamlFile(t, content)
	viper.Set(viperKey, filename)
	return filename
}

// Set the configurations as expected for the testingbackends
// See testing/README.md for details on testing setup
func stageTestingBackendsConfig(t testing.TB) (filename string) {
	return stageYamlFileContent(t, s3BackendConfigFile, string(testingBackendsConfig))
}

func stageTestingOIDCConfig(t testing.TB) (filename string) {
	return stageYamlFileContent(t, stsOIDCConfigFile, string(testConfigFakeTesting))
}

func getTestingKeyStorage(t testing.TB) utils.KeyPairKeeper {
	rsaKeyFilePath := viper.GetString(s3ProxyJwtPrivateRSAKey)
	keyStorage, err := utils.NewKeyStorage(rsaKeyFilePath)
	if err != nil {
		t.Error("Could not get signing key for testing", "error", err)
		t.FailNow()
	}
	return keyStorage
}

func policyFixture(t testing.TB, policies map[string]string) (tearDown func()) {
	policyDir := testutils.StagePoliciesInTempDir(t, policies)
	oldRolePolicyPath := viper.GetString(rolePolicyPath)
	viper.Set(rolePolicyPath, policyDir)
	return func() {
		viper.Set(rolePolicyPath, oldRolePolicyPath)
	}
}

var testPolicyAllowAllARN = "arn:aws:iam::000000000000:role/AllowAll"

func defaultPolicyFixture(t testing.TB) (teardown func()) {
	return policyFixture(
		t,
		map[string]string{
			testPolicyAllowAllARN: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "*",
						"Resource": "*"
					}
				]
			}`,
			testPolicyAllowTeamFolderARN:   testPolicyAllowTeamFolder,
			testPolicyAllowAllInRegion1ARN: testPolicyAllowAllInRegion1,
		},
	)
}

// This is the testing fixture. It starts an sts and s3 proxy which
// are configured with the S3 backends detailed in testing/README.md.
func testingFixture(t testing.TB) (
	tearDown func(),
	getToken func(subject string, d time.Duration, tags session.AWSSessionTags) string,
	stsServer server.Serverable,
	s3Server server.Serverable,
) {
	return testingFixtureCustomServerOpts(
		t,
		server.ServerOpts{},
		server.ServerOpts{},
	)
}

func testingFixtureCustomServerOpts(t testing.TB, stsServerOpts server.ServerOpts, s3ServerOpts server.ServerOpts) (
	tearDown func(),
	getToken func(subject string, d time.Duration, tags session.AWSSessionTags) string,
	stsServer server.Serverable,
	s3Server server.Serverable,
) {
	skipIfNoTestingBackends(t)
	//Configure backends to be the testing S3 backends
	stageTestingBackendsConfig(t)
	stageTestingOIDCConfig(t)
	teardownPolicies := defaultPolicyFixture(t)
	defer teardownPolicies()

	//Given valid server config
	teardownSuiteSTS, stsServer := setupSuiteProxySTS(t, stsServerOpts)
	teardownSuiteS3, s3Server := setupSuiteProxyS3(t, s3ServerOpts)

	keyStorage := getTestingKeyStorage(t)

	//function to stop the setup of the fixture
	tearDownProxies := func() {
		teardownSuiteSTS(t)
		teardownSuiteS3(t)
	}

	//function to get a valid token that can be exchanged for credentials
	getSignedToken := func(subject string, d time.Duration, tags session.AWSSessionTags) string {
		unsignedToken := jwt.NewWithClaims(jwt.SigningMethodRS256, credentials.NewIDPClaims(testFakeIssuer, subject, d, tags))

		token, err := credentials.CreateSignedToken(unsignedToken, keyStorage)
		if err != nil {
			t.Errorf("Could create signed token with subject %s and tags %v: %s", subject, tags, err)
			t.FailNow()
		}
		return token
	}

	return tearDownProxies, getSignedToken, stsServer, s3Server
}

func getCredentialsFromTestStsProxy(t testing.TB, token, sessionName, roleArn string, stsServer server.Serverable, durationSecs *int32) aws.Credentials {
	result, err := testutils.AssumeRoleWithWebIdentityAgainstTestStsProxy(t, token, sessionName, roleArn, stsServer, durationSecs)
	if err != nil {
		t.Errorf("encountered error when assuming role: %s", err)
		t.FailNow()
	}
	creds := result.Credentials
	awsCreds := aws.Credentials{
		AccessKeyID:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
		Expires:         *creds.Expiration,
		CanExpire:       true,
	}
	return awsCreds
}

// region object is setup in the backends and matches the region name of the backend
func getRegionObjectContent(t *testing.T, region string, creds *credentials.AWSCredentials, s3Server server.Serverable) (string, smithy.APIError) {
	return getTestBucketObjectContent(t, region, testingRegionTxtObjectKey, creds, s3Server)
}

func getTestBucketObjectContent(t testing.TB, region, objectKey string, creds *credentials.AWSCredentials, s3Server server.Serverable) (string, smithy.APIError) {

	client := testutils.GetTestClientS3(t, region, creds, s3Server)

	max1Sec, cancel := context.WithTimeout(context.Background(), 1000*time.Second)

	input := s3.GetObjectInput{
		Bucket: &testingBucketNameBackenddetails,
		Key:    &objectKey,
	}
	defer cancel()
	s3ObjectOutput, err := client.GetObject(max1Sec, &input)
	if err != nil {
		var oe smithy.APIError
		if !errors.As(err, &oe) {
			t.Errorf("Could not convert smity error")
			t.FailNow()
		}
		return "", oe
	}
	bytes, err := io.ReadAll(s3ObjectOutput.Body)
	if err != nil {
		t.Error("Reading body should not fail unless issue with test environment")
		t.FailNow()
	}
	return string(bytes), nil
}

// Backend selection is done by chosing a region. The enpdoint we use is fixed
// to our testing S3Proxy and therefore the hostname is the same. In each backend
// we have a bucket with the same name and region.txt which holds the actual region
// name which we can use to validate that our request went to the right backend.
func TestMakeSureCorrectBackendIsSelected(t *testing.T) {
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	//Given the policy Manager that has roleArn for the testARN (is in default fixture)
	//Given credentials for that role
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, nil)

	for _, backendRegion := range backendTestRegions {
		regionContent, err := getRegionObjectContent(t, backendRegion, credentials.FromAwsFormat(creds), s3Server)
		if err != nil {
			t.Errorf("Could not get region content due to error %s", err)
		} else if regionContent != backendRegion {
			t.Errorf("when retrieving region file for %s we got %s", backendRegion, regionContent)
		}
	}
}

// When requests are made with an invalid region generally it is expected to have the requests fail.
// for the legacy implementation only supporting a single backend that was not the case and the region
// information was ignored. It is recommended to discourage usage of wrong regions by region out to users
// who are using an invalid region. But to allow for a grace period where not breaking old usages you can also
// ENABLE_LEGACY_BEHAVIOR_INVALID_REGION_TO_DEFAULT_REGION
func TestAllowFallbackToDefaultBackend(t *testing.T) {
	//Given legacy behavior mode enabled
	viper.Set(enableLegacyBehaviorInvalidRegionToDefaultRegion, true)

	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	//Given the policy Manager that has roleArn for the testARN (is in default fixture)
	//Given credentials for that role
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, nil)

	// When a request is done to an invalid region
	regionContent, err := getRegionObjectContent(t, "invalidRegion", credentials.FromAwsFormat(creds), s3Server)
	// The response is as if the request was set to the default region
	if err != nil {
		t.Errorf("Could not get region content due to error %s", err)
	} else if regionContent != defaultBakendIdAlmostE2ETests {
		t.Errorf("when retrieving region file for %s we got %s but expected %s", "invalidRegion", regionContent, defaultBakendIdAlmostE2ETests)
	}
}

// When not allowing fallback an invalid region should have clear indication that it is a user err
func TestIfNoFallbackToDefaultBackendBadRequestShouldBeReturned(t *testing.T) {
	//Given legacy behavior mode enabled
	viper.Set(enableLegacyBehaviorInvalidRegionToDefaultRegion, false)

	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	//Given the policy Manager that has roleArn for the testARN (is in default fixture)
	//Given credentials for that role
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, nil)

	// When a request is done to an invalid region
	regionContent, err := getRegionObjectContent(t, "invalidRegion", credentials.FromAwsFormat(creds), s3Server)
	// The response is as if the request was set to the default region
	if err == nil {
		t.Errorf("Should not have succeeded but I got %s without error", regionContent)
	}
	if err.ErrorMessage() != "The provided region is not valid." {
		t.Errorf("Unexpected error message: %s", err.ErrorMessage())
		t.FailNow()
	}
}

func TestSigv4PresignedUrlsWork(t *testing.T) {
	//Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Second*2, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	var durationSecs int32 = 2
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, &durationSecs)

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodGet, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	//When creating a presigned url it and using that presigned url it should return the region correctly.
	for _, backendRegion := range backendTestRegions {
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
		}
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Get(signedUri)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Did not expect error when getting body of signed url response for %s. Got %s", backendRegion, err)
		}
		if string(bytes) != backendRegion {
			t.Errorf("Invalid response of presigned url expected %s, got %s", backendRegion, string(bytes))
		}
	}
}

func TestSigv4PresignedUrlsWorkAndCORSHeadersAreAdded(t *testing.T) {
	//Given an allow for a test origin
	t.Setenv(FAKES3PP_S3_CORS_STRATEGY, valueStatic)
	testOrigin := "my.test.internal"
	t.Setenv(FAKES3PP_S3_CORS_STATIC_ALLOWED_ORIGIN, testOrigin)

	//Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Second*2, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	var durationSecs int32 = 2
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, &durationSecs)

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodGet, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	//When creating a presigned url it and using that presigned url it should return the region correctly.
	for _, backendRegion := range backendTestRegions {
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
		}
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Get(signedUri)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Did not expect error when getting body of signed url response for %s. Got %s", backendRegion, err)
		}
		if string(bytes) != backendRegion {
			t.Errorf("Invalid response of presigned url expected %s, got %s", backendRegion, string(bytes))
		}
		accessControlAllowOrigin := resp.Header.Values("Access-Control-Allow-origin")
		originWhitelisted := false
		for _, value := range accessControlAllowOrigin {
			if value == testOrigin {
				originWhitelisted = true
			}
		}
		if !originWhitelisted {
			t.Errorf("The origin wasn't whitelisted")
		}
	}
}

func TestSigv4PresignedUrlsWorkWithIgnorableQueryParams(t *testing.T) {
	//Given ignore configuration
	err := os.Setenv(FAKES3PP_S3_PROXY_REMOVABLE_QUERY_PARAMS, "^_origin$,Ignore")
	if err != nil {
		t.Errorf("Error when preparing env for test: %s", err)
	}

	//Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Second*2, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	var durationSecs int32 = 2000
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, &durationSecs)

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodGet, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	//When creating a valid presigned url
	for _, backendRegion := range backendTestRegions {
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
		}
		//When an extra argument is added to the request
		signedUriPatched := fmt.Sprintf("%s%s", signedUri, "&_origin=%2Ftest_my_custom_traceflag")
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Get(signedUriPatched)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Did not expect error when getting body of signed url response for %s. Got %s", backendRegion, err)
		}
		//THEN we still get the expected object content
		if string(bytes) != backendRegion {
			t.Errorf("Invalid response of presigned url expected %s, got %s", backendRegion, string(bytes))
		}
	}
}

func TestHmacV1PresignedUrlsHeadObjectWorks(t *testing.T) {
	//Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Second*2, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	var durationSecs int32 = 2
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, &durationSecs)

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodHead, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	//When creating a presigned url it and using that presigned url it should return the region correctly.
	signedUri, err := presign.CalculateS3PresignedHmacV1QueryUrl(req, creds, 300)
	if err != nil {
		t.Errorf("Did not expect error when signing url. Got %s", err)
	}
	resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Head(signedUri)
	if err != nil {
		t.Errorf("Did not expect error when using signing url. Got %s", err)
	}
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("Did not expect error when getting body of signed url response. Got %s", err)
	}
	if string(bytes) != "" {
		t.Errorf("invalid response of presigned url expected empty body, got %s", string(bytes))
	}
	contentLength, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 0, 32)
	if err != nil {
		t.Errorf("invalid Content-length %s cannot conver to int: %s", resp.Header.Get("Content-Length"), err)
	}
	if int(contentLength) != len(defaultBakendIdAlmostE2ETests) {
		t.Errorf("invalid Content-length header expected %d, got %s", len(defaultBakendIdAlmostE2ETests), resp.Header.Get("Content-Length"))
	}
}

func TestSigv4PresignedUrlsHeadObjectWorks(t *testing.T) {
	//Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Second*2, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	var durationSecs int32 = 2
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, &durationSecs)

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodHead, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	//When creating a presigned url it and using that presigned url it should return the region correctly.
	for _, backendRegion := range backendTestRegions {
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
		}
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Head(signedUri)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Did not expect error when getting body of signed url response for %s. Got %s", backendRegion, err)
		}
		if string(bytes) != "" {
			t.Errorf("invalid response of presigned url expected empty body, got %s", string(bytes))
		}
		contentLength, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 0, 32)
		if err != nil {
			t.Errorf("invalid Content-length %s cannot conver to int: %s", resp.Header.Get("Content-Length"), err)
		}
		if int(contentLength) != len(backendRegion) {
			t.Errorf("invalid Content-length header expected %d, got %s", len(backendRegion), resp.Header.Get("Content-Length"))
		}
	}
}

func TestSigv4PresignedUrlsHeadObjectForGetSignedWorks(t *testing.T) {
	// Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Second*2, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	var durationSecs int32 = 2
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, &durationSecs)

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodGet, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	// Given extra query parameter "AllowHead=true"
	urlValues := url.Values{}
	urlValues.Add(constants.HeadAsGet, "true")
	req.URL.RawQuery = urlValues.Encode()

	for _, backendRegion := range backendTestRegions {
		//WHEN creating a presigned url for a get method
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
		}
		//THEN performing a HEAD using that presigned url it should return the correct Content-Length
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Head(signedUri)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Did not expect error when getting body of signed url response for %s. Got %s", backendRegion, err)
		}
		if string(bytes) != "" {
			t.Errorf("invalid response of presigned url expected empty body, got %s", string(bytes))
		}
		contentLength, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 0, 32)
		if err != nil {
			t.Errorf("invalid Content-length %s cannot conver to int: %s", resp.Header.Get("Content-Length"), err)
		}
		if int(contentLength) != len(backendRegion) {
			t.Errorf("invalid Content-length header expected %d, got %s", len(backendRegion), resp.Header.Get("Content-Length"))
		}
		//THEN performing a GET using that presigned url it should return the correct region
		resp, err = testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Get(signedUri)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		bytes, err = io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Did not expect error when getting body of signed url response for %s. Got %s", backendRegion, err)
		}
		if string(bytes) != backendRegion {
			t.Errorf("Invalid response of presigned url expected %s, got %s", backendRegion, string(bytes))
		}
	}
}

func TestSigv4PresignedUrlsHeadObjectForGetSignedCannotBeAltered(t *testing.T) {
	// Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Second*2, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	var durationSecs int32 = 2
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, &durationSecs)

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodGet, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	for _, backendRegion := range backendTestRegions {
		//WHEN creating a presigned url for a get method
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
		}
		// WHEN adding extra query parameter "AllowHead=true"
		urlValues := url.Values{}
		urlValues.Add(constants.HeadAsGet, "true")
		signedUri = fmt.Sprintf("%s&%s", signedUri, urlValues.Encode())
		//THEN performing a HEAD using that presigned url it should be Forbidden
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Head(signedUri)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Altered request should get forbidden response (403), got %d", resp.StatusCode)
		}
		//THEN performing a GET using that presigned url it should be Forbidden
		resp, err = testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Get(signedUri)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Altered request should get forbidden response (403), got %d", resp.StatusCode)
		}
	}
}

func TestSigv4PresignedUrlsWorkInGracePeriod(t *testing.T) {
	testutils.SkipIfNoSlowUnittests(t)
	//Given grace time of 5 seconds (../etc/.env)
	//Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	var durationSecs int32 = 2
	token := getSignedToken("mySubject", time.Second*time.Duration(durationSecs), session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, &durationSecs)

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodGet, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	time.Sleep(time.Second * time.Duration(durationSecs+1))
	//When creating a presigned url it and using that presigned url it should return the region correctly.
	for _, backendRegion := range backendTestRegions {
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
		}
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Get(signedUri)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Did not expect error when getting body of signed url response for %s. Got %s", backendRegion, err)
		}
		if string(bytes) != backendRegion {
			t.Errorf("Invalid response of presigned url expected %s, got %s", backendRegion, string(bytes))
		}
	}
}

func TestSigv4PresignedUrlsFailOutsideGracePeriod(t *testing.T) {
	testutils.SkipIfNoSlowUnittests(t)
	//Given grace time of 5 seconds (../etc/.env)
	//Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	var durationSecs int32 = 2
	token := getSignedToken("mySubject", time.Second*time.Duration(durationSecs), session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, &durationSecs)

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodGet, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	time.Sleep(time.Second * time.Duration(durationSecs+5))
	//When creating a presigned url it and using that presigned url it should return the region correctly.
	for _, backendRegion := range backendTestRegions {
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
		}
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Get(signedUri)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Did not expect error when getting body of signed url response for %s. Got %s", backendRegion, err)
		}
		if resp.StatusCode >= 500 || resp.StatusCode < 400 {
			t.Errorf("Invalid response code. Must indicate user error got %d", resp.StatusCode)
		}
		if !strings.Contains(string(bytes), "credentials are expired") {
			t.Errorf("Expected response to indicate expired credentials got %s", string(bytes))
		}
	}
}

func TestSigv4PresignedUrlsWorkWithRanges(t *testing.T) {
	//Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN, stsServer, nil)

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodGet, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	//When creating a presigned url
	for _, backendRegion := range backendTestRegions {
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
		}
		req, err := http.NewRequest("GET", signedUri, nil)
		if err != nil {
			t.Errorf("Did not expect error when creating request object for signing url for %s. Got %s", backendRegion, err)
		}
		//And when adding a range post-signing
		firstByte := 0
		lastByte := 2
		req.Header.Add("Range", fmt.Sprintf("bytes=%d-%d", firstByte, lastByte))
		//Then it should work and return the corresponding bytes
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Do(req)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Did not expect error when getting body of signed url response for %s. Got %s", backendRegion, err)
		}
		// Range includes the upper bound where golang slices do not
		if string(bytes) != backendRegion[firstByte:lastByte+1] {
			t.Errorf("Invalid response of presigned url expected %s, got %s", backendRegion, string(bytes))
		}
	}
}

var testPolicyAllowTeamFolderARN = "arn:aws:iam::000000000000:role/AllowTeamFolder"
var testAllowedTeam = "teamA"
var testDisallowedTeam = "teamB"
var testTeamTag = "team"
var testTeamFile = "team.txt"

// This policy is to test whether principl tags are correctly set when
// assuming a role an correctly enforced when evaluating policies. This is
// used in test cases that start with TestPolicyAllowTeamFolder
var testPolicyAllowTeamFolder string = fmt.Sprintf(`{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::%s/%s",
			"Condition" : {
					"StringLike" : {
							"aws:PrincipalTag/%s": "%s"
					}
			}
		}
	]
}`, testingBucketNameBackenddetails, testTeamFile, testTeamTag, testAllowedTeam)

var testPolicyAllowAllInRegion1ARN string = "arn:aws:iam::000000000000:role/AllowAllInRegion1"

// This policy is to test whether a policy can be scoped to a specific region
// since our proxy uses region to determine a backend this makes sure to be able
// to have different permissions for different backends. This is used in test cases
// that start with TestPolicyAllowAllInRegion1
var testPolicyAllowAllInRegion1 string = fmt.Sprintf(`{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": "s3:*",
			"Resource": "*",
			"Condition" : {
					"StringLike" : {
							"aws:RequestedRegion": "%s"
					}
			}
		}
	]
}`, testRegion1)

func TestPolicyAllowTeamFolderIDPClaimsCanBeUsedInPolicyEvaluationPrincipalWithCorrectTag(t *testing.T) {
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	// GIVEN token for team that does have access
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{testTeamTag: {testAllowedTeam}}})
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowTeamFolderARN, stsServer, nil)

	//WHEN access is attempted that required the team information
	content, err := getTestBucketObjectContent(t, testRegion1, testTeamFile, credentials.FromAwsFormat(creds), s3Server)

	//THEN the file content should be returned
	if err != nil {
		t.Errorf("Could not get team file even though part of correct team. got %s", err)
	}
	expectedContent := "teamSecret123"
	if content != expectedContent {
		t.Errorf("Got %s, expected %s", content, expectedContent)
	}
}

func TestPolicyAllowTeamFolderIDPClaimsCanBeUsedInPolicyEvaluationPrincipalWithIncorrectTag(t *testing.T) {
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	// GIVEN token for team that does not have access
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{testTeamTag: {testDisallowedTeam}}})
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowTeamFolderARN, stsServer, nil)

	//WHEN access is attempted that required the team information
	_, err := getTestBucketObjectContent(t, testRegion1, testTeamFile, credentials.FromAwsFormat(creds), s3Server)

	//THEN the request should be denied
	if err == nil {
		t.Error("We should have gotten a Forbidden error but no error was raised.")
	}
	if err.ErrorCode() != "AccessDenied" {
		t.Errorf("Expected AccessDenied, got %s", err.ErrorCode())
	}
}

func TestPolicyAllowTeamFolderIDPClaimsCanBeUsedInPolicyEvaluationPrincipalWithoutTag(t *testing.T) {
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	// GIVEN token with no team information
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{}})
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowTeamFolderARN, stsServer, nil)

	//WHEN access is attempted that required the team information
	_, err := getTestBucketObjectContent(t, testRegion1, testTeamFile, credentials.FromAwsFormat(creds), s3Server)

	//THEN the request should be denied
	if err == nil {
		t.Error("We should have gotten a Forbidden error but no error was raised.")
	}
	if err.ErrorCode() != "AccessDenied" {
		t.Errorf("Expected AccessDenied, got %s", err.ErrorCode())
	}
}

func TestPolicyAllowAllInRegion1ConditionsOnRegionAreEnforced(t *testing.T) {
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	//Given the policy Manager that has our test policies
	//Given credentials that use the policy that allow everything in Region1
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllInRegion1ARN, stsServer, nil)

	//WHEN we get an object in region 1
	regionContent, err := getRegionObjectContent(t, testRegion1, credentials.FromAwsFormat(creds), s3Server)
	//THEN it should just succeed as any action is allowed
	if err != nil {
		t.Errorf("Could not get region content due to error %s", err)
	} else if regionContent != testRegion1 {
		t.Errorf("when retrieving region file for %s we got %s", testRegion1, regionContent)
	}

	//WHEN we get an object in region2
	regionContent2, err2 := getRegionObjectContent(t, testRegion2, credentials.FromAwsFormat(creds), s3Server)
	//THEN we expect it to give an access denied as no explicit allow exists for which region is not excluded via a condition
	if err2 == nil {
		t.Errorf("Could get region content %s but policy should have limited to %s", regionContent2, testRegion1)
	} else {
		if err2.ErrorCode() != "AccessDenied" {
			t.Errorf("Expected AccessDenied, got %s", err.ErrorCode())
		}
	}
}

func _listTestBucketObjects(t testing.TB, prefix string, client *s3.Client) (*s3.ListObjectsV2Output, smithy.APIError) {
	max1Sec, cancel := context.WithTimeout(context.Background(), 1000*time.Second)

	input := s3.ListObjectsV2Input{
		Bucket: &testingBucketNameBackenddetails,
		Prefix: &prefix,
	}
	defer cancel()
	s3ListObjectsOutput, err := client.ListObjectsV2(max1Sec, &input)
	if err != nil {
		var oe smithy.APIError
		if !errors.As(err, &oe) {
			t.Errorf("Could not convert smity error")
			t.FailNow()
		}
		return nil, oe
	}
	return s3ListObjectsOutput, nil
}

func listTestBucketObjects(t testing.TB, region, prefix string, creds aws.CredentialsProvider, s3server server.Serverable) (*s3.ListObjectsV2Output, smithy.APIError) {
	client := testutils.GetTestClientS3(t, region, creds, s3server)
	return _listTestBucketObjects(t, prefix, client)
}

func putTestBucketObject(t testing.TB, region, key, content string, creds aws.CredentialsProvider, s3server server.Serverable) (*s3.PutObjectOutput, smithy.APIError) {
	client := testutils.GetTestClientS3(t, region, creds, s3server)
	putObjectParams := s3.PutObjectInput{
		Bucket: &testingBucketNameBackenddetails,
		Key:    &key,
		Body:   strings.NewReader(content),
	}
	out, err := client.PutObject(context.TODO(), &putObjectParams)
	if err != nil {
		var oe smithy.APIError
		if !errors.As(err, &oe) {
			t.Errorf("Could not convert smity error")
			t.FailNow()
		}
		return nil, oe
	}
	return out, nil
}

// Make sure that needleObjectKey exists in the object Listing objectsList
func assertObjectInBucketListing(t testing.TB, objectsList *s3.ListObjectsV2Output, needleObjectKey string) {
	for _, s3Object := range objectsList.Contents {
		if needleObjectKey == *s3Object.Key {
			return
		}
	}
	t.Errorf("Did not encounter %s in %v", needleObjectKey, objectsList)
}

func TestListingOfS3BucketHasExpectedObjects(t *testing.T) {
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	//Given the policy Manager that has our test policies
	//Given credentials that use the policy that allow everything in Region1
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllInRegion1ARN, stsServer, nil)

	var prefix = ""

	//WHEN we get an object in region 1
	listObjects, err := listTestBucketObjects(t, testRegion1, prefix, credentials.FromAwsFormat(creds), s3Server)
	//THEN it should just succeed as any action is allowed
	if err != nil {
		t.Errorf("Could not get objects in bucket due to error %s", err)
	}
	//THEN it should report the known objects "region.txt" and "team.txt"
	assertObjectInBucketListing(t, listObjects, "region.txt")
	assertObjectInBucketListing(t, listObjects, "team.txt")
}

// This test wil verify support for unicode characters
// It covers both the regular signature part as the presigned part
func TestForHtmlEscaping(t *testing.T) {
	tearDown, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDown()
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	//Given the policy Manager that has our test policies
	//Given credentials that use the policy that allow everything in Region1
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllInRegion1ARN, stsServer, nil)

	var key = "unicodeTestσ"

	//WHEN we pu an object in region 1
	_, err := putTestBucketObject(t, testRegion1, key, "myContent", credentials.FromAwsFormat(creds), s3Server)
	//THEN it should just succeed as any action is allowed
	if err != nil {
		t.Errorf("Could not get objects in bucket due to error %s", err)
	}

	url := fmt.Sprintf("%s/%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, key)
	req, e := http.NewRequest(http.MethodGet, url, nil)
	if e != nil {
		t.Errorf("Could not create request for generating presigned url %s", url)
	}
	signedUri, _, e := presign.PreSignRequestWithCreds(context.Background(), req, 100, time.Now(), creds, testRegion1)
	if e != nil {
		t.Errorf("error when signing request with creds: %s", err)
	}
	resp, e := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Get(signedUri)
	if e != nil {
		t.Errorf("The get should have gone through but got an error: %s", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Presigned url not usable. Got status code %d: %v", resp.StatusCode, resp)
	}
}

func TestAuditLogEntry(t *testing.T) {
	tearDownProxy, getSignedToken, stsServer, s3Server := testingFixture(t)
	defer tearDownProxy()
	teardownLog, getCapturedStructuredLogEntries := testutils.CaptureStructuredLogsFixture(t, slog.LevelInfo, nil)
	defer teardownLog()

	//GIVEN we run another test scenario
	//_GIVEN token for team that does have access
	token := getSignedToken("mySubject", time.Minute*20, session.AWSSessionTags{PrincipalTags: map[string][]string{testTeamTag: {testAllowedTeam}}})
	creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowTeamFolderARN, stsServer, nil)

	//_WHEN access is attempted that required the team information
	content, err := getTestBucketObjectContent(t, testRegion1, testTeamFile, credentials.FromAwsFormat(creds), s3Server)

	//_THEN the file content should be returned
	if err != nil {
		t.Errorf("Could not get team file even though part of correct team. got %s", err)
	}
	expectedContent := "teamSecret123"
	if content != expectedContent {
		t.Errorf("Got %s, expected %s", content, expectedContent)
	}

	//WHEN we get the logs
	logEntries := getCapturedStructuredLogEntries()
	//THEN we have 1 access log entry per service (sts & s3)
	accesslogEntries := logEntries.GetEntriesWithMsg(t, "Request end")
	if len(accesslogEntries) != 2 {
		t.Errorf("Invalid number of access log entries. Expected 2 got: %d", len(accesslogEntries))
	}

	//WHEN we check the s3 auditlog entry
	s3Entry := accesslogEntries.GetEntriesContainingField(t, "s3")[0]
	//Then the operation should be GetObject
	operation := s3Entry.GetStringField(t, "Operation")
	if operation != "GetObject" {
		t.Errorf("Wrong operation present in s3 access log. Expected GetObject got %s", operation)
	}
	if s3Entry.GetFloat64(t, "HTTP status") != 200 {
		t.Error("HTTPS status should have been a 200")
	}
	//Then the error should be empty
	errorCode := s3Entry.GetStringField(t, "Error")
	if errorCode != "-" {
		t.Errorf("Wrong errorCode present in s3 access log. Expected - got %s", errorCode)
	}

	//WHEN we check the sts audit log entry
	stsEntry := accesslogEntries.GetEntriesContainingField(t, "sts")[0]
	//Then the operation should be AssumeRoleWithWebIdentity
	operation = stsEntry.GetStringField(t, "Operation")
	if operation != "AssumeRoleWithWebIdentity" {
		t.Errorf("Wrong operation present in sts access log. Expected AssumeRoleWithWebIdentity got %s", operation)

	}

}

func TestMakeSureRequestFailsWithOldSigningStrategy(t *testing.T) {
	tearDown, _, _, s3Server := testingFixture(t)
	defer tearDown()

	//Given credentials like how they were generated in the old times
	creds := getLegacyCredentials(t, testPolicyAllowAllARN, session.AWSSessionTags{})

	for _, backendRegion := range backendTestRegions {
		_, err := getRegionObjectContent(t, backendRegion, credentials.FromAwsFormat(creds), s3Server)
		if err == nil {
			t.Error("Should not have been able to get region content but it worked")
		}
	}
}

func TestMakeSureRequestSucceedsWithOldSigningStrategyWhenBackwardsCompatibilityEnabled(t *testing.T) {
	//Given feature flag that allows legacy credentials
	restore_env := fixture_with_environment_values(t, map[string]string{"DEPRECATED_ALLOW_LEGACY_CREDENTIALS": "YES"})
	defer restore_env()

	tearDown, _, _, s3Server := testingFixture(t)
	defer tearDown()

	//Given credentials like how they were generated in the old times
	creds := getLegacyCredentials(t, testPolicyAllowAllARN, session.AWSSessionTags{})

	for _, backendRegion := range backendTestRegions {
		regionContent, err := getRegionObjectContent(t, backendRegion, credentials.FromAwsFormat(creds), s3Server)
		if err != nil {
			t.Errorf("Could not get region content due to error %s", err)
		} else if regionContent != backendRegion {
			t.Errorf("when retrieving region file for %s we got %s", backendRegion, regionContent)
		}
	}
}

func TestSigv4PresignedUrlsFailWithOldSigningStrategy(t *testing.T) {
	//Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, _, _, s3Server := testingFixture(t)
	defer tearDown()

	//Given credentials like how they were generated in the old times
	creds := getLegacyCredentials(t, testPolicyAllowAllARN, session.AWSSessionTags{})

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodGet, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	//When creating a presigned url it and using that presigned url it should return the region correctly.
	for _, backendRegion := range backendTestRegions {
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
			t.FailNow()
		}
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Get(signedUri)
		if err != nil {
			t.Errorf("The get should have gone through but got an error: %s", err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("The api should have returned a Bad Request status but got %d, %v", resp.StatusCode, resp)
		}
	}
}

// test can be removed after DEPRECATED behavior is no longer tolerated.
func TestSigv4PresignedUrlsSucceedWithOldSigningStrategyWhenBackwardsCompatibilityEnabled(t *testing.T) {
	//Given feature flag that allows legacy credentials
	restore_env := fixture_with_environment_values(t, map[string]string{"DEPRECATED_ALLOW_LEGACY_CREDENTIALS": "YES"})
	defer restore_env()

	//Given a running proxy and credentials against that proxy that allow access for the get operation
	tearDown, _, _, s3Server := testingFixture(t)
	defer tearDown()

	//Given credentials like how they were generated in the old times
	creds := getLegacyCredentials(t, testPolicyAllowAllARN, session.AWSSessionTags{})

	//Given a Get request for the region.txt file
	regionFileUrl := fmt.Sprintf("%s%s/%s", testutils.GetTestServerUrl(s3Server), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
	req, err := http.NewRequest(http.MethodGet, regionFileUrl, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	//When creating a presigned url it and using that presigned url it should return the region correctly.
	for _, backendRegion := range backendTestRegions {
		signedUri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 300, time.Now(), creds, backendRegion)
		if err != nil {
			t.Errorf("Did not expect error when signing url for %s. Got %s", backendRegion, err)
		}
		resp, err := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t).Get(signedUri)
		if err != nil {
			t.Errorf("Did not expect error when using signing url for %s. Got %s", backendRegion, err)
		}
		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Did not expect error when getting body of signed url response for %s. Got %s", backendRegion, err)
		}
		if string(bytes) != backendRegion {
			t.Errorf("Invalid response of presigned url expected %s, got %s", backendRegion, string(bytes))
		}
	}
}

func getLegacyCredentials(t testing.TB, roleArn string, tags session.AWSSessionTags) aws.Credentials {
	pkKeeper, err := utils.NewKeyStorage(viper.GetString(s3ProxyJwtPrivateRSAKey))
	if err != nil {
		t.Error("Could not get signing key material")
		t.FailNow()
	}

	expiry := time.Hour

	token := credentials.CreateRS256PolicyToken("issuer", "iisuer", "subject", roleArn, expiry, tags)

	creds, err := newLegacyAWSCredentialsForToken(token, expiry, pkKeeper)
	if err != nil {
		t.Error("Could not create legacy credentials: %w", err)
		t.FailNow()
	}
	awsCreds := aws.Credentials{
		AccessKeyID:     creds.AccessKey,
		SecretAccessKey: creds.SecretKey,
		SessionToken:    creds.SessionToken,
		Expires:         creds.Expiration,
		CanExpire:       true,
	}
	return awsCreds
}

func newLegacyAWSCredentialsForToken(token *jwt.Token, expiry time.Duration, keyStorage utils.PrivateKeyKeeper) (*credentials.AWSCredentials, error) {
	accessKey := credentials.NewAccessKey()

	key, err := keyStorage.GetPrivateKey()
	if err != nil {
		return nil, err
	}
	sessionToken, err := token.SignedString(key)
	if err != nil {
		return nil, err
	}
	secretKey, err := credentials.CalculateSecretKey(accessKey, keyStorage)
	if err != nil {
		return nil, err
	}
	cred := &credentials.AWSCredentials{
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
		Expiration:   time.Now().UTC().Add(expiry),
	}
	return cred, nil
}
