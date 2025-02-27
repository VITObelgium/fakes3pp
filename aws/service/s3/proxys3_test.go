package s3

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/VITObelgium/fakes3pp/logging"
	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/VITObelgium/fakes3pp/testutils"
	"github.com/VITObelgium/fakes3pp/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

// https://stackoverflow.com/questions/23729790/how-can-i-do-test-setup-using-the-testing-package-in-go
func TestMain(m *testing.M) {
	logging.InitializeLogging(slog.LevelDebug, nil, nil)
	m.Run()
}

var testRequests = []*http.Request{}

var testProxyStub = func (ctx context.Context, w http.ResponseWriter, r *http.Request, backendId string, bm interfaces.BackendManager)  {
	testRequests = append(testRequests, r)
	w.WriteHeader(http.StatusOK)
}

func popLastRequestByTestProxy() (*http.Request) {
	if len(testRequests) == 0 {
		return nil
	}
	lastRequest := testRequests[len(testRequests)-1]
	testRequests = testRequests[:len(testRequests)-1]
	return lastRequest
}
var testStubJustProxy interfaces.HandlerBuilderI = handlerBuilder{proxyFunc: testProxyStub}

const testS3Port = 8443
const testS3Host = "localhost"
var testEtcPath = "../../../etc"

func getDefaultTestBackendConfig() (interfaces.BackendManager) {
	return &backendsConfig{
		backends: map[string]backendConfigEntry{
			"waw3-1": {
				credentials: aws.Credentials{
					AccessKeyID: "testKeyIdWaw31",
					SecretAccessKey: "testSecretKeyWaw31",
				},
				endpoint: "https://s3.waw3-1.cloudferro.com",
			},
			"eu-nl": {
				credentials: aws.Credentials{
					AccessKeyID: "testKeyIdEuNl",
					SecretAccessKey: "testSecretKeyEuNl",
					SessionToken: "testSessionTokenEuNl",
				},
				endpoint: "https://obs.eu-nl.otc.t-systems.com",
			},
		},
		defaultBackend: "waw3-1",
	}
}

func NewTestS3Server(t testing.TB, proxyHB interfaces.HandlerBuilderI, pm *iam.PolicyManager, bm interfaces.BackendManager,
	mws []middleware.Middleware, isTlsEnabled bool) (*S3Server) {
	tlsCert := ""
	tlsKey := ""

	if bm == nil {
		bm = getDefaultTestBackendConfig()
	}

	if pm == nil {
		pm = newTestPolicyManager(t, nil)
	}

	if isTlsEnabled{
		tlsCert = fmt.Sprintf("%s/cert.pem", testEtcPath)
		tlsKey = fmt.Sprintf("%s/key.pem", testEtcPath)
	}
	signedUrlGraceTimeSeconds := 3600

	var jwtTestToken = fmt.Sprintf("%s/jwt_testing_rsa", testEtcPath)
	s, err:= newS3Server(
		jwtTestToken,
		testS3Port,
		[]string{testS3Host},
		tlsCert,
		tlsKey,
		pm,
		signedUrlGraceTimeSeconds,
		proxyHB,
		bm,
		mws,
	)
	if err != nil {
		t.Error("Problem creating test STS server", "error", err)
		t.FailNow()
	}
	return s
}

func setupSuiteProxyS3(
	t testing.TB, proxyHB interfaces.HandlerBuilderI, pm *iam.PolicyManager, bm interfaces.BackendManager, mws []middleware.Middleware, tlsEnabled bool,
) (func(t testing.TB), *S3Server) {
	s := NewTestS3Server(t, proxyHB, pm, bm, mws, tlsEnabled)
	stsProxyDone, stsProxySrv, err := server.CreateAndStart(s, server.ServerOpts{})
	if err != nil {
		t.Errorf("Could not spawn fake STS server %s", err)
	}

	// Return a function to teardown the test
	return func(t testing.TB) {
		if err := stsProxySrv.Shutdown(context.Background()); err != nil {
			panic(err)
		}
		// wait for goroutines started in startHttpServer() to stop
		stsProxyDone.Wait()
	}, s
}

func getS3ProxyUrlWithoutPort(_ testing.TB, s server.Serverable) string {
	tlsEnabled, _, _ := s.GetTls()
	if tlsEnabled {
		return fmt.Sprintf("https://%s", testS3Host)
	} else {
		return fmt.Sprintf("http://%s", testS3Host)
	}
}

//Get the fully qualified URL to the S3 Proxy
func getS3ProxyUrl(t testing.TB, s server.Serverable) string {
	return fmt.Sprintf("%s:%d/", getS3ProxyUrlWithoutPort(t, s), s.GetPort())
}


var testPolicyNoPermissions string = `{
	"Version": "2012-10-17",
	"Statement": []
}`

var testPolicyAllowAll string = `{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": "*",
			"Resource": "*"
		}
	]
}`

var testPolicyAllowAllARN = "arn:aws:iam::000000000000:role/AllowAll"
var testPolicyNoPermissionsARN = "arn:aws:iam::000000000000:role/NoPermissions"

func newTestPolicyManager(_ testing.TB, extraPolicies map[string]string) *iam.PolicyManager {
	policyMap := map[string]string{
		testPolicyAllowAllARN: testPolicyAllowAll,
		testPolicyNoPermissionsARN: testPolicyNoPermissions,
	}
	if extraPolicies == nil {
		extraPolicies = map[string]string{}
	}
	for k, v := range extraPolicies {
		policyMap[k] = v 
	}
	return iam.NewTestPolicyManager(
		policyMap,
	)
}

func createTestCredentialsForPolicy(t testing.TB, policyArn string, keyStorage utils.KeyPairKeeper) (*credentials.AWSCredentials) {
	token := credentials.CreateRS256PolicyToken("stsissuer", "initialIssuer", "userid", policyArn, 20 * time.Minute, session.AWSSessionTags{})
	cred, err := credentials.NewAWSCredentials(token, time.Hour, keyStorage)

	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	return cred
}

func TestWithValidCredsButNoAccess(t *testing.T) {
	teardownSuite, s := setupSuiteProxyS3(t, testStubJustProxy, nil, nil, nil, true)
	defer teardownSuite(t)

	cred := createTestCredentialsForPolicy(t, testPolicyNoPermissionsARN, s.jwtKeyMaterial)

	client := testutils.GetTestClientS3(t, "eu-west-1", cred, s)
	
	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	testPrefix := "doesNotMatter"
	input := s3.ListObjectsV2Input{
		Bucket: &testBucketName,
		Prefix: &testPrefix,
	}
	defer cancel()
	_, err := client.ListObjectsV2(max1Sec, &input)
	if err == nil {
		t.Errorf("encountered no error when trying to do list bucket request")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("Did not get Access Denied, got %s", err.Error())
	}
	popLastRequestByTestProxy()
}

func TestWithValidCreds(t *testing.T) {
	teardownSuite, s := setupSuiteProxyS3(t, testStubJustProxy, nil, nil, nil, true)
	defer teardownSuite(t)

	//Given valid credentials with required permissions
	cred := createTestCredentialsForPolicy(t, testPolicyAllowAllARN, s.jwtKeyMaterial)

	client := testutils.GetTestClientS3(t, "eu-west-1", cred, s)
	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	testPrefix := "doesnotmatterAllareallowed/"
	input := s3.ListObjectsV2Input{
		Bucket: &testBucketName,
		Prefix: &testPrefix,
	}
	defer cancel()
	_, err := client.ListObjectsV2(max1Sec, &input)
	if err != nil {
		t.Errorf("encountered error when trying to do list bucket request: %s", err)
	}
	popLastRequestByTestProxy()
}

func TestWithInValidCreds(t *testing.T) {
	teardownSuite, s := setupSuiteProxyS3(t, testStubJustProxy, nil, nil, nil, true)
	defer teardownSuite(t)

	//Given credentials that as a whole are not valid
	cred := createTestCredentialsForPolicy(t, testPolicyAllowAllARN, s.jwtKeyMaterial)
	cred.AccessKey = "OverwriteToInvalidValue"

	client := testutils.GetTestClientS3(t, "eu-west-1", cred, s)

	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	input := s3.ListBucketsInput{}
	defer cancel()
	_, err := client.ListBuckets(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
}

func TestWithValidCredsOtherRegion(t *testing.T) {
	teardownSuite, s := setupSuiteProxyS3(t, testStubJustProxy, nil, nil, nil, true)
	defer teardownSuite(t)

	//Given credentials that are valid
	cred := createTestCredentialsForPolicy(t, testPolicyAllowAllARN, s.jwtKeyMaterial)

	//Given a client that goes to a different region
	client := testutils.GetTestClientS3(t, "eu-west-1", cred, s)

	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	input := s3.ListBucketsInput{}
	defer cancel()
	_, err := client.ListBuckets(max1Sec, &input)
	if err != nil {
		t.Errorf("encountered error when trying to do list bucket request: %s", err)
	}
	popLastRequestByTestProxy()
}

type BucketBasics struct {
	S3Client *s3.Client
}

type Presigner struct {
	PresignClient *s3.PresignClient
	t             *testing.T
}

func (presigner Presigner) GetObject(
	ctx context.Context, bucketName string, objectKey string, lifetimeSecs int64) (*v4.PresignedHTTPRequest, error) {
	request, err := presigner.PresignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = time.Duration(lifetimeSecs * int64(time.Second))
	})
	if err != nil {
		presigner.t.Errorf("Couldn't get a presigned request to get %v:%v. Here's why: %v\n", bucketName, objectKey, err)
	}
	return request, err
}

func TestWithValidPresignedUrlOtherRegion(t *testing.T) {
	teardownSuite, s := setupSuiteProxyS3(t, testStubJustProxy, nil, nil, nil,true)
	defer teardownSuite(t)

	//Given credentials that are valid
	cred := createTestCredentialsForPolicy(t, testPolicyAllowAllARN, s.jwtKeyMaterial)

	//Given a client that goes to a different region
	client := testutils.GetTestClientS3(t, "eu-west-1", cred, s)

	presignClient := s3.NewPresignClient(client)
	presigner := Presigner{PresignClient: presignClient}

	req, err := presigner.GetObject(context.Background(), testBucketName, "key", 60)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, nil)
	if err != nil {
		t.Errorf("client: error making http request: %s\n", err)
	}
	httpClient := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t)
	res, err := httpClient.Do(httpReq)
	if err != nil {
		t.Errorf("client: error making http request: %s\n", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("Unexpected response: %v", res)
	}
	popLastRequestByTestProxy()
}

func assertHttpRequestOK(tb testing.TB, resp *http.Response) {
	if resp.StatusCode != http.StatusOK {
		tb.Errorf("Should have gotten succesful request")
	}
}

//When you go through a proxy it might add some headers
//This will mess up the signature when they are considered in the signing
//process
func TestWithValidCredsButProxyHeaders(t *testing.T) {
	teardownSuite, s := setupSuiteProxyS3(t, testStubJustProxy, nil, nil, nil, true)
	defer teardownSuite(t)

	//Given headers that are added by a proxy component
	proxyHeaderAdder := createHeaderAdder(map[string]string {
		"accept-encoding": "gzip",
		"x-forwarded-for": "",
		"x-forwarded-host": "",
		"x-forwarded-port": "443",
		"x-forwarded-proto": "https",
		"x-forwarded-server": "",
		"x-real-ip": "",
	})

	//When doing a valid request where headers are added by an intermediate stop (post-signing)
	resp := performValidListObjectTestRequest(t, s, doNotAddAnyHeader, proxyHeaderAdder)

	//Then the result should be valid
	assertHttpRequestOK(t, resp)
}

//Create a function which adds headers to a http.Header object
func createHeaderAdder(headersToAdd map[string]string) (func (http.Header) ()) {
	var adder = func (header http.Header) {
		for headerName, headerValue := range headersToAdd {
			header.Add(headerName, headerValue)
		}
	}

	return adder
}

//helper to not manipulate headers
var doNotAddAnyHeader = createHeaderAdder(map[string]string{})

//When having other headers added that might influence the behavior
func TestWithValidCredsButUntrustedHeaders(t *testing.T) {
	teardownSuite, s := setupSuiteProxyS3(t, testStubJustProxy, nil, nil, nil, true)
	defer teardownSuite(t)

	//Given headers are added by a proxy component
	maliciousHeaderAdder := createHeaderAdder(map [string]string{"allYourBases": "belongToUs"})

	//When doing a valid request where headers are added by an intermediate stop
	resp := performValidListObjectTestRequest(t, s, doNotAddAnyHeader, maliciousHeaderAdder)

	//Then the result should be a bad request
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Should have gotten a bad signature ")
	}
}


func getTestUUID4WithPrefix(prefix string) string {
	fully_random := uuid.New().String()
	if prefix > fully_random {
		panic("Impossible to use a prefix longer than the actual uuid4")
	}
	return strings.Join([]string{prefix, fully_random[len(prefix):]}, "")
}

//Perform a valid ListObject request for testing and allow manipulation of headers using callbacks before (pre) and after (post) signing
//and return the response of the request
func performValidListObjectTestRequest(t testing.TB, s *S3Server, headerModifierPreSign func (http.Header) (), headerModifierPostSign func (http.Header) ()) (*http.Response) {
	ctx := context.Background()

	//Given valid credentials
	cred := createTestCredentialsForPolicy(t, testPolicyAllowAllARN, s.jwtKeyMaterial)

	awsCred, err := cred.Retrieve(ctx)
	if err != nil {
		t.Error(err)
	}

	//Given a valid request
	baseUrl := getS3ProxyUrl(t, s)
	bucketName := "my-test-bucket"
	queryPart := "list-type=2&prefix=&delimiter=%2F&encoding-type=url"
	requestUrl := fmt.Sprintf("%s%s?%s", baseUrl, bucketName, queryPart)
	req, err := http.NewRequest(http.MethodGet, requestUrl, nil)
	if err != nil {
		t.Errorf("Could not create request: %s", err)
	}
	req.Header.Add("User-Agent", "aws-cli/2.15.40 Python/3.11.8 Linux/6.8.0-40-generic exe/x86_64.ubuntu.12 prompt/off command/s3.ls")
	req.Header.Add("X-Amz-Content-SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	headerModifierPreSign(req.Header)

	err = presign.SignWithCreds(ctx, req, awsCred, testDefaultBackendRegion)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	headerModifierPostSign(req.Header)

	client := testutils.BuildUnsafeHttpClientThatTrustsAnyCert(t)
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Could not perform request: %s", err)
		t.FailNow()
	}
	return resp
}


//When having other headers added that might influence the behavior
func TestAllowEnablingTracingAtClientSide(t *testing.T) {
	//Given the provider of the S3 proxy has configured a prefix to force logging
	os.Setenv(logging.ENV_FORCE_LOGGING_FOR_REQUEST_ID_PREFIX, "00AABBCC")
	
	//Given a way to capture logs
	stopLogCapture, getLogLines := testutils.CaptureLogFixture(t, slog.LevelError, nil)
	defer stopLogCapture()

	//Given a uuid4 that starts with the prefix
	userChosenUuid4 := getTestUUID4WithPrefix("00aabbcc")

	//Given a test environment
	teardownSuite, s := setupSuiteProxyS3(t, testStubJustProxy, nil, nil, nil, true)
	defer teardownSuite(t)

	//Given helper function that adds the chosen UUID4 as the X-Request-ID header
	addUserChosenUUID4 := createHeaderAdder(map [string]string{requestctx.XRequestID: userChosenUuid4})

	//When performing a valid request but without picking a request id
	resp := performValidListObjectTestRequest(t, s, doNotAddAnyHeader, doNotAddAnyHeader)
	assertHttpRequestOK(t, resp)

	//Then limited logging should have happend.
	logLines := getLogLines()
	logLinesWithoutDebug := len(logLines)
	if strings.Contains(strings.Join(logLines, "\n"), "DEBUG") {
		t.Errorf("There should not be debug statements in the log if we do not use a special request ID")
	}

	//When performing a valid request but without picking a request id
	resp = performValidListObjectTestRequest(t, s, addUserChosenUUID4, doNotAddAnyHeader)
	assertHttpRequestOK(t, resp)
	logLines = getLogLines()

	//Then there should be more logging
	logLinesWithDebug := len(logLines)
	if logLinesWithDebug <= logLinesWithoutDebug {
		t.Errorf("Log length with debug %d must be bigger than log length without debug %d", logLinesWithDebug, logLinesWithoutDebug)
	}
	if !strings.Contains(strings.Join(logLines, "\n"), "DEBUG") {
		t.Errorf("There should be debug statements in the log if we do use a special request ID")
	}
}