package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/viper"
)

// https://stackoverflow.com/questions/23729790/how-can-i-do-test-setup-using-the-testing-package-in-go
func TestMain(m *testing.M) {
	envFiles = "../etc/.env"
	loadEnvVarsFromDotEnv()
	initConfig()
	initializeLogging()
	m.Run()
}

func getTestServerCreds(t *testing.T) aws.Credentials{
	creds, err := getBackendCredentials("waw3-1")
	if err != nil {
		t.Errorf("Could not get test credentials")
		t.FailNow()
	}
	return creds
}

func TestValidPreSignWithServerCreds(t *testing.T) {
	//Given valid server config
	BindEnvVariables("proxys3")
	//Pre-sign with server creds so must initialize backend config for testing
	if err := initializeGlobalBackendsConfig(); err != nil {
		t.Error(err) //Fail hard as no valid backends are configured
		t.FailNow()
	}

	//Given we have a valid signed URI valid for 1 second
	signedURI, err := PreSignRequestForGet("pvb-test", "onnx_dependencies_1.16.3.zip", testDefaultBackendRegion, time.Now(), 60)
	if err != nil {
		t.Errorf("could not presign request: %s\n", err)
	}
	//When we check the signature within 1 second
	isValid, err := presign.IsPresignedUrlWithValidSignature(context.Background(), signedURI, getTestServerCreds(t))
	//Then it is a valid signature
	if err != nil {
		t.Errorf("Url should have been valid but %s", err)
	}
	if !isValid {
		t.Errorf("Url was not valid")
	}
}

func getMainS3ProxyFQDNForTest(t *testing.T) string {
	mainS3ProxyFQDN, err := getMainS3ProxyFQDN()
	if err != nil {
		t.Errorf("COuld not get Main S3 Proxy FQDN: %s", err)
		t.FailNow()
	}
	return mainS3ProxyFQDN
}

func TestValidPreSignWithTempCreds(t *testing.T) {
	//Given valid server config
	BindEnvVariables("proxys3")

	accessKeyId := "myAccessKeyId"
	key, err := getSigningKey()
	if err != nil {
		t.Error("Could not get signing key")
		t.FailNow()
	}
	creds := aws.Credentials{
		AccessKeyID: "myAccessKeyId",
		SecretAccessKey: CalculateSecretKey(accessKeyId, key),
		SessionToken: "Incredibly secure",
	}

	//Given we have a valid signed URI valid for 1 second
	url := fmt.Sprintf("https://%s:%d/%s/%s", getMainS3ProxyFQDNForTest(t), viper.GetInt(s3ProxyPort), "bucket", "key")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Errorf("error when creating a request context for url: %s", err)
	}

	uri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 100, time.Now(), creds, testDefaultBackendRegion)
	if err != nil {
		t.Errorf("error when signing request with creds: %s", err)
	}
	

	//When we check the signature within 1 second
	isValid, err := presign.IsPresignedUrlWithValidSignature(context.Background(), uri, creds)
	//Then it is a valid signature
	if err != nil {
		t.Errorf("Url should have been valid but %s", err)
	}
	if !isValid {
		t.Errorf("Url was not valid")
	}
}

func TestExpiredPreSign(t *testing.T) {
	//Given valid server config
	BindEnvVariables("proxys3")
	//Pre-sign with server creds so must initialize backend config for testing
	if err := initializeGlobalBackendsConfig(); err != nil {
		t.Error(err) //Fail hard as no valid backends are configured
		t.FailNow()
	}
	//Given we have a valid signed URI valid for 1 second
	signedURI, err := PreSignRequestForGet("pvb-test", "onnx_dependencies_1.16.3.zip", testDefaultBackendRegion, time.Now(), 1)
	if err != nil {
		t.Errorf("could not presign request: %s\n", err)
	}
	//When we would check the url after 1 second
	time.Sleep(1 * time.Second)
	isValid, err := presign.IsPresignedUrlWithValidSignature(context.Background(), signedURI, getTestServerCreds(t))
	//Then it is no longer a valid signature TODO check
	if err != nil {
		t.Errorf("Url should have been valid but %s", err)
	}
	if !isValid {
		t.Errorf("Url was not valid")
	}
}

var testRequests = []*http.Request{}

var testProxyStub = func (ctx context.Context, w http.ResponseWriter, r *http.Request, backendId string)  {
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
var testStubJustProxy handlerBuilderI = handlerBuilder{proxyFunc: testProxyStub}


func setupSuiteProxyS3(t *testing.T, handlerBuilder handlerBuilderI) (func(t *testing.T)) {
	// Have test Config
	BindEnvVariables(proxys3)
	// Make sure proxy key config is there 
	err := initializeS3ProxyKeyFunc(viper.GetString(s3ProxyJwtPublicRSAKey))
	if err != nil {
		t.Errorf("Failed to S3 proxy key function config due to %s", err)
		t.FailNow()
	}

	s3ProxyDone, s3ProxySrv, err := createAndStartS3Proxy(handlerBuilder)
	if err != nil {
		t.Errorf("Could not spawn fake S3 server %s", err)
		t.FailNow()
	}

	// Return a function to teardown the test
	return func(t *testing.T) {
		if err := s3ProxySrv.Shutdown(context.Background()); err != nil {
			panic(err)
		}
		// wait for goroutines started in startHttpServer() to stop
		s3ProxyDone.Wait()
	}
}

//Get the fully qualified URL to the S3 Proxy
func getS3ProxyUrl() string {
	return fmt.Sprintf("%s:%d/", getProxyUrlWithoutPort(), viper.GetInt(s3ProxyPort))
}


func adapterCredentialsToCredentialsProvider(creds aws.Credentials) aws.CredentialsProviderFunc {
	return func(ctx context.Context) (aws.Credentials, error) {
		return creds, nil
	}
}

func adapterAwsCredentialsToCredentials(creds AWSCredentials) aws.Credentials {
	return aws.Credentials{
		AccessKeyID: creds.AccessKey,
		SecretAccessKey: creds.SecretKey,
		SessionToken: creds.SessionToken,
	}
}


func getS3ClientAgainstS3Proxy(t *testing.T, region string, creds aws.Credentials) (*s3.Client) {
	cfg := getTestAwsConfig(t)

	client := s3.NewFromConfig(cfg, func (o *s3.Options) {
		o.BaseEndpoint = aws.String(getS3ProxyUrl())
		o.Credentials = adapterCredentialsToCredentialsProvider(creds)
		o.Region = region
		o.UsePathStyle = true
	})

	return client
}

func TestWithValidCredsButNoAccess(t *testing.T) {
	teardownSuite := setupSuiteProxyS3(t, testStubJustProxy)
	defer teardownSuite(t)

	token := CreateTestingTokenWithNoAccess()
	cred, err := NewAWSCredentials(token, time.Hour)
	if err != nil {
		t.Error(err)
	}

	client := getS3ClientAgainstS3Proxy(t, "eu-west-1", adapterAwsCredentialsToCredentials(*cred))
	
	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	testPrefix := testAllowedPrefix
	input := s3.ListObjectsV2Input{
		Bucket: &testBucketName,
		Prefix: &testPrefix,
	}
	defer cancel()
	_, err = client.ListObjectsV2(max1Sec, &input)
	if err == nil {
		t.Errorf("encountered no error when trying to do list bucket request")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("Did not get Access Denied, got %s", err.Error())
	}
	popLastRequestByTestProxy()
}

func TestWithValidCreds(t *testing.T) {
	teardownSuite := setupSuiteProxyS3(t, testStubJustProxy)
	defer teardownSuite(t)

	token := CreateTestingToken()
	cred, err := NewAWSCredentials(token, time.Hour)
	if err != nil {
		t.Error(err)
	}

	cfg := getTestAwsConfig(t)

	client := s3.NewFromConfig(cfg, func (o *s3.Options) {
		o.BaseEndpoint = aws.String(getS3ProxyUrl())
		o.Credentials = cred
		o.Region = "eu-west-1"
		o.UsePathStyle = true
	})
	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	testPrefix := testAllowedPrefix
	input := s3.ListObjectsV2Input{
		Bucket: &testBucketName,
		Prefix: &testPrefix,
	}
	defer cancel()
	_, err = client.ListObjectsV2(max1Sec, &input)
	if err != nil {
		t.Errorf("encountered error when trying to do list bucket request: %s", err)
	}
	popLastRequestByTestProxy()
}

func TestWithInValidCreds(t *testing.T) {
	teardownSuite := setupSuiteProxyS3(t, testStubJustProxy)
	defer teardownSuite(t)

	token := CreateTestingToken()
	cred, err := NewAWSCredentials(token, time.Hour)
	cred.AccessKey = "OverwriteToInvalidValue"
	if err != nil {
		t.Error(err)
	}

	cfg := getTestAwsConfig(t)

	client := s3.NewFromConfig(cfg, func (o *s3.Options) {
		o.BaseEndpoint = aws.String(getS3ProxyUrl())
		o.Credentials = cred
	})
	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	input := s3.ListBucketsInput{}
	defer cancel()
	_, err = client.ListBuckets(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
}

func TestWithValidCredsOtherRegion(t *testing.T) {
	teardownSuite := setupSuiteProxyS3(t, testStubJustProxy)
	defer teardownSuite(t)

	token := CreateTestingToken()
	cred, err := NewAWSCredentials(token, time.Hour)
	if err != nil {
		t.Error(err)
	}

	cfg := getTestAwsConfig(t)

	client := s3.NewFromConfig(cfg, func (o *s3.Options) {
		o.BaseEndpoint = aws.String(getS3ProxyUrl())
		o.Credentials = cred
		o.Region = "us-east-1"
	})
	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	input := s3.ListBucketsInput{}
	defer cancel()
	_, err = client.ListBuckets(max1Sec, &input)
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
	teardownSuite := setupSuiteProxyS3(t, testStubJustProxy)
	defer teardownSuite(t)

	token := CreateTestingToken()
	cred, err := NewAWSCredentials(token, time.Hour)
	if err != nil {
		t.Error(err)
	}


	cfg := getTestAwsConfig(t)

	client := s3.NewFromConfig(cfg, func (o *s3.Options) {
		o.BaseEndpoint = aws.String(getS3ProxyUrl())
		o.Credentials = cred
		o.Region = "eu-central-1"
		o.UsePathStyle = true
	})

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
	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Errorf("client: error making http request: %s\n", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("Unexpected response: %v", res)
	}
	popLastRequestByTestProxy()
}

//When you go through a proxy it might add some headers
//This will mess up the signature when they are considered in the signing
//process
func TestWithValidCredsButProxyHeaders(t *testing.T) {
	teardownSuite := setupSuiteProxyS3(t, testStubJustProxy)
	defer teardownSuite(t)

	ctx := context.Background()
	//Given valid credentials
	token := CreateTestingToken()
	cred, err := NewAWSCredentials(token, time.Hour)
	if err != nil {
		t.Error(err)
	}
	awsCred, err := cred.Retrieve(ctx)
	if err != nil {
		t.Error(err)
	}

	//Given a valid request
	baseUrl := getS3ProxyUrl()
	bucketName := "my-test-bucket"
	queryPart := "list-type=2&prefix=&delimiter=%2F&encoding-type=url"
	requestUrl := fmt.Sprintf("%s%s?%s", baseUrl, bucketName, queryPart)
	req, err := http.NewRequest(http.MethodGet, requestUrl, nil)
	if err != nil {
		t.Errorf("Could not create request: %s", err)
	}
	req.Header.Add("User-Agent", "aws-cli/2.15.40 Python/3.11.8 Linux/6.8.0-40-generic exe/x86_64.ubuntu.12 prompt/off command/s3.ls")
	req.Header.Add("X-Amz-Content-SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	ctx = buildContextWithRequestID(req)
	err = presign.SignWithCreds(ctx, req, awsCred, testDefaultBackendRegion)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	//Given headers are headed by a proxy component
	req.Header.Add("accept-encoding", "gzip")
	req.Header.Add("x-forwarded-for", "")
	req.Header.Add("x-forwarded-host", "")
	req.Header.Add("x-forwarded-port", "443")
	req.Header.Add("x-forwarded-proto", "https")
	req.Header.Add("x-forwarded-server", "")
	req.Header.Add("x-real-ip", "")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Could not perform request: %s", err)
	}
	defer resp.Body.Close()


	if resp.StatusCode != http.StatusOK {
		t.Errorf("Should have gotten an OK ")
	}
}

//When having other headers added that might influence the behavior
func TestWithValidCredsButUntrustedHeaders(t *testing.T) {
	teardownSuite := setupSuiteProxyS3(t, testStubJustProxy)
	defer teardownSuite(t)

	ctx := context.Background()
	//Given valid credentials
	token := CreateTestingToken()
	cred, err := NewAWSCredentials(token, time.Hour)
	if err != nil {
		t.Error(err)
	}
	awsCred, err := cred.Retrieve(ctx)
	if err != nil {
		t.Error(err)
	}

	//Given a valid request
	baseUrl := getS3ProxyUrl()
	bucketName := "my-test-bucket"
	queryPart := "list-type=2&prefix=&delimiter=%2F&encoding-type=url"
	requestUrl := fmt.Sprintf("%s%s?%s", baseUrl, bucketName, queryPart)
	req, err := http.NewRequest(http.MethodGet, requestUrl, nil)
	if err != nil {
		t.Errorf("Could not create request: %s", err)
	}
	req.Header.Add("User-Agent", "aws-cli/2.15.40 Python/3.11.8 Linux/6.8.0-40-generic exe/x86_64.ubuntu.12 prompt/off command/s3.ls")
	req.Header.Add("X-Amz-Content-SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	ctx = buildContextWithRequestID(req)
	err = presign.SignWithCreds(ctx, req, awsCred, testDefaultBackendRegion)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	//Given headers are headed by a proxy component
	req.Header.Add("allYourBases", "belongToUs")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Could not perform request: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Should have gotten a bad signature ")
	}
}