package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/spf13/viper"
)


const testRegion1 = "tst-1"
const testRegion2 = "eu-test-2"
var defaultBakendIdAlmostE2ETests = testRegion2
var backendTestRegions = []string{testRegion1, testRegion2}
var testingBucketNameBackenddetails = "backenddetails"
var testingRegionTxtObjectKey = "region.txt"

var testingBackendsConfig = []byte(fmt.Sprintf(`
# This is a test file check backend-config.yaml if you want to create a configuration
s3backends:
  - region: %s
    credentials:
      file: ../etc/creds/cfc_creds.yaml
    endpoint: http://localhost:5000
  - region: %s
    credentials:
      file: ../etc/creds/otc_creds.yaml
    endpoint: http://localhost:5001
default:  %s
`, testRegion1, testRegion2, defaultBakendIdAlmostE2ETests))


//Set the configurations as expected for the testingbackends
//See testing/README.md for details on testing setup
func setTestingBackendsConfig(t *testing.T) {
	cfg, err :=  getBackendsConfigFromBytes(testingBackendsConfig)
  if err != nil {
    t.Error(err)
    t.FailNow()
  }
  globalBackendsConfig = cfg
}

//This is the testing fixture. It starts an sts and s3 proxy which
//are configured with the S3 backends detailed in testing/README.md.
func testingFixture(t *testing.T) (tearDown func ()(), getToken func(subject string, d time.Duration, tags AWSSessionTags) string){
  //Configure backends to be the testing S3 backends
  setTestingBackendsConfig(t)
	//Given valid server config
  teardownSuiteSTS := setupSuiteProxySTS(t)
  teardownSuiteS3 := setupSuiteProxyS3(t, justProxied)

  //function to stop the setup of the fixture
  tearDownProxies := func () {
    teardownSuiteSTS(t)
    teardownSuiteS3(t)
  }

  _, err := loadOidcConfig([]byte(testConfigFakeTesting))
	if err != nil {
		t.Error(err)
	}
	
	signingKey, err := getTestSigningKey()
	if err != nil {
		t.Error("Could not get test signing key")
		t.FailNow()
	}

  //function to get a valid token that can be exchanged for credentials
  getSignedToken := func(subject string, d time.Duration, tags AWSSessionTags) string {
    token, err := CreateSignedToken(createRS256PolicyTokenWithSessionTags(testFakeIssuer, subject, d, tags), signingKey)
    if err != nil {
      t.Errorf("Could create signed token with subject %s and tags %v: %s", subject, tags, err)
      t.FailNow()
    }
    return token
  }
	

  return tearDownProxies, getSignedToken
}

func getCredentialsFromTestStsProxy(t *testing.T, token, sessionName, roleArn string) aws.Credentials {
	result, err := assumeRoleWithWebIdentityAgainstTestStsProxy(t, token, sessionName, roleArn)
	if err != nil {
		t.Errorf("encountered error when assuming role: %s", err)
	}
  creds := result.Credentials
  awsCreds := aws.Credentials{
    AccessKeyID: *creds.AccessKeyId,
    SecretAccessKey: *creds.SecretAccessKey,
    SessionToken: *creds.SessionToken,
    Expires: *creds.Expiration,
    CanExpire: true,
  }
  return awsCreds
}

//region object is setup in the backends and matches the region name of the backend
func getRegionObjectContent(t *testing.T, region string, creds aws.Credentials) (string, smithy.APIError){
  client := getS3ClientAgainstS3Proxy(t, region, creds)
	
	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)

	input := s3.GetObjectInput{
		Bucket: &testingBucketNameBackenddetails,
    Key: &testingRegionTxtObjectKey,
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


//Backend selection is done by chosing a region. The enpdoint we use is fixed
//to our testing S3Proxy and therefore the hostname is the same. In each backend
//we have a bucket with the same name and region.txt which holds the actual region
//name which we can use to validate that our request went to the right backend.
func TestMakeSureCorrectBackendIsSelected(t *testing.T) {
  tearDown, getSignedToken := testingFixture(t)
  defer tearDown()
  token := getSignedToken("mySubject", time.Minute * 20, AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
  //Given the policy Manager that has roleArn for the testARN
	pm = *NewTestPolicyManagerAllowAll()
  //Given credentials for that role
  creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN)


  for _, backendRegion := range backendTestRegions {
    regionContent, err := getRegionObjectContent(t, backendRegion, creds)
    if err != nil {
      t.Errorf("Could not get region content due to error %s", err)
    } else if regionContent != backendRegion {
      t.Errorf("when retrieving region file for %s we got %s", backendRegion, regionContent)
    }
  }
}

//When requests are made with an invalid region generally it is expected to have the requests fail.
//for the legacy implementation only supporting a single backend that was not the case and the region
//information was ignored. It is recommended to discourage usage of wrong regions by region out to users
//who are using an invalid region. But to allow for a grace period where not breaking old usages you can also
//ENABLE_LEGACY_BEHAVIOR_INVALID_REGION_TO_DEFAULT_REGION
func TestAllowFallbackToDefaultBackend(t *testing.T) {
  //Given legacy behavior mode enabled
  viper.Set(enableLegacyBehaviorInvalidRegionToDefaultRegion, true)
  
  tearDown, getSignedToken := testingFixture(t)
  defer tearDown()
  token := getSignedToken("mySubject", time.Minute * 20, AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
  //Given the policy Manager that has roleArn for the testARN
	pm = *NewTestPolicyManagerAllowAll()
  //Given credentials for that role
  creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN)

  // When a request is done to an invalid region
  regionContent, err := getRegionObjectContent(t, "invalidRegion", creds)
  // The response is as if the request was set to the default region
  if err != nil {
    t.Errorf("Could not get region content due to error %s", err)
  } else if regionContent != defaultBakendIdAlmostE2ETests {
    t.Errorf("when retrieving region file for %s we got %s but expected %s", "invalidRegion", regionContent, testDefaultBackendRegion)
  }
}

//When not allowing fallback an invalid region should have clear indication that it is a user err
func TestIfNoFallbackToDefaultBackendBadRequestShouldBeReturned(t *testing.T) {
  //Given legacy behavior mode enabled
  viper.Set(enableLegacyBehaviorInvalidRegionToDefaultRegion, false)
  
  tearDown, getSignedToken := testingFixture(t)
  defer tearDown()
  token := getSignedToken("mySubject", time.Minute * 20, AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
  //Given the policy Manager that has roleArn for the testARN
	pm = *NewTestPolicyManagerAllowAll()
  //Given credentials for that role
  creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN)

  // When a request is done to an invalid region
  regionContent, err := getRegionObjectContent(t, "invalidRegion", creds)
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
  tearDown, getSignedToken := testingFixture(t)
  defer tearDown()
  token := getSignedToken("mySubject", time.Minute * 20, AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	pm = *NewTestPolicyManagerAllowAll()
  creds := getCredentialsFromTestStsProxy(t, token, "my-session", testPolicyAllowAllARN)

  //Given a Get request for the region.txt file
  regionFileUrl := fmt.Sprintf("%s%s/%s", getS3ProxyUrl(), testingBucketNameBackenddetails, testingRegionTxtObjectKey)
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
    resp, err := http.Get(signedUri)
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