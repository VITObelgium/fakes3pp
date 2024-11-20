package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

const testStsEndpoint = "https://localstshost:8444/"

func buildAssumeRoleWithIdentityTokenUrl(duration int, roleSessionName, roleArn, token string) (string) {
	return fmt.Sprintf(
		"%s?Action=AssumeRoleWithWebIdentity&DurationSeconds=%d&RoleSessionName=%s&RoleArn=%s&WebIdentityToken=%s&Version=2011-06-15", 
		testStsEndpoint, duration, roleSessionName, roleArn, token,
	)
}

func getTestingToken(t *testing.T) string{
	token, err := CreateSignedTestingToken()
	if err != nil {
		t.Errorf("Could not create a testing token %s", err)
		t.Fail()
	}
	return token
}

func TestProxySts(t *testing.T) {
	//Given valid server config
	BindEnvVariables("proxysts")
	_, err := loadOidcConfig([]byte(testConfigFakeTesting))
	if err != nil {
		t.Error(err)
	}

	token := getTestingToken(t)
	//Given the policy Manager that has roleArn for the testARN
	initializePolicyManager()

	url := buildAssumeRoleWithIdentityTokenUrl(901, "mysession", testARN, token)
	req, err := http.NewRequest("POST", url, nil)

    if err != nil {
        t.Fatal(err)
    }
	rr := httptest.NewRecorder()
	processSTSPost(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Errorf("Could not assume role with testing token: %v", rr)
	}
}

func createBasicRS256PolicyToken(issuer, subject string, expiry time.Duration) (*jwt.Token) {
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiry)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
		Issuer:    issuer,
		Subject:   subject,
		ID:        uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token
}

//Test the most basic web identity token which only has the subject
func TestProxyStsAssumeRoleWithWebIdentityBasicToken(t *testing.T) {
	//Given valid server config
	BindEnvVariables("proxysts")
	_, err := loadOidcConfig([]byte(testConfigFakeTesting))
	if err != nil {
		t.Error(err)
	}
	
	signingKey, err := getTestSigningKey()
	if err != nil {
		t.Error("Could not get test signing key")
		t.FailNow()
	}
	token, err := CreateSignedToken(createBasicRS256PolicyToken(testFakeIssuer, testSubject, 20 * time.Minute), signingKey)
	if err != nil {
		t.Error("Could create signed token")
		t.FailNow()
	}

	//Given the policy Manager that has roleArn for the testARN
	pm = *NewTestPolicyManagerAllowAll()


	url := buildAssumeRoleWithIdentityTokenUrl(901, "mysession", testPolicyAllowAllARN, token)
	req, err := http.NewRequest("POST", url, nil)

    if err != nil {
        t.Fatal(err)
    }
	rr := httptest.NewRecorder()
	processSTSPost(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Errorf("Could not assume role with testing token: %v", rr)
	}
}

var testSessionTagsCustomIdA = AWSSessionTags{
	PrincipalTags: map[string][]string{
		"custom_id": {"idA"},
	},
	TransitiveTagKeys: []string{"custom_id"},
}

func createRS256PolicyTokenWithSessionTags(issuer, subject string, expiry time.Duration, tags AWSSessionTags) (*jwt.Token) { 
	claims := newIDPClaims(issuer, subject, expiry, tags)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token
}

//Test the most basic web identity token which only has the subject
func TestProxyStsAssumeRoleWithWebIdentitySessionTagsToken(t *testing.T) {
	//Given valid server config
	BindEnvVariables("proxysts")
	_, err := loadOidcConfig([]byte(testConfigFakeTesting))
	if err != nil {
		t.Error(err)
	}
	
	signingKey, err := getTestSigningKey()
	if err != nil {
		t.Error("Could not get test signing key")
		t.FailNow()
	}
	token, err := CreateSignedToken(createRS256PolicyTokenWithSessionTags(testFakeIssuer, testSubject, 20 * time.Minute, testSessionTagsCustomIdA), signingKey)
	if err != nil {
		t.Error("Could create signed token")
		t.FailNow()
	}

	//Given the policy Manager that has roleArn for the testARN
	pm = *NewTestPolicyManagerAllowAll()


	url := buildAssumeRoleWithIdentityTokenUrl(901, "mysession", testPolicyAllowAllARN, token)
	req, err := http.NewRequest("POST", url, nil)

    if err != nil {
        t.Fatal(err)
    }
	rr := httptest.NewRecorder()
	processSTSPost(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Errorf("Could not assume role with testing token: %v", rr)
	}
}


// This works like a fixture see https://medium.com/nerd-for-tech/setup-and-teardown-unit-test-in-go-bd6fa1b785cd
func setupSuiteProxySTS(t *testing.T) func(t *testing.T) {
	// Make sure OIDC config is for testing 
	_, err := loadOidcConfig([]byte(testConfigAll))
	if err != nil {
		t.Errorf("Failed to load OIDC config due to %s", err)
		t.Fail()
	}
	// Have test Config
	BindEnvVariables(proxysts)
	stsProxyDone, stsProxySrv, err := createAndStartStsProxy()
	if err != nil {
		t.Errorf("Could not spawn fake STS server %s", err)
	}

	// Return a function to teardown the test
	return func(t *testing.T) {
		if err := stsProxySrv.Shutdown(context.Background()); err != nil {
			panic(err)
		}
		// wait for goroutines started in startHttpServer() to stop
		stsProxyDone.Wait()
	}
}

//Just get basic config but disable TLS verification
//As for tests we use self-signed requests and all is
//on localhost anyway
func getTestAwsConfig(t *testing.T) (aws.Config) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Error(err)
	}
	//https://github.com/aws/aws-sdk-go/issues/2404
	tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
	httpClient := &http.Client{Transport: tr}
	cfg.HTTPClient = httpClient
	return cfg
}

func getProxyUrlWithoutPort() string {
	secure := viper.GetBool(secure)
	var protocol string
	if secure {
		protocol = "https"
	} else {
		protocol = "http"
	}
	return fmt.Sprintf("%s://%s", protocol, viper.GetString(stsProxyFQDN))
}

func getStsProxyUrl() string {
	return fmt.Sprintf("%s:%d/", getProxyUrlWithoutPort(), viper.GetInt(stsProxyPort))
}

func assumeRoleWithWebIdentityAgainstTestStsProxy(t *testing.T, token, roleSessionName, roleArn string) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	cfg := getTestAwsConfig(t)


	client := sts.NewFromConfig(cfg, func (o *sts.Options) {
		o.BaseEndpoint = aws.String(getStsProxyUrl())
	})
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleSessionName: &roleSessionName,
		WebIdentityToken: &token,
		RoleArn: &roleArn,
	}

	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	defer cancel()
	result, err := client.AssumeRoleWithWebIdentity(
		max1Sec, input,
	)

	return result, err
}

func TestProxyStsViaSTSClient(t *testing.T) {
	teardownSuite := setupSuiteProxySTS(t)
	defer teardownSuite(t)

	token := getTestingToken(t)
	//Given the policy Manager that has roleArn for the testARN
	initializePolicyManager()

	_, err := assumeRoleWithWebIdentityAgainstTestStsProxy(t, token, "my-session", testARN)
	if err != nil {
		t.Errorf("encountered error when assuming role: %s", err)
	}
}