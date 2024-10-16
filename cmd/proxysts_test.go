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

func TestProxyStsViaSTSClient(t *testing.T) {
	teardownSuite := setupSuiteProxySTS(t)
	defer teardownSuite(t)

	cfg := getTestAwsConfig(t)
	secure := viper.GetBool(secure)
	var protocol string
	if secure {
		protocol = "https"
	} else {
		protocol = "http"
	}

	client := sts.NewFromConfig(cfg, func (o *sts.Options) {
		o.BaseEndpoint = aws.String(
			fmt.Sprintf("%s://%s:%d/", protocol, viper.GetString(stsProxyFQDN), viper.GetInt(stsProxyPort)),
		)
	})

	token := getTestingToken(t)
	//Given the policy Manager that has roleArn for the testARN
	initializePolicyManager()
	roleSessionName := "my-session"
	var arnToAssume string = testARN

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleSessionName: &roleSessionName,
		WebIdentityToken: &token,
		RoleArn: &arnToAssume,
	}

	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	defer cancel()
	_, err := client.AssumeRoleWithWebIdentity(
		max1Sec, input,
	)
	if err != nil {
		t.Errorf("encountered error when assuming role: %s", err)
	}
}