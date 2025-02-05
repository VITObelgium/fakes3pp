package sts

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/VITObelgium/fakes3pp/testutils"
	"github.com/VITObelgium/fakes3pp/utils"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testStsEndpoint = "https://localstshost:8444/"
var testEtcPath = "../../../etc"

var testFakeIssuer string = "https://localhost/auth/realms/testing"
var testProviderFakeTesting string = fmt.Sprintf(`
  testing:
    realm: testing
    public_key: "MIIBCgKCAQEAoncey4tgLAI2zZj6CGZTCnhOW9hxtv+QJ/1qDTqYKyZecSahk4a9duUVRUT0wZUZRZgba/mYZg/9ypuz4C/elf2iMgnHRmBCJmQy1eQGa+RirzmnDpFeo/1bCeWLXd4gg+HT5NFoJKl79O1ZX9TXa9mExZsK7/+1WoZeWH0u9YP50+ULMmeFReAH9SzytJVx8fD2Ir1dEsrQFM5dYPP1liYFidUwD5Q5STHqAEoOkOPMhduUjyGRLEy66sPM1o9Iw3GcN1IdPVKVEkuX9QcM/AJCVtSbES5MDYqysJXAeF3a0ucHMwE9ND+mqPZD9tUQ9zbw0dULdCyI0zac/c6HEwIDAQAB"
    token-service: https://localhost/auth/realms/testing/protocol/openid-connect
    account-service: https://localhost/auth/realms/testing/account
    tokens-not-before: 0
    iss: %s`, testFakeIssuer)

var testOIDCConfigFakeTesting string = fmt.Sprintf("providers:%s", testProviderFakeTesting)



var testSTSFQDN = "localhost"
var testSTSPort = 8444

func NewTestSTSServer(t testing.TB, pm *iam.PolicyManager, maxDurationSeconds int, oidcConfig string, isTlsEnabled bool) (*STSServer) {
	tlsCert := ""
	tlsKey := ""

	if isTlsEnabled{
		tlsCert = fmt.Sprintf("%s/cert.pem", testEtcPath)
		tlsKey = fmt.Sprintf("%s/key.pem", testEtcPath)
	}

	var jwtTestToken = fmt.Sprintf("%s/jwt_testing_rsa", testEtcPath)
	s, err:= newSTSServer(
		jwtTestToken,
		testSTSPort,
		[]string{testSTSFQDN},
		tlsCert,
		tlsKey,
		testutils.TempYamlFile(t, oidcConfig),
		pm,
		maxDurationSeconds,
	)
	if err != nil {
		t.Error("Problem creating test STS server", "error", err)
		t.FailNow()
	}
	return s
}

func buildAssumeRoleWithIdentityTokenUrl(duration int, roleSessionName, roleArn, token string) (string) {
	return fmt.Sprintf(
		"%s?Action=AssumeRoleWithWebIdentity&DurationSeconds=%d&RoleSessionName=%s&RoleArn=%s&WebIdentityToken=%s&Version=2011-06-15", 
		testStsEndpoint, duration, roleSessionName, roleArn, token,
	)
}

var testPolicyArnForTestPM = "arn:aws:iam::000000000000:role/S3Access"
func getNewTestPM(t testing.TB) (*iam.PolicyManager) {
	pm, err := iam.NewPolicyManagerForLocalPolicies(fmt.Sprintf("%s/policies", testEtcPath))
	if err != nil {
		t.Error("Could not get testing Policy Manager)", "error", err)
		t.FailNow()
	}
	return pm
}

func getWebIdentityTestingToken(t testing.TB, keyStorage utils.PrivateKeyKeeper, d time.Duration, tags *session.AWSSessionTags) string{
	token, err := CreateSignedOIDCTestingToken(keyStorage, d, tags)
	if err != nil {
		t.Errorf("Could not create a testing token %s", err)
		t.Fail()
	}
	return token
}

//Create a signed OIDC testing TOken
func CreateSignedOIDCTestingToken(keyStorage utils.PrivateKeyKeeper, d time.Duration, tags *session.AWSSessionTags) (string, error) {
	if tags == nil {
		tags = &session.AWSSessionTags{}
	}
	oidc_token := jwt.NewWithClaims(jwt.SigningMethodRS256, credentials.NewIDPClaims(
		testFakeIssuer,
		"test-user",
		d,
		*tags,
	))

	return credentials.CreateSignedToken(oidc_token, keyStorage)
}

func TestProxySts(t *testing.T) {
	//Given the policy Manager that has roleArn for the testARN
	pm := getNewTestPM(t)

	//Given valid server config
	s := NewTestSTSServer(t, pm, 3600, testOIDCConfigFakeTesting, true)

	//Given a valid testing token
	token := getWebIdentityTestingToken(t, s.jwtKeyMaterial, 10 * time.Minute, nil)

	//When an assume role with WebIdentity request is done
	url := buildAssumeRoleWithIdentityTokenUrl(901, "mysession", testPolicyArnForTestPM, token)
	req, err := http.NewRequest("POST", url, nil)

    if err != nil {
        t.Fatal(err)
    }
	rr := httptest.NewRecorder()
	s.processSTSPost(rr, req)
	//Then the result must be OK
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
	//Given the policy Manager that has roleArn for the testARN
	pm := getNewTestPM(t)

	//Given valid server config
	s := NewTestSTSServer(t, pm, 3600, testOIDCConfigFakeTesting, true)

	//Given a valid testing token
	token, err := credentials.CreateSignedToken(
		createBasicRS256PolicyToken(testFakeIssuer, "test-user", time.Minute), 
		s.jwtKeyMaterial,
	)
	if err != nil {
		t.Error("Could not create valid testing token", "error", err)
		t.FailNow()
	}

	url := buildAssumeRoleWithIdentityTokenUrl(901, "mysession", testPolicyArnForTestPM, token)
	req, err := http.NewRequest("POST", url, nil)

    if err != nil {
        t.Fatal(err)
    }
	rr := httptest.NewRecorder()
	s.processSTSPost(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Errorf("Could not assume role with testing token: %v", rr)
	}
}

var testSessionTagsCustomIdA = session.AWSSessionTags{
	PrincipalTags: map[string][]string{
		"custom_id": {"idA"},
	},
	TransitiveTagKeys: []string{"custom_id"},
}

//Test the most basic web identity token which only has the subject
func TestProxyStsAssumeRoleWithWebIdentitySessionTagsToken(t *testing.T) {
	//Given the policy Manager that has roleArn for the testARN
	pm := getNewTestPM(t)

	//Given valid server config
	s := NewTestSTSServer(t, pm, 3600, testOIDCConfigFakeTesting, true)

	//Given a valid testing token
	token := getWebIdentityTestingToken(t, s.jwtKeyMaterial, 20* time.Minute, &testSessionTagsCustomIdA)

	url := buildAssumeRoleWithIdentityTokenUrl(901, "mysession", testPolicyArnForTestPM, token)
	req, err := http.NewRequest("POST", url, nil)

    if err != nil {
        t.Fatal(err)
    }
	rr := httptest.NewRecorder()
	s.processSTSPost(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Errorf("Could not assume role with testing token: %v", rr)
	}
}


// This works like a fixture see https://medium.com/nerd-for-tech/setup-and-teardown-unit-test-in-go-bd6fa1b785cd
func setupSuiteProxySTS(t testing.TB, pm *iam.PolicyManager, oidcConfig string, tlsEnabled bool) (func(t testing.TB), *STSServer) {
	s := NewTestSTSServer(t, pm, 3600, oidcConfig, tlsEnabled)
	stsProxyDone, stsProxySrv, err := server.CreateAndStart(s)
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

func TestProxyStsViaSTSClient(t *testing.T) {
	for _, tlsEnabled := range []bool{true, false} {
		func() { // Make it easy to use defer for the teardown
			teardownSuite, s := setupSuiteProxySTS(t, getNewTestPM(t), testOIDCConfigFakeTesting, tlsEnabled)
			defer teardownSuite(t)
		
			token := getWebIdentityTestingToken(t, s.jwtKeyMaterial, 20*time.Minute, nil)
		
			_, err := testutils.AssumeRoleWithWebIdentityAgainstTestStsProxy(t, token, "my-session", testPolicyArnForTestPM, s)
			if err != nil {
				t.Errorf("encountered error when assuming role: %s", err)
			}
		}()
	}
}