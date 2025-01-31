package cmd

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/golang-jwt/jwt/v5"
)

var testProviderCDSE string = `
  CDSE:
    realm: CDSE
    public_key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp6LwUL4v3SjzOdBYr4IxRRwsSJQ6lRvwS/7GiO77RO63+73Ne6htXmM6L/iDP1RLKT0N3rVp1oAnX/9HEd+s/xP7rXS6TmDG3mlSwQ/PKlILpqiatesaPo/tp/RUYyREjHeuUj/bzEVJUhC/rsjY5R1jwVlnSRAJ8VYTrwXiV7S87oxH+SL3XtuCpheGIm2QjJrVHGJ9kfanZouqKIk2MF54loCQ8EDxpQCEJFnY8l1+2qh7+6J1rRHromwgx0seUtbi+tQmVANkJrWOaMgJvORd4EDdouDa3nRy0BkLBQTJwZOXKhQKf0w2SchcZx2cy4iaMVa2O8o4lbIvrw++GwIDAQAB"
    token-service: https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect
    account-service: https://identity.dataspace.copernicus.eu/auth/realms/CDSE/account
    tokens-not-before: 0
    iss: https://identity.dataspace.copernicus.eu/auth/realms/CDSE`

var testEgiIssuer = "https://aai.egi.eu/auth/realms/egi"
var testProviderEgi string = fmt.Sprintf(`
  egi:
    iss: %s`, testEgiIssuer)

var testProviderEgiFull string = `
  egi:
    realm: egi
    public_key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqwhdua+/zTG5SDw/dFkW+OzYMh5e7e3+neeiZy/ajKVRCHGky4jSx5WjoVxfWvqt/JpGbCQ/Vk9x19UiRQlSBNmufJtVtrBHcXSrppTjABg20TVY+mRK2WJfdwK2YUc8xtNw1rCMOQQk0CC5j2AeUgwAY02WLaU0FYKmypJgfSQEeW1Cywl8OrkkYhcnEET7EwgemuEbqDY+pcqd3kIH++kwgjymUQ8CJgIgI3/zHLVrJsCxdADDP/zFFsTOnE205nMoBMTk10EcdTGAUBj3IosTn7HirVyQgiFL2stsjmxK3TeBli0YzVqlP0iuSA9FCPC4nqzRIDynjy70z2hZwIDAQAB"
    token-service: https://aai.egi.eu/auth/realms/egi/protocol/openid-connect
    account-service: https://aai.egi.eu/auth/realms/egi/account
    tokens-not-before: 0
    iss: https://aai.egi.eu/auth/realms/egi`


var testFakeIssuer string = "https://localhost/auth/realms/testing"

var testProviderFakeTesting string = fmt.Sprintf(`
  testing:
    realm: testing
    public_key: "MIIBCgKCAQEAoncey4tgLAI2zZj6CGZTCnhOW9hxtv+QJ/1qDTqYKyZecSahk4a9duUVRUT0wZUZRZgba/mYZg/9ypuz4C/elf2iMgnHRmBCJmQy1eQGa+RirzmnDpFeo/1bCeWLXd4gg+HT5NFoJKl79O1ZX9TXa9mExZsK7/+1WoZeWH0u9YP50+ULMmeFReAH9SzytJVx8fD2Ir1dEsrQFM5dYPP1liYFidUwD5Q5STHqAEoOkOPMhduUjyGRLEy66sPM1o9Iw3GcN1IdPVKVEkuX9QcM/AJCVtSbES5MDYqysJXAeF3a0ucHMwE9ND+mqPZD9tUQ9zbw0dULdCyI0zac/c6HEwIDAQAB"
    token-service: https://localhost/auth/realms/testing/protocol/openid-connect
    account-service: https://localhost/auth/realms/testing/account
    tokens-not-before: 0
    iss: %s`, testFakeIssuer)

var testConfigAll string = fmt.Sprintf("providers:%s\n%s\n%s", testProviderCDSE, testProviderEgi, testProviderFakeTesting)
var testConfigCDSE string = fmt.Sprintf("providers:%s", testProviderCDSE)
var testConfigEGI string = fmt.Sprintf("providers:%s", testProviderEgiFull)
var testConfigFakeTesting string = fmt.Sprintf("providers:%s", testProviderFakeTesting)


const (
	testCDSERealm string = "CDSE"
	testCDSEPublicKey string = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp6LwUL4v3SjzOdBYr4IxRRwsSJQ6lRvwS/7GiO77RO63+73Ne6htXmM6L/iDP1RLKT0N3rVp1oAnX/9HEd+s/xP7rXS6TmDG3mlSwQ/PKlILpqiatesaPo/tp/RUYyREjHeuUj/bzEVJUhC/rsjY5R1jwVlnSRAJ8VYTrwXiV7S87oxH+SL3XtuCpheGIm2QjJrVHGJ9kfanZouqKIk2MF54loCQ8EDxpQCEJFnY8l1+2qh7+6J1rRHromwgx0seUtbi+tQmVANkJrWOaMgJvORd4EDdouDa3nRy0BkLBQTJwZOXKhQKf0w2SchcZx2cy4iaMVa2O8o4lbIvrw++GwIDAQAB"
    testCDSETokenService string = "https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect" 
    testCDSEAccountService string = "https://identity.dataspace.copernicus.eu/auth/realms/CDSE/account"
    testCDSETokensNotBefore int = 0
	testEGIRealm string = "egi"
	testEGIPublicKey string = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqwhdua+/zTG5SDw/dFkW+OzYMh5e7e3+neeiZy/ajKVRCHGky4jSx5WjoVxfWvqt/JpGbCQ/Vk9x19UiRQlSBNmufJtVtrBHcXSrppTjABg20TVY+mRK2WJfdwK2YUc8xtNw1rCMOQQk0CC5j2AeUgwAY02WLaU0FYKmypJgfSQEeW1Cywl8OrkkYhcnEET7EwgemuEbqDY+pcqd3kIH++kwgjymUQ8CJgIgI3/zHLVrJsCxdADDP/zFFsTOnE205nMoBMTk10EcdTGAUBj3IosTn7HirVyQgiFL2stsjmxK3TeBli0YzVqlP0iuSA9FCPC4nqzRIDynjy70z2hZwIDAQAB"
    testEGITokenService string = "https://aai.egi.eu/auth/realms/egi/protocol/openid-connect"
    testEGIAccountService string = "https://aai.egi.eu/auth/realms/egi/account"
    testEGITokensNotBefore int = 0
)
var testCDSECfg *oidcProviderConfig = &oidcProviderConfig{
	Realm: testCDSERealm,
	PublicKey: testCDSEPublicKey,
	TokenService: testCDSETokenService,
	AccountService: testCDSEAccountService,
	TokensNotBefore: testCDSETokensNotBefore,
}
var testEGICfg *oidcProviderConfig = &oidcProviderConfig{
	Realm: testEGIRealm,
	PublicKey: testEGIPublicKey,
	TokenService: testEGITokenService,
	AccountService: testEGIAccountService,
	TokensNotBefore: testEGITokensNotBefore,
}
var testProvidersTruth *oidcConfig = &oidcConfig{
	Providers: map[string]*oidcProviderConfig{
		"CDSE": testCDSECfg,
		"egi": testEGICfg,
	},
}

func checkOidcProviderConfigEqual(cfg1, cfg2 *oidcProviderConfig) error {
	differences := []string{}
	if cfg1.Realm != cfg2.Realm {
		differences = append(differences, fmt.Sprintf("realms differs %s <> %s", cfg1.Realm, cfg2.Realm))
	}
	if cfg1.PublicKey != cfg2.PublicKey {
		differences = append(differences, fmt.Sprintf("public_key differs %s <> %s", cfg1.PublicKey, cfg2.PublicKey))
	}
	if cfg1.TokenService != cfg2.TokenService {
		differences = append(differences, fmt.Sprintf("token_service differs %s <> %s", cfg1.TokenService, cfg2.TokenService))
	}
	if cfg1.AccountService != cfg2.AccountService {
		differences = append(differences, fmt.Sprintf("account_service differs %s <> %s", cfg1.AccountService, cfg2.AccountService))
	}
	if cfg1.TokensNotBefore != cfg2.TokensNotBefore {
		differences = append(differences, fmt.Sprintf("tokens_not_before differs %d <> %d", cfg1.TokensNotBefore, cfg2.TokensNotBefore))
	}

	if len(differences) == 0 {
		return nil
	}
	return errors.New(strings.Join(differences, "\n"))
}

func TestLoadConfig(t *testing.T) {
	oidcConfig, err := loadOidcConfig([]byte(testConfigAll))
	if err != nil {
		t.Errorf("Failed to load OIDC config due to %s", err)
	}

	for providerName, providerExpectedCfg := range testProvidersTruth.Providers {
		providerCfg, exists := oidcConfig.Providers[providerName]
		if !exists {
			t.Errorf("%s provider config was missing", providerName)
		} else {
			err = checkOidcProviderConfigEqual(providerCfg, providerExpectedCfg)
			if err != nil {
				t.Errorf("OIDC provider config for %s is not equal %s", providerName, err)
			}
		}
	} 
}

func getTestSigningKey() (*rsa.PrivateKey, error){
	return PrivateKeyFromPemFile("../etc/jwt_testing_rsa")
}

var testSubject string = "55959a95-714e-4013-b065-fadbfb8de0ae"
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
var testPolicyNoPermissions string = `{
	"Version": "2012-10-17",
	"Statement": []
}`

var testPolicyAllowAllARN = "arn:aws:iam::000000000000:role/AllowAll"
var testPolicyNoPermissionsARN = "arn:aws:iam::000000000000:role/NoPermissions"
func NewTestPolicyManagerAllowAll() *PolicyManager {
	return NewPolicyManager(
		TestPolicyRetriever{
			testPolicies: map[string]string{
				testPolicyAllowAllARN: testPolicyAllowAll,
				testPolicyNoPermissionsARN: testPolicyNoPermissions,
			},
		},
	)
}

func CreateTestingToken() (*jwt.Token) {
	pm = *NewTestPolicyManagerAllowAll()
	return createRS256PolicyToken(testFakeIssuer, testEgiIssuer, testSubject, testPolicyAllowAllARN,20 * time.Minute, session.AWSSessionTags{})
}

func CreateTestingTokenWithNoAccess() (*jwt.Token) {
	pm = *NewTestPolicyManagerAllowAll()
	return createRS256PolicyToken(testFakeIssuer, testEgiIssuer, testSubject, testPolicyNoPermissionsARN,20 * time.Minute, session.AWSSessionTags{})
}

func CreateSignedTestingToken() (string, error) {
	signingKey, err := getTestSigningKey()
	if err != nil {
		return "", err
	}
	return CreateSignedToken(CreateTestingToken(), signingKey)
}

func TestGetTokenClaims(t *testing.T) {
	_, err := loadOidcConfig([]byte(testConfigFakeTesting))
	if err != nil {
		t.Errorf("Failed to load OIDC config due to %s", err)
	}

	token, err := CreateSignedTestingToken()
	if err != nil {
		t.Errorf("Could not create testing token %s: %s", token, err)
		t.Fail()
	}
	claimMap, err :=ExtractOIDCTokenClaims(token)
	if err != nil {
		t.Errorf("Could not get claims from testing token %s: %s", token, err)
		t.Fail()
	}
	sub, err := claimMap.GetSubject()
	if err != nil {
		t.Errorf("Could not get subject from claims %s: %s", token, err)
		t.Fail()
	}
	if sub != testSubject {
		t.Errorf("Test subject should have been %s, got %s", testSubject, sub)
		t.Fail()
	}
	if claimMap.RoleARN != testPolicyAllowAllARN {
		t.Errorf("Test policy should have been %s, got %s", testPolicyAllowAll, claimMap.RoleARN)
		t.Fail()
	}
}

func TestGetCDSEPublicKey (t *testing.T) {
	cfg, err := loadOidcConfig([]byte(testConfigCDSE))
	if err != nil {
		t.Errorf("Failed to load OIDC config due to %s", err)
	}
	providerCfg := cfg.Providers["CDSE"]
	key, err := providerCfg.getPublicKey()
	if err != nil {
		t.Errorf("Could not get public key due to %s", err)
	}
	if key == nil {
		t.Error("Retrieved public key was nil")
	}

}

func TestGetEGIPublicKey (t *testing.T) {
	cfg, err := loadOidcConfig([]byte(testConfigEGI))
	if err != nil {
		t.Errorf("Failed to load OIDC config due to %s", err)
	}
	providerCfg := cfg.Providers["egi"]
	key, err := providerCfg.getPublicKey()
	if err != nil {
		t.Errorf("Could not get public key due to %s", err)
	}
	if key == nil {
		t.Error("Retrieved public key was nil")
	}

}