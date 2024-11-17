package cmd

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)


var testDefaultBackendRegion = "waw3-1"
var testSecondBackendRegion = "eu-nl"
var testDefaultBackendCredentials = aws.Credentials{
	AccessKeyID: "fake_key_id",
	SecretAccessKey: "fake_secret",
}
var testSecondaryBackendCredentials = aws.Credentials{
	AccessKeyID: "fake_key_id_otc",
	SecretAccessKey: "fake_secret_otc",
	SessionToken: "fakeSessionTokOtc1",
	CanExpire: true,
}

func TestLoadingOfExampleConfig(t *testing.T) {
	BindEnvVariables(proxys3)
	cfg , err := getBackendsConfig()
	if err != nil {
		t.Error("Could not load S3 backend config")
		t.Fail()
	}
	if cfg.defaultBackend != testDefaultBackendRegion {
		t.Errorf("Incorrect default backend. Got %s, Expected %s", cfg.defaultBackend, testDefaultBackendRegion)
	}
	_, err = cfg.getBackendConfig(testDefaultBackendRegion)
	if err != nil {
		t.Error("Default backend config is not available")
	}
	creds1, err := cfg.getBackendCredentials(testDefaultBackendRegion)
	if err != nil {
		t.Error("Default backend credentials are not available")
	}
	if creds1 != testDefaultBackendCredentials {
		t.Error("Default backend credentials are not correctly loaded")
	}

	_, err = cfg.getBackendConfig(testSecondBackendRegion)
	if err != nil {
		t.Error("Secondary backend config is not available")
	}
	creds2, err := cfg.getBackendCredentials(testSecondBackendRegion)
	if err != nil {
		t.Error("Secondary backend credentials are not available")
	}
	if creds2 != testSecondaryBackendCredentials {
		t.Error("Secondary backend credentials are not correctly loaded")
	}
}