package s3

import (
	"fmt"
	"path"
	"testing"

	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/testutils"
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
var relativeEtcPathForS3Package = "../../../etc"

func TestLoadingOfExampleConfig(t *testing.T) {
	cfg , err := getBackendsConfig(path.Join(relativeEtcPathForS3Package, "backend-config.yaml"), true)
	if err != nil {
		t.Error("Could not load S3 backend config")
		t.FailNow()
	}
	if cfg.defaultBackend != testDefaultBackendRegion {
		t.Errorf("Incorrect default backend. Got %s, Expected %s", cfg.defaultBackend, testDefaultBackendRegion)
	}
	_, err = cfg.getBackendConfig(testDefaultBackendRegion)
	if err != nil {
		t.Error("Default backend config is not available")
	}
	creds1, err := cfg.GetBackendCredentials(testDefaultBackendRegion)
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
	creds2, err := cfg.GetBackendCredentials(testSecondBackendRegion)
	if err != nil {
		t.Error("Secondary backend credentials are not available")
	}
	if creds2 != testSecondaryBackendCredentials {
		t.Error("Secondary backend credentials are not correctly loaded")
	}
}

func TestLoadingOfExampleConfigAbsoluteCredentialPaths(t *testing.T) {
	//Given 2 credentials file and their absolute path
	cfcCredFile := testutils.CreateTempTestCopy(t, path.Join(relativeEtcPathForS3Package, "creds/cfc_creds.yaml"))
	otcCredFile := testutils.CreateTempTestCopy(t, path.Join(relativeEtcPathForS3Package, "creds/otc_creds.yaml"))

	//Given a config that uses the absolute paths
	backendConfigYaml := fmt.Sprintf(`
s3backends:
  - region: waw3-1
    credentials:
      file: %s
    endpoint: https://s3.waw3-1.cloudferro.com
    capabilities: ["StreamingUnsignedPayloadTrailer"]
  - region: eu-nl
    credentials:
      file: %s
    endpoint: https://obs.eu-nl.otc.t-systems.com
default:  waw3-1
`, cfcCredFile, otcCredFile)

	//Given that this config file is on the relative path
	relativepath := relativeEtcPathForS3Package

	//WHEN we load the config file
	cfg , err := getBackendsConfigFromBytes([]byte(backendConfigYaml), true, relativepath)
	//THEN it loads correctly and we can get the different config values
	if err != nil {
		t.Errorf("Could not load S3 backend config: %s", err)
		t.FailNow()
	}
	if cfg.defaultBackend != testDefaultBackendRegion {
		t.Errorf("Incorrect default backend. Got %s, Expected %s", cfg.defaultBackend, testDefaultBackendRegion)
	}
	_, err = cfg.getBackendConfig(testDefaultBackendRegion)
	if err != nil {
		t.Error("Default backend config is not available")
	}
	creds1, err := cfg.GetBackendCredentials(testDefaultBackendRegion)
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
	creds2, err := cfg.GetBackendCredentials(testSecondBackendRegion)
	if err != nil {
		t.Error("Secondary backend credentials are not available")
	}
	if creds2 != testSecondaryBackendCredentials {
		t.Error("Secondary backend credentials are not correctly loaded")
	}

	if !cfg.HasCapability(testDefaultBackendRegion, interfaces.S3CapabilityStreamingUnsignedPayloadTrailer) {
		t.Error("default region was configured with capability but not found")
	}

	if cfg.HasCapability(testSecondBackendRegion, interfaces.S3CapabilityStreamingUnsignedPayloadTrailer) {
		t.Error("second backend region was NOT configured with capability but still reported as having it")
	}

	if !cfg.HasCapability("us-east-1", interfaces.S3CapabilityStreamingUnsignedPayloadTrailer) {
		t.Error("Non defined backend region should use capabilities of default backend which was configured with capability")
	}
}