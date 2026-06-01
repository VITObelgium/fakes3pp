package s3

import (
	"errors"
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
	AccessKeyID:     "fake_key_id",
	SecretAccessKey: "fake_secret",
}
var testSecondaryBackendCredentials = aws.Credentials{
	AccessKeyID:     "fake_key_id_otc",
	SecretAccessKey: "fake_secret_otc",
	SessionToken:    "fakeSessionTokOtc1",
	CanExpire:       true,
}
var relativeEtcPathForS3Package = "../../../etc"

func TestLoadingOfExampleConfig(t *testing.T) {
	cfg, err := getBackendsConfig(path.Join(relativeEtcPathForS3Package, "backend-config.yaml"), true)
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
	cfg, err := getBackendsConfigFromBytes([]byte(backendConfigYaml), true, relativepath)
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

// ---- credential rule tests ----

const testCredRuleRegion = "eu-test-1"

// baseYaml wraps a credentials block in a minimal valid backends config
func baseYaml(credentialsBlock string) string {
	return fmt.Sprintf(`
s3backends:
  - region: %s
    endpoint: https://backend.example
    credentials:
%s
default: %s
`, testCredRuleRegion, credentialsBlock, testCredRuleRegion)
}

var credsTeamA = aws.Credentials{AccessKeyID: "KEY_A", SecretAccessKey: "SECRET_A"}
var credsTeamB = aws.Credentials{AccessKeyID: "KEY_B", SecretAccessKey: "SECRET_B"}
var credsDefault = aws.Credentials{AccessKeyID: "KEY_DEFAULT", SecretAccessKey: "SECRET_DEFAULT"}

const rulesYaml = `      rules:
        - name: team-a
          when:
            StringEquals:
              aws:PrincipalTag/org:
                - a
          inline:
            aws_access_key_id: KEY_A
            aws_secret_access_key: SECRET_A
        - name: team-b
          when:
            StringEquals:
              aws:PrincipalTag/org:
                - b
          inline:
            aws_access_key_id: KEY_B
            aws_secret_access_key: SECRET_B
        - name: default
          inline:
            aws_access_key_id: KEY_DEFAULT
            aws_secret_access_key: SECRET_DEFAULT
`

func loadTestConfig(t *testing.T, yaml string) *backendsConfig {
	t.Helper()
	cfg, err := getBackendsConfigFromBytes([]byte(yaml), false, "")
	if err != nil {
		t.Fatalf("could not load config: %s", err)
	}
	return cfg
}

func TestCredentialRulesSelectByPrincipalTag(t *testing.T) {
	cfg := loadTestConfig(t, baseYaml(rulesYaml))

	tests := []struct {
		description string
		selCtx      CredentialSelectionContext
		want        aws.Credentials
	}{
		{
			"org=a selects team-a credentials",
			CredentialSelectionContext{
				PrincipalTags: map[string][]string{"org": {"a"}},
			},
			credsTeamA,
		},
		{
			"org=b selects team-b credentials",
			CredentialSelectionContext{
				PrincipalTags: map[string][]string{"org": {"b"}},
			},
			credsTeamB,
		},
		{
			"unknown org falls through to default",
			CredentialSelectionContext{
				PrincipalTags: map[string][]string{"org": {"c"}},
			},
			credsDefault,
		},
		{
			"no tags falls through to default",
			CredentialSelectionContext{},
			credsDefault,
		},
	}

	for _, tc := range tests {
		creds, _, err := cfg.SelectBackendCredentials(testCredRuleRegion, tc.selCtx)
		if err != nil {
			t.Errorf("%s: unexpected error: %s", tc.description, err)
			continue
		}
		if creds.AccessKeyID != tc.want.AccessKeyID {
			t.Errorf("%s: want AccessKeyID %s got %s", tc.description, tc.want.AccessKeyID, creds.AccessKeyID)
		}
	}
}

func TestCredentialRulesSelectByRequestAKID(t *testing.T) {
	const akidRulesYaml = `      rules:
        - name: legacy-akid
          when:
            StringEquals:
              fakes3pp:RequestAccessKeyId:
                - AKIAOLD
          inline:
            aws_access_key_id: KEY_LEGACY
            aws_secret_access_key: SECRET_LEGACY
        - name: default
          inline:
            aws_access_key_id: KEY_DEFAULT
            aws_secret_access_key: SECRET_DEFAULT
`
	cfg := loadTestConfig(t, baseYaml(akidRulesYaml))

	tests := []struct {
		description string
		akid        string
		wantKey     string
	}{
		{"matching AKID selects legacy creds", "AKIAOLD", "KEY_LEGACY"},
		{"other AKID falls through to default", "AKIANEW", "KEY_DEFAULT"},
		{"empty AKID falls through to default", "", "KEY_DEFAULT"},
	}

	for _, tc := range tests {
		selCtx := CredentialSelectionContext{RequestAccessKeyID: tc.akid}
		creds, _, err := cfg.SelectBackendCredentials(testCredRuleRegion, selCtx)
		if err != nil {
			t.Errorf("%s: unexpected error: %s", tc.description, err)
			continue
		}
		if creds.AccessKeyID != tc.wantKey {
			t.Errorf("%s: want %s got %s", tc.description, tc.wantKey, creds.AccessKeyID)
		}
	}
}

func TestCredentialRulesSelectByClaimsSub(t *testing.T) {
	const claimsRulesYaml = `      rules:
        - name: admin
          when:
            StringEquals:
              claims:sub:
                - admin
          inline:
            aws_access_key_id: KEY_ADMIN
            aws_secret_access_key: SECRET_ADMIN
        - name: wildcard-user
          when:
            StringLike:
              claims:sub:
                - user-*
          inline:
            aws_access_key_id: KEY_USER
            aws_secret_access_key: SECRET_USER
        - name: default
          inline:
            aws_access_key_id: KEY_DEFAULT
            aws_secret_access_key: SECRET_DEFAULT
`
	cfg := loadTestConfig(t, baseYaml(claimsRulesYaml))

	tests := []struct {
		sub     string
		wantKey string
	}{
		{"admin", "KEY_ADMIN"},
		{"user-alice", "KEY_USER"},
		{"user-bob", "KEY_USER"},
		{"other", "KEY_DEFAULT"},
	}

	for _, tc := range tests {
		selCtx := CredentialSelectionContext{ClaimsSubject: tc.sub}
		creds, _, err := cfg.SelectBackendCredentials(testCredRuleRegion, selCtx)
		if err != nil {
			t.Errorf("sub=%s: unexpected error: %s", tc.sub, err)
			continue
		}
		if creds.AccessKeyID != tc.wantKey {
			t.Errorf("sub=%s: want %s got %s", tc.sub, tc.wantKey, creds.AccessKeyID)
		}
	}
}

func TestCredentialRulesSelectByRegion(t *testing.T) {
	const regionRulesYaml = `      rules:
        - name: eu-only
          when:
            StringLike:
              aws:RequestedRegion:
                - eu-*
          inline:
            aws_access_key_id: KEY_EU
            aws_secret_access_key: SECRET_EU
        - name: default
          inline:
            aws_access_key_id: KEY_DEFAULT
            aws_secret_access_key: SECRET_DEFAULT
`
	cfg := loadTestConfig(t, baseYaml(regionRulesYaml))

	tests := []struct {
		region  string
		wantKey string
	}{
		{"eu-west-1", "KEY_EU"},
		{"eu-test-1", "KEY_EU"},
		{"us-east-1", "KEY_DEFAULT"},
	}

	for _, tc := range tests {
		selCtx := CredentialSelectionContext{RequestedRegion: tc.region}
		creds, _, err := cfg.SelectBackendCredentials(testCredRuleRegion, selCtx)
		if err != nil {
			t.Errorf("region=%s: unexpected error: %s", tc.region, err)
			continue
		}
		if creds.AccessKeyID != tc.wantKey {
			t.Errorf("region=%s: want %s got %s", tc.region, tc.wantKey, creds.AccessKeyID)
		}
	}
}

func TestCredentialRulesDefaultIsAlwaysLast(t *testing.T) {
	// Default rule appears first in config but must be evaluated last
	const defaultFirstYaml = `      rules:
        - name: catch-all-default
          inline:
            aws_access_key_id: KEY_DEFAULT
            aws_secret_access_key: SECRET_DEFAULT
        - name: team-a
          when:
            StringEquals:
              aws:PrincipalTag/org:
                - a
          inline:
            aws_access_key_id: KEY_A
            aws_secret_access_key: SECRET_A
`
	cfg := loadTestConfig(t, baseYaml(defaultFirstYaml))

	selCtx := CredentialSelectionContext{
		PrincipalTags: map[string][]string{"org": {"a"}},
	}
	creds, rule, err := cfg.SelectBackendCredentials(testCredRuleRegion, selCtx)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if creds.AccessKeyID != "KEY_A" {
		t.Errorf("default-first config: conditional rule should win over default, got %s (rule=%s)", creds.AccessKeyID, rule)
	}
}

func TestCredentialRulesNoMatchWithoutDefaultReturnsAccessDenied(t *testing.T) {
	const noDefaultYaml = `      rules:
        - name: team-a
          when:
            StringEquals:
              aws:PrincipalTag/org:
                - a
          inline:
            aws_access_key_id: KEY_A
            aws_secret_access_key: SECRET_A
`
	cfg := loadTestConfig(t, baseYaml(noDefaultYaml))

	selCtx := CredentialSelectionContext{
		PrincipalTags: map[string][]string{"org": {"b"}},
	}
	_, _, err := cfg.SelectBackendCredentials(testCredRuleRegion, selCtx)
	if !errors.Is(err, ErrNoMatchingCredentialRule) {
		t.Errorf("expected ErrNoMatchingCredentialRule, got %v", err)
	}
}

func TestCredentialRulesRejectsMultipleDefaults(t *testing.T) {
	const twoDefaultsYaml = `      rules:
        - name: default-1
          inline:
            aws_access_key_id: KEY_1
            aws_secret_access_key: SECRET_1
        - name: default-2
          inline:
            aws_access_key_id: KEY_2
            aws_secret_access_key: SECRET_2
`
	_, err := getBackendsConfigFromBytes([]byte(baseYaml(twoDefaultsYaml)), false, "")
	if err == nil {
		t.Error("expected error for two default rules, got none")
	}
}

func TestCredentialRulesRejectsMixingRulesWithLegacy(t *testing.T) {
	const mixedYaml = `      rules:
        - name: r1
          inline:
            aws_access_key_id: KEY_1
            aws_secret_access_key: SECRET_1
      file: some-file.yaml
`
	_, err := getBackendsConfigFromBytes([]byte(baseYaml(mixedYaml)), false, "")
	if err == nil {
		t.Error("expected error for mixing rules with file, got none")
	}
}

func TestCredentialRulesLegacyInlineNormalized(t *testing.T) {
	// Legacy inline config must still work and behave as a single default rule
	const legacyInlineYaml = `      inline:
        aws_access_key_id: KEY_LEGACY
        aws_secret_access_key: SECRET_LEGACY
`
	cfg := loadTestConfig(t, baseYaml(legacyInlineYaml))

	// GetBackendCredentials (legacy static path) must work
	creds, err := cfg.GetBackendCredentials(testCredRuleRegion)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if creds.AccessKeyID != "KEY_LEGACY" {
		t.Errorf("want KEY_LEGACY got %s", creds.AccessKeyID)
	}

	// SelectBackendCredentials must also match with an empty context (default rule)
	selCreds, _, err := cfg.SelectBackendCredentials(testCredRuleRegion, CredentialSelectionContext{})
	if err != nil {
		t.Fatalf("unexpected error from SelectBackendCredentials: %s", err)
	}
	if selCreds.AccessKeyID != "KEY_LEGACY" {
		t.Errorf("want KEY_LEGACY got %s", selCreds.AccessKeyID)
	}
}
