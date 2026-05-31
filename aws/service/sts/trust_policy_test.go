package sts

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	"github.com/VITObelgium/fakes3pp/utils"
)

// writeTrustPolicyFile writes a trust policy template under dir for the given
// role ARN, using the base32 naming scheme expected by LocalPolicyRetriever.
func writeTrustPolicyFile(t testing.TB, dir, roleArn, body string) string {
	t.Helper()
	name := fmt.Sprintf("%s.json.tmpl", utils.B32(roleArn))
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write trust policy: %v", err)
	}
	return p
}

func newTrustPM(t testing.TB, dir string) *iam.PolicyManager {
	t.Helper()
	tpm, err := iam.NewPolicyManagerForLocalPolicies(dir)
	if err != nil {
		t.Fatalf("trust pm: %v", err)
	}
	return tpm
}

func doAssumeRole(t testing.TB, s *STSServer, roleArn, token string) *httptest.ResponseRecorder {
	t.Helper()
	url := buildAssumeRoleWithIdentityTokenUrl(901, "mysession", roleArn, token)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.processSTSPost(rr, req)
	return rr
}

// 1) When no trust policy manager is wired, assume-role succeeds (the
// existing TestProxySts already covers this implicitly; this is the explicit
// "default-allow when tpm nil" test).
func TestTrustPolicy_NilManagerAllows(t *testing.T) {
	pm := getNewTestPM(t)
	s := NewTestSTSServerWithTrust(t, pm, nil, 3600, testOIDCConfigFakeTesting, false)

	token := getWebIdentityTestingToken(t, s.jwtKeyMaterial, 10*time.Minute, nil)
	rr := doAssumeRole(t, s, testPolicyArnForTestPM, token)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with nil trust manager, got %d: %s", rr.Result().StatusCode, rr.Body.String())
	}
}

// 2) Trust path configured but no file for the role -> default-allow.
func TestTrustPolicy_NoFileAllows(t *testing.T) {
	dir := t.TempDir()
	pm := getNewTestPM(t)
	tpm := newTrustPM(t, dir)
	s := NewTestSTSServerWithTrust(t, pm, tpm, 3600, testOIDCConfigFakeTesting, false)

	token := getWebIdentityTestingToken(t, s.jwtKeyMaterial, 10*time.Minute, nil)
	rr := doAssumeRole(t, s, testPolicyArnForTestPM, token)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when no trust file exists, got %d: %s", rr.Result().StatusCode, rr.Body.String())
	}
}

// 3) Trust policy that allows the call -> success.
func TestTrustPolicy_AllowSucceeds(t *testing.T) {
	dir := t.TempDir()
	writeTrustPolicyFile(t, dir, testPolicyArnForTestPM, fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s"
		}]
	}`, testPolicyArnForTestPM))

	pm := getNewTestPM(t)
	tpm := newTrustPM(t, dir)
	s := NewTestSTSServerWithTrust(t, pm, tpm, 3600, testOIDCConfigFakeTesting, false)

	token := getWebIdentityTestingToken(t, s.jwtKeyMaterial, 10*time.Minute, nil)
	rr := doAssumeRole(t, s, testPolicyArnForTestPM, token)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with allowing trust policy, got %d: %s", rr.Result().StatusCode, rr.Body.String())
	}
}

// 4) Trust policy with mismatching condition -> 403.
func TestTrustPolicy_ConditionMismatchDenies(t *testing.T) {
	dir := t.TempDir()
	writeTrustPolicyFile(t, dir, testPolicyArnForTestPM, fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s",
			"Condition": {
				"StringEquals": { "localhost:sub": "another-user" }
			}
		}]
	}`, testPolicyArnForTestPM))

	pm := getNewTestPM(t)
	tpm := newTrustPM(t, dir)
	s := NewTestSTSServerWithTrust(t, pm, tpm, 3600, testOIDCConfigFakeTesting, false)

	token := getWebIdentityTestingToken(t, s.jwtKeyMaterial, 10*time.Minute, nil)
	rr := doAssumeRole(t, s, testPolicyArnForTestPM, token)
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 with non-matching trust policy, got %d: %s", rr.Result().StatusCode, rr.Body.String())
	}
}

// 5) Federated principal mismatch -> 403.
func TestTrustPolicy_FederatedMismatchDenies(t *testing.T) {
	dir := t.TempDir()
	writeTrustPolicyFile(t, dir, testPolicyArnForTestPM, fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": { "Federated": "https://other.idp/example" },
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s"
		}]
	}`, testPolicyArnForTestPM))

	pm := getNewTestPM(t)
	tpm := newTrustPM(t, dir)
	s := NewTestSTSServerWithTrust(t, pm, tpm, 3600, testOIDCConfigFakeTesting, false)

	token := getWebIdentityTestingToken(t, s.jwtKeyMaterial, 10*time.Minute, nil)
	rr := doAssumeRole(t, s, testPolicyArnForTestPM, token)
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 with mismatched Federated Principal, got %d: %s", rr.Result().StatusCode, rr.Body.String())
	}
}

// 7) Multi-audience token with ForAnyValue:StringEquals trust policy is allowed.
func TestTrustPolicy_MultiAudienceForAnyValueAllow(t *testing.T) {
	dir := t.TempDir()
	writeTrustPolicyFile(t, dir, testPolicyArnForTestPM, fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s",
			"Condition": {
				"ForAnyValue:StringEquals": { "localhost:aud": "fakes3pp" }
			}
		}]
	}`, testPolicyArnForTestPM))

	pm := getNewTestPM(t)
	tpm := newTrustPM(t, dir)
	s := NewTestSTSServerWithTrust(t, pm, tpm, 3600, testOIDCConfigFakeTesting, false)

	token, err := CreateSignedOIDCTestingToken(s.jwtKeyMaterial, 10*time.Minute, nil, "fakes3pp", "myservice")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	rr := doAssumeRole(t, s, testPolicyArnForTestPM, token)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with ForAnyValue match, got %d: %s", rr.Result().StatusCode, rr.Body.String())
	}
}

// 8) Multi-audience token with ForAllValues policy denies when token has an
// audience not in the allow-list.
func TestTrustPolicy_MultiAudienceForAllValuesDeny(t *testing.T) {
	dir := t.TempDir()
	writeTrustPolicyFile(t, dir, testPolicyArnForTestPM, fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s",
			"Condition": {
				"ForAllValues:StringEquals": { "localhost:aud": ["fakes3pp"] }
			}
		}]
	}`, testPolicyArnForTestPM))

	pm := getNewTestPM(t)
	tpm := newTrustPM(t, dir)
	s := NewTestSTSServerWithTrust(t, pm, tpm, 3600, testOIDCConfigFakeTesting, false)

	token, err := CreateSignedOIDCTestingToken(s.jwtKeyMaterial, 10*time.Minute, nil, "fakes3pp", "extraneous")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	rr := doAssumeRole(t, s, testPolicyArnForTestPM, token)
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 with ForAllValues extraneous aud, got %d: %s", rr.Result().StatusCode, rr.Body.String())
	}
}

// 6) Hot reload: start denying, rewrite to allow, then it must allow.
func TestTrustPolicy_HotReload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping hot-reload test in short mode")
	}
	dir := t.TempDir()
	// Initial: deny via non-matching condition.
	path := writeTrustPolicyFile(t, dir, testPolicyArnForTestPM, fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s",
			"Condition": { "StringEquals": { "localhost:sub": "nope" } }
		}]
	}`, testPolicyArnForTestPM))

	pm := getNewTestPM(t)
	tpm := newTrustPM(t, dir)
	s := NewTestSTSServerWithTrust(t, pm, tpm, 3600, testOIDCConfigFakeTesting, false)
	token := getWebIdentityTestingToken(t, s.jwtKeyMaterial, 10*time.Minute, nil)

	// Prime the watcher by triggering a load.
	if rr := doAssumeRole(t, s, testPolicyArnForTestPM, token); rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected initial 403, got %d", rr.Result().StatusCode)
	}

	// Rewrite to allow.
	allowing := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s"
		}]
	}`, testPolicyArnForTestPM)
	if err := os.WriteFile(path, []byte(allowing), 0o600); err != nil {
		t.Fatalf("rewrite trust policy: %v", err)
	}

	// fsnotify delivery is async; poll briefly for the change to take effect.
	deadline := time.Now().Add(2 * time.Second)
	var lastStatus int
	for time.Now().Before(deadline) {
		rr := doAssumeRole(t, s, testPolicyArnForTestPM, token)
		lastStatus = rr.Result().StatusCode
		if lastStatus == http.StatusOK {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("trust policy was not hot-reloaded; last status=%d", lastStatus)
}
