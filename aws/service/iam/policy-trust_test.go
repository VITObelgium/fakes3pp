package iam

import (
	"fmt"
	"testing"

	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
)

const testTrustRoleArn = "arn:aws:iam::000000000000:role/S3Access"
const testTrustIssuer = "https://localhost/auth/realms/testing"

func newTestTrustData() *TrustPolicySessionData {
	return &TrustPolicySessionData{
		Claims: TrustPolicySessionClaims{
			Subject:  "test-user",
			Issuer:   testTrustIssuer,
			Audience: []string{"fakes3pp", "myservice"},
		},
		Tags: session.AWSSessionTags{
			PrincipalTags: map[string][]string{
				"custom_id": {"idA"},
			},
		},
		RoleArn:         testTrustRoleArn,
		RoleSessionName: "mysession",
		DurationSeconds: 3600,
	}
}

func evalTrust(t *testing.T, pol string, data *TrustPolicySessionData) (bool, evalReason) {
	t.Helper()
	pe, err := NewPolicyEvaluatorFromStr(pol)
	if err != nil {
		t.Fatalf("could not parse trust policy: %v", err)
	}
	action := NewAssumeRoleWithWebIdentityIAMAction(data.RoleArn, data)
	allowed, reason, err := pe.Evaluate(action)
	if err != nil {
		t.Fatalf("unexpected eval error: %v (reason=%s)", err, reason)
	}
	return allowed, reason
}

func TestTrustPolicy_PrincipalWildcardAllows(t *testing.T) {
	pol := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s"
		}]
	}`, testTrustRoleArn)

	allowed, _ := evalTrust(t, pol, newTestTrustData())
	if !allowed {
		t.Fatalf("expected allow with wildcard Principal")
	}
}

func TestTrustPolicy_FederatedPrincipalMatch(t *testing.T) {
	pol := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": { "Federated": "%s" },
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s"
		}]
	}`, testTrustIssuer, testTrustRoleArn)

	allowed, _ := evalTrust(t, pol, newTestTrustData())
	if !allowed {
		t.Fatalf("expected allow for matching Federated principal")
	}
}

func TestTrustPolicy_FederatedPrincipalMismatch(t *testing.T) {
	pol := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": { "Federated": "https://some.other/issuer" },
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s"
		}]
	}`, testTrustRoleArn)

	allowed, reason := evalTrust(t, pol, newTestTrustData())
	if allowed {
		t.Fatalf("expected deny for non-matching Federated principal, reason=%s", reason)
	}
}

func TestTrustPolicy_ConditionMatchesIssuerHostKey(t *testing.T) {
	// localhost is the host part of the issuer URL.
	pol := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s",
			"Condition": {
				"StringLike": { "localhost:sub": "test-*" }
			}
		}]
	}`, testTrustRoleArn)

	allowed, _ := evalTrust(t, pol, newTestTrustData())
	if !allowed {
		t.Fatalf("expected allow when condition matches")
	}
}

func TestTrustPolicy_ConditionUnmatched(t *testing.T) {
	pol := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s",
			"Condition": {
				"StringEquals": { "localhost:sub": "other-user" }
			}
		}]
	}`, testTrustRoleArn)

	allowed, _ := evalTrust(t, pol, newTestTrustData())
	if allowed {
		t.Fatalf("expected deny when condition does not match")
	}
}

func TestTrustPolicy_ExplicitDenyOverridesAllow(t *testing.T) {
	pol := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "sts:AssumeRoleWithWebIdentity",
				"Resource": "%s"
			},
			{
				"Effect": "Deny",
				"Principal": "*",
				"Action": "sts:AssumeRoleWithWebIdentity",
				"Resource": "%s",
				"Condition": {
					"StringEquals": { "aws:PrincipalTag/custom_id": "idA" }
				}
			}
		]
	}`, testTrustRoleArn, testTrustRoleArn)

	allowed, reason := evalTrust(t, pol, newTestTrustData())
	if allowed {
		t.Fatalf("expected explicit deny to win, reason=%s", reason)
	}
	if reason != reasonExplicitDeny {
		t.Fatalf("expected explicit-deny reason, got %s", reason)
	}
}

func TestTrustPolicy_AudienceSingleValuedStringEquals(t *testing.T) {
	pol := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s",
			"Condition": {
				"StringEquals": { "localhost:aud": "fakes3pp" }
			}
		}]
	}`, testTrustRoleArn)

	d := newTestTrustData()
	d.Claims.Audience = []string{"fakes3pp"}
	allowed, _ := evalTrust(t, pol, d)
	if !allowed {
		t.Fatalf("expected allow when single audience matches")
	}
}

// Regression: unqualified operators against a multi-valued context key (such
// as a token with multiple audiences) must error rather than silently match.
// Policies need to opt in to multi-valued evaluation via ForAnyValue/
// ForAllValues quantifiers.
func TestTrustPolicy_AudienceMultiValuedUnqualifiedErrors(t *testing.T) {
	pol := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s",
			"Condition": {
				"StringEquals": { "localhost:aud": "fakes3pp" }
			}
		}]
	}`, testTrustRoleArn)

	pe, err := NewPolicyEvaluatorFromStr(pol)
	if err != nil {
		t.Fatalf("could not parse trust policy: %v", err)
	}
	d := newTestTrustData() // has two audiences
	action := NewAssumeRoleWithWebIdentityIAMAction(d.RoleArn, d)
	_, _, err = pe.Evaluate(action)
	if err == nil {
		t.Fatalf("expected error for unqualified op on multi-valued context key")
	}
}

func TestTrustPolicy_AudienceMultiValuedForAnyValueAllow(t *testing.T) {
	pol := fmt.Sprintf(`{
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
	}`, testTrustRoleArn)

	allowed, _ := evalTrust(t, pol, newTestTrustData())
	if !allowed {
		t.Fatalf("expected allow when one audience matches under ForAnyValue")
	}
}

func TestTrustPolicy_AudienceMultiValuedForAllValuesDeny(t *testing.T) {
	pol := fmt.Sprintf(`{
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
	}`, testTrustRoleArn)

	// Token has audiences ["fakes3pp", "myservice"]; "myservice" is not in
	// the allow-list so ForAllValues must deny.
	allowed, reason := evalTrust(t, pol, newTestTrustData())
	if allowed {
		t.Fatalf("expected deny when ForAllValues sees an extra audience, reason=%s", reason)
	}
}

func TestTrustPolicy_AudienceMultiValuedForAllValuesAllow(t *testing.T) {
	pol := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s",
			"Condition": {
				"ForAllValues:StringEquals": { "localhost:aud": ["fakes3pp", "myservice", "extra"] },
				"Null":                       { "localhost:aud": "false" }
			}
		}]
	}`, testTrustRoleArn)

	allowed, _ := evalTrust(t, pol, newTestTrustData())
	if !allowed {
		t.Fatalf("expected allow when all audiences are in allow-list and key is present")
	}
}

func TestTrustPolicy_RoleSessionNameCondition(t *testing.T) {
	pol := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRoleWithWebIdentity",
			"Resource": "%s",
			"Condition": {
				"StringLike": { "sts:RoleSessionName": "my*" }
			}
		}]
	}`, testTrustRoleArn)

	allowed, _ := evalTrust(t, pol, newTestTrustData())
	if !allowed {
		t.Fatalf("expected allow when session name matches")
	}
}

// Regression: permission policies (no Principal) must keep matching even now
// that isPrincipalMatch exists.
func TestPermissionPolicy_NoPrincipalStillMatches(t *testing.T) {
	pol := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::bucket1/*"
		}]
	}`
	pe, err := NewPolicyEvaluatorFromStr(pol)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	action := NewIamAction("s3:GetObject", "arn:aws:s3:::bucket1/key", nil)
	allowed, reason, err := pe.Evaluate(action)
	if err != nil {
		t.Fatalf("eval error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected allow for permission policy without Principal, reason=%s", reason)
	}
}

func TestIssuerHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://accounts.google.com", "accounts.google.com"},
		{"https://accounts.google.com/", "accounts.google.com"},
		{"https://Accounts.Google.Com/realm", "accounts.google.com"},
		{"plain-string", "plain-string"},
		{"", ""},
	}
	for _, c := range cases {
		if got := IssuerHost(c.in); got != c.want {
			t.Errorf("IssuerHost(%q)=%q want %q", c.in, got, c.want)
		}
	}
}
