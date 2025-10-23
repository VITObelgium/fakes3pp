package iam

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/VITObelgium/fakes3pp/utils"
)

var testPolicyRealistic = `
	{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "Allow bucket level permissions for artifacts",
				"Effect": "Allow",
				"Action": [
					"s3:ListBucket",
					"s3:ListBucketMultipartUploads"
				],
				"Resource": "arn:aws:s3:::OpenEO-artifacts",
				"Condition" : {
					"StringLike" : {
						"s3:prefix": "{{.Claims.Subject}}/*" 
					}
				} 
			}
		]
	}
`

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

const testRegion1 = "tst-1"

// This policy is to test whether a policy can be scoped to a specific region
// since our proxy uses region to determine a backend this makes sure to be able
// to have different permissions for different backends. This is used in test cases
// that start with TestPolicyAllowAllInRegion1
var testPolicyAllowAllInRegion1 string = fmt.Sprintf(`{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": "s3:*",
			"Resource": "*",
			"Condition" : {
					"StringLike" : {
							"aws:RequestedRegion": "%s" 
					}
			} 
		}
	]
}`, testRegion1)

func newTestPolicyManager() *PolicyManager {
	return NewTestPolicyManager(
		map[string]string{
			"policyRealistic": testPolicyRealistic,
			"now":             "{{Now | YYYYmmdd }}",
			"nowSlashed":      "{{Now | YYYYmmddSlashed}}",
			"tomorrow":        "{{Now | Add1Day | YYYYmmdd}}",
			"sha1":            "{{ printf \"%s:%s\" .Claims.Issuer .Claims.Subject | SHA1}}",
		},
	)
}

type policyGenerationTestCase struct {
	PolicyName     string
	Claims         *credentials.SessionClaims
	Expectedpolicy string
}

func buildTestSessionClaimsNoTags(issuer, subject string) *credentials.SessionClaims {
	idpClaims := credentials.NewIDPClaims(issuer, subject, time.Hour*1, session.AWSSessionTags{})
	return &credentials.SessionClaims{
		RoleARN:   "",
		IIssuer:   "",
		IDPClaims: *idpClaims,
	}
}

func TestPolicyGeneration(t *testing.T) {
	testCases := []policyGenerationTestCase{
		{
			PolicyName:     "policyRealistic",
			Claims:         buildTestSessionClaimsNoTags("", "userA"),
			Expectedpolicy: strings.ReplaceAll(testPolicyRealistic, "{{.Claims.Subject}}", "userA"),
		},
		{
			PolicyName:     "now",
			Claims:         buildTestSessionClaimsNoTags("", ""),
			Expectedpolicy: YYYYmmdd(Now()),
		},
		{
			PolicyName:     "nowSlashed",
			Claims:         buildTestSessionClaimsNoTags("", ""),
			Expectedpolicy: YYYYmmddSlashed(Now()),
		},
		{
			PolicyName:     "tomorrow",
			Claims:         buildTestSessionClaimsNoTags("", ""),
			Expectedpolicy: YYYYmmdd(Now().Add(time.Hour * 24)),
		},
		{
			PolicyName:     "sha1",
			Claims:         buildTestSessionClaimsNoTags("a", "b"),
			Expectedpolicy: utils.Sha1sum("a:b"),
		},
	}

	tpm := newTestPolicyManager()

	for _, tc := range testCases {
		policyData := GetPolicySessionDataFromClaims(tc.Claims)
		got, err := tpm.GetPolicy(tc.PolicyName, policyData)
		if err != nil {
			t.Errorf("Encountered for policy %s error %s", tc.PolicyName, err)
		}
		if got != tc.Expectedpolicy {
			t.Errorf("Got %s, expected %s", got, tc.Expectedpolicy)
		}
	}
}

const testVersion = "2012-10-17"

// This ARN corresponds to a test policy file that is shipped in the repo
const testARN = "arn:aws:iam::000000000000:role/S3Access"

func getPMForTesting(t testing.TB) *PolicyManager {
	pm, err := NewPolicyManagerForLocalPolicies("../../../etc/policies")
	if err != nil {
		t.Error("Could not get PM for testing", "error", err)
		t.FailNow()
	}
	return pm
}

func TestLocatePolicy(t *testing.T) {
	// //Given config of proxysts is set
	// BindEnvVariables("proxysts")
	// initializePolicyManager()

	pm := getPMForTesting(t)
	//Given an input ARN for which we have the policy file at the expected location
	//When we load it
	p, err := pm.retriever.retrievePolicyStr(testARN)
	if err != nil {
		t.Errorf("Did not get policy str content %s, got errror %s", p, err)
	}
	content, err := parsePolicy(p)
	//We should not error out
	if err != nil {
		t.Errorf("Did not get policy content %v, got errror %s", content, err)
	}
	//And the policy object should be a valid object
	if content.Version != testVersion {
		t.Errorf(
			"Policy did not have expected version, got %s wanted %s",
			content.Version, testVersion,
		)
	}
}

func TestPolicyManagerPrewarm(t *testing.T) {
	// //Given config of proxysts is set
	// BindEnvVariables("proxysts")
	// initializePolicyManager()
	pm := getPMForTesting(t)

	//When we prewarm the policy manager
	err := pm.PreWarm()
	if err != nil {
		//Then we do not expect errors
		t.Error(err)
	}
	expectedPolicy := "arn:aws:iam::000000000000:role/S3Access"
	if !pm.DoesPolicyExist(expectedPolicy) {
		t.Errorf("Missing policy %s", expectedPolicy)
	}
}

func createTestPolicyFileForLocalPolicyRetriever(policyArn, policyContent string, pr *LocalPolicyRetriever, t *testing.T) {
	policyFileName := pr.getPolicyPath(policyArn)
	f, err := os.Create(policyFileName)
	checkErrorTestDependency(err, t, fmt.Sprintf("Could Not create policy file %s", policyFileName))

	_, err = f.Write([]byte(policyContent))
	checkErrorTestDependency(err, t, fmt.Sprintf("Could not write policy content while creating test policy %s: %s", policyArn, policyContent))

	defer utils.Close(f, fmt.Sprintf("CreateTestPolicyFileForLocalPolicyRetriever %s", policyArn), nil)
}

func deleteTestPolicyFileForLocalPolicyRetriever(policyArn string, pr *LocalPolicyRetriever, t *testing.T) {
	policyFileName := pr.getPolicyPath(policyArn)
	err := os.Remove(policyFileName)
	checkErrorTestDependency(err, t, fmt.Sprintf("Could not delete policy file %s", policyFileName))
}

func TestCacheInvalidationLocalPolicyRetrieverIfPolicyIsRemoved(t *testing.T) {
	//Given a policy manager that is backed by a local PolicyRetriever
	pr := NewLocalPolicyRetriever(t.TempDir())
	pm := NewPolicyManager(pr)
	//Given a test Arn
	testArn := "arn:aws:iam::000000000000:role/cache-invalidation"

	//WHEN the policy file exists in the expected place
	createTestPolicyFileForLocalPolicyRetriever(testArn, testPolicyAllowAll, pr, t)
	//THEN it must exist as per the Policy Manager
	if !pm.DoesPolicyExist(testArn) {
		t.Errorf("Policy %s should have existed but it did not", testArn)
		t.FailNow()
	}

	//WHEN the policyFile gets deleted
	deleteTestPolicyFileForLocalPolicyRetriever(testArn, pr, t)
	deletionTime := time.Now()

	var policyManagerKnowsPolicyDoesNotExist predicateFunction = func() bool {
		return !pm.DoesPolicyExist(testArn)
	}

	//THEN in due time it should no longer exist
	if !isTrueWithinDueTime(policyManagerKnowsPolicyDoesNotExist) {
		t.Errorf("Policy %s was removed at %s and now %s policy manager still thinks it exists", testArn, deletionTime, time.Now())
		t.FailNow()
	}
}

func TestCacheInvalidationLocalPolicyRetrieverIfPolicyIsChanged(t *testing.T) {
	//Given a policy manager that is backed by a local PolicyRetriever
	pr := NewLocalPolicyRetriever(t.TempDir())
	pm := NewPolicyManager(pr)
	//Given 2 test Arn
	testArn1 := "arn:aws:iam::000000000000:role/cache-invalidation1"
	testArn2 := "arn:aws:iam::000000000000:role/cache-invalidation2"

	//WHEN the policy files exists in the expected place and are policies without time conditions
	createTestPolicyFileForLocalPolicyRetriever(testArn1, testPolicyAllowAll, pr, t)
	createTestPolicyFileForLocalPolicyRetriever(testArn2, testPolicyAllowAllInRegion1, pr, t)

	//THEN the templates actually differ
	pol1, err1 := pm.GetPolicy(testArn1, &PolicySessionData{})
	checkErrorTestDependency(err1, t, "Policy1 should have been retrievable")
	pol2, err2 := pm.GetPolicy(testArn2, &PolicySessionData{})
	checkErrorTestDependency(err2, t, "Policy2 should have been retrievable")

	if pol1 == pol2 {
		t.Errorf("Policies should have been different but both gave: %s", pol1)
		t.FailNow()
	}

	//WHEN the 2nd policy gets updated such that it has the same content as the first.
	deleteTestPolicyFileForLocalPolicyRetriever(testArn2, pr, t)
	createTestPolicyFileForLocalPolicyRetriever(testArn2, testPolicyAllowAll, pr, t)

	updateTime := time.Now()

	var policyManagerSeesUpdate predicateFunction = func() bool {
		pol1, err1 := pm.GetPolicy(testArn1, &PolicySessionData{})
		checkErrorTestDependency(err1, t, "Policy1 should have been retrievable")
		pol2, err2 := pm.GetPolicy(testArn2, &PolicySessionData{})
		checkErrorTestDependency(err2, t, "Policy2 should have been retrievable")

		return pol1 == pol2
	}

	//THEN in due time it should no longer exist
	if !isTrueWithinDueTime(policyManagerSeesUpdate) {
		polText, err := pm.GetPolicy(testArn2, &PolicySessionData{})
		if err != nil {
			polText = err.Error()
		}
		t.Errorf("Policy %s was updated at %s and now %s policy manager still sees %s", testArn2, updateTime, time.Now(), polText)
		t.FailNow()
	}
}
