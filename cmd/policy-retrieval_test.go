package cmd

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)


type TestPolicyRetriever struct{
	testPolicies map[string]string
}

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

func newTestPolicyManager() *PolicyManager {
	return NewPolicyManager(
		TestPolicyRetriever{
			testPolicies: map[string]string{
				"policyRealistic": testPolicyRealistic,
				"now": "{{Now | YYYYmmdd }}",
				"nowSlashed": "{{Now | YYYYmmddSlashed}}",
				"tomorrow": "{{Now | Add1Day | YYYYmmdd}}",
				"sha1": "{{ printf \"%s:%s\" .Claims.Issuer .Claims.Subject | SHA1}}",
			},
		},
	)
}

func (r TestPolicyRetriever) retrievePolicyStr(arn string) (string, error) {
	policy, ok := r.testPolicies[arn]
	if !ok {
		return "", fmt.Errorf("No test policy named %s", arn)
	}
	return policy, nil 
}

func (r TestPolicyRetriever) registerPolicyManager(pm *PolicyManager) {
	//Cache invalidation is not a thing for testpolicy retriever so no need to keep PolicyManager
}

func (r TestPolicyRetriever) retrieveAllIdentifiers() ([]string, error) {
	keys := make([]string, len(r.testPolicies))

	i := 0
	for k := range r.testPolicies {
		keys[i] = k
		i++
	}
	return keys, nil
}

type policyGenerationTestCase struct {
	PolicyName     string 
	Claims         *SessionClaims
	Expectedpolicy string
}

func buildTestSessionClaimsNoTags(issuer, subject string) (*SessionClaims) {
	idpClaims := newIDPClaims(issuer, subject, time.Hour * 1, AWSSessionTags{})
	return &SessionClaims{
		RoleARN: "",
		IIssuer: "",
		IDPClaims: *idpClaims,
	}
}

func TestPolicyGeneration(t *testing.T) {
	testCases := []policyGenerationTestCase{
		{
			PolicyName: "policyRealistic",
			Claims:     buildTestSessionClaimsNoTags("", "userA"),
			Expectedpolicy: strings.Replace(testPolicyRealistic, "{{.Claims.Subject}}", "userA", -1),
		},
		{
			PolicyName: "now",
			Claims:     buildTestSessionClaimsNoTags("", ""),
			Expectedpolicy: YYYYmmdd(Now()),
		},
		{
			PolicyName: "nowSlashed",
			Claims:     buildTestSessionClaimsNoTags("", ""),
			Expectedpolicy: YYYYmmddSlashed(Now()),
		},
		{
			PolicyName: "tomorrow",
			Claims:     buildTestSessionClaimsNoTags("", ""),
			Expectedpolicy: YYYYmmdd(Now().Add(time.Hour * 24)),
		},
		{
			PolicyName: "sha1",
			Claims:     buildTestSessionClaimsNoTags("a", "b"),
			Expectedpolicy: sha1sum("a:b"),
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

//This ARN corresponds to a test policy file that is shipped in the repo
const testARN = "arn:aws:iam::000000000000:role/S3Access"



func TestLocatePolicy(t *testing.T) {
	//Given config of proxysts is set
	BindEnvVariables("proxysts")
	initializePolicyManager()

	//Given an input ARN for which we have the policy file at the expected location
	//When we load it
	p, err := pm.retriever.retrievePolicyStr(testARN)
	if err != nil {
		t.Errorf("Did not get policy str content %s, got errror %s", p, err)
	}
	content, err := parsePolicy(p)
	//We should not error out
	if err != nil{
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
	//Given config of proxysts is set
	BindEnvVariables("proxysts")
	initializePolicyManager()

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

	defer f.Close()
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

	var policyManagerKnowsPolicyDoesNotExist predicateFunction = func () bool{
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

	var policyManagerSeesUpdate predicateFunction = func () bool{
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
