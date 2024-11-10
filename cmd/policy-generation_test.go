package cmd

import (
	"fmt"
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
						"s3:prefix": "{{.Claims.Issuer}}/*" 
					}
				} 
			}
		]
	}
`

func NewTestPolicyRetriever() *TestPolicyRetriever {
	return &TestPolicyRetriever{
		testPolicies: map[string]string{
			"policyRealistic": testPolicyRealistic,
		},
	}
}

func NewTestPolicyManager() *PolicyManager {
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
	Claims         policyTemplateData
	Expectedpolicy string
}

func TestPolicyGeneration(t *testing.T) {
	testCases := []policyGenerationTestCase{
		{
			PolicyName: "policyRealistic",
			Claims:     policyTemplateData{Claims: map[string]string{"Issuer": "https://SuperIssuer"}},
			Expectedpolicy: strings.Replace(testPolicyRealistic, "{{.Claims.Issuer}}", "https://SuperIssuer", -1),
		},
		{
			PolicyName: "now",
			Claims:     policyTemplateData{Claims: map[string]string{}},
			Expectedpolicy: YYYYmmdd(Now()),
		},
		{
			PolicyName: "nowSlashed",
			Claims:     policyTemplateData{Claims: map[string]string{}},
			Expectedpolicy: YYYYmmddSlashed(Now()),
		},
		{
			PolicyName: "tomorrow",
			Claims:     policyTemplateData{Claims: map[string]string{}},
			Expectedpolicy: YYYYmmdd(Now().Add(time.Hour * 24)),
		},
		{
			PolicyName: "sha1",
			Claims:     policyTemplateData{Claims: map[string]string{"Issuer": "a", "Subject": "b"}},
			Expectedpolicy: sha1sum("a:b"),
		},
	}

	tpm := NewTestPolicyManager()

	for _, tc := range testCases {
		got, err := tpm.GetPolicy(tc.PolicyName, tc.Claims)
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