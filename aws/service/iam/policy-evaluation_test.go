package iam

import (
	"fmt"
	"testing"

	"github.com/VITObelgium/fakes3pp/aws/service/iam/actionnames"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/micahhausler/aws-iam-policy/policy"
)


var testBucketName = "bucket1"
const testAllowedPrefix = "okprefix/"
const testAllowedPrefix2 = "okprefix2/"
var testBucketARN = fmt.Sprintf("arn:aws:s3:::%s", testBucketName)

var allowedWriteARNStart = fmt.Sprintf("%s/%s", testBucketARN, testAllowedPrefix)
var testNotAllowedPrefix = "notokprefix/"
var notAllowedARNStart = fmt.Sprintf("%s/%s", testBucketARN, testNotAllowedPrefix)
var allowedWriteARN = fmt.Sprintf("%s*", allowedWriteARNStart)
var testPolScen1AllowPutWithinPrefix = fmt.Sprintf(`
{
	"Version": "2012-10-17",
	"Statement": [
        {
			"Sid": "Allow to put objects under a prefix",
			"Effect": "Allow",
			"Action": [
				"%s"
			],
			"Resource": "%s"
          } 
	]
}
`, actionnames.IAMActionS3PutObject, allowedWriteARN)


var testPolScen2AllowListingBucketWithinPrefix = fmt.Sprintf(`
{
	"Version": "2012-10-17",
	"Statement": [
        {
			"Sid": "Allow to list objects under a prefix",
			"Effect": "Allow",
			"Action": [
				"%s"
			],
			"Resource": "%s",
			"Condition" : {
                "StringLike" : {
                    "s3:prefix": "%s*" 
                }
            } 
          } 
	]
}
`, actionnames.IAMActionS3ListBucket, testBucketARN, testAllowedPrefix)

var testPolScen2AllowListingBucketWithinPrefixes = fmt.Sprintf(`
{
	"Version": "2012-10-17",
	"Statement": [
        {
			"Sid": "Allow to list objects under a prefix",
			"Effect": "Allow",
			"Action": [
				"%s"
			],
			"Resource": "%s",
			"Condition" : {
                "StringLike" : {
                    "s3:prefix": ["%s*", "%s*"] 
                }
            } 
          } 
	]
}
`, actionnames.IAMActionS3ListBucket, testBucketARN, testAllowedPrefix, testAllowedPrefix2)

var testPolAllowAllIfTestDepartmentOtherwiseDenyAll = `
{
	"Version": "2012-10-17",
	"Statement": [
        {
			"Sid": "Allow all if test department",
			"Effect": "Allow",
			"Action": [
				"*"
			],
			"Resource": "*",
			"Condition" : {
                "StringLike" : {
                    "aws:PrincipalTag/department": "test" 
                }
            } 
        },
		{
			"Sid": "Deny all if not test department",
			"Effect": "Deny",
			"Action": [
				"*"
			],
			"Resource": "*",
			"Condition" : {
                "StringNotLike" : {
                    "aws:PrincipalTag/department": "test" 
                }
            } 
        } 
	]
}
`

var testDenyAllUnlessMasterAsSubject = `
{
	"Version": "2012-10-17",
	"Statement": [
        {
			"Sid": "Allow all if test department",
			"Effect": "Allow",
			"Action": [
				"*"
			],
			"Resource": "*"
        },
		{
			"Sid": "Deny all",
			"Effect": "Deny",
			"Action": [
				"*"
			],
			"Resource": "*",
			"Condition" : {
                "StringNotLike" : {
                    "claims:sub": "master" 
                }
            } 
        } 
	]
}
`

var testDenyAllUnlessSpecificIssuer = `
{
	"Version": "2012-10-17",
	"Statement": [
        {
			"Sid": "Allow all if test department",
			"Effect": "Allow",
			"Action": [
				"*"
			],
			"Resource": "*"
        },
		{
			"Sid": "Deny all",
			"Effect": "Deny",
			"Action": [
				"*"
			],
			"Resource": "*",
			"Condition" : {
                "StringNotLike" : {
                    "claims:iss": "specificissuer" 
                }
            } 
        } 
	]
}
`

var testSessionDataTestDepartment = &PolicySessionData{
	Claims: PolicySessionClaims{},
	Tags: session.AWSSessionTags{
		PrincipalTags: map[string][]string{
			"department": {"test"},
		},
		TransitiveTagKeys: []string{"department"},
	},
}

var testSessionDataQaDeparment = &PolicySessionData{
	Claims: PolicySessionClaims{},
	Tags: session.AWSSessionTags{
		PrincipalTags: map[string][]string{
			"department": {"qa"},
		},
		TransitiveTagKeys: []string{"department"},
	},
}

func TestPolicyEvaluations(t *testing.T) {
	policyTests := []struct {
        Description     string 
		PolicyString    string
		Action          IAMAction
		ShouldBeAllowed bool
		ExpectedReason  evalReason
	}{
		{
			"A PutObject in an allowed prefix should be allowed",
			testPolScen1AllowPutWithinPrefix,
			IAMAction{
				Action: actionnames.IAMActionS3PutObject,
				Resource: fmt.Sprintf("%s/my_object", allowedWriteARNStart),
			},
			true,
			reasonActionIsAllowed,
		},
		{
			"A PutObject in an not allowed prefix shouldn't be allowed",
			testPolScen1AllowPutWithinPrefix,
			IAMAction{
				Action: actionnames.IAMActionS3PutObject,
				Resource: fmt.Sprintf("%s/my_object", notAllowedARNStart),
			},
			false,
			reasonNoStatementAllowingAction,
		},
		{
			"A GetObject is not allowed as we only allow puts in our policy",
			testPolScen1AllowPutWithinPrefix,
			IAMAction{
				Action: actionnames.IAMActionS3GetObject,
				Resource: fmt.Sprintf("%s/my_object", allowedWriteARNStart),
			},
			false,
			reasonNoStatementAllowingAction,
		},
		{
			"A listBucket is allowed if it is under the conditioned prefix",
			testPolScen2AllowListingBucketWithinPrefix,
			IAMAction{
				Action: actionnames.IAMActionS3ListBucket,
				Resource: testBucketARN,
				Context: map[string]*policy.ConditionValue{
					actionnames.IAMConditionS3Prefix: policy.NewConditionValueString(true, fmt.Sprintf("%ssubprefix/", testAllowedPrefix)),
				},
			},
			true,
			reasonActionIsAllowed,
		},
		{
			"A listBucket is not allowed if it is without prefix but policy does specify a conditioned prefix",
			testPolScen2AllowListingBucketWithinPrefix,
			IAMAction{
				Action: actionnames.IAMActionS3ListBucket,
				Resource: testBucketARN,
				Context: map[string]*policy.ConditionValue{
					actionnames.IAMConditionS3Prefix: policy.NewConditionValueString(true, ""),
				},
			},
			false,
			reasonNoStatementAllowingAction,
		},
		{
			"A listBucket is allowed if it is under the conditioned prefix with multiple prefixes (prefix1)",
			testPolScen2AllowListingBucketWithinPrefixes,
			IAMAction{
				Action: actionnames.IAMActionS3ListBucket,
				Resource: testBucketARN,
				Context: map[string]*policy.ConditionValue{
					actionnames.IAMConditionS3Prefix: policy.NewConditionValueString(true, fmt.Sprintf("%ssubprefix/", testAllowedPrefix)),
				},
			},
			true,
			reasonActionIsAllowed,
		},
		{
			"A listBucket is allowed if it is under the conditioned prefix with multiple prefixes (prefix2)",
			testPolScen2AllowListingBucketWithinPrefixes,
			IAMAction{
				Action: actionnames.IAMActionS3ListBucket,
				Resource: testBucketARN,
				Context: map[string]*policy.ConditionValue{
					actionnames.IAMConditionS3Prefix: policy.NewConditionValueString(true, fmt.Sprintf("%ssubprefix/", testAllowedPrefix2)),
				},
			},
			true,
			reasonActionIsAllowed,
		},
		{
			"Any action should be allowed if we run with test department session tag",
			testPolAllowAllIfTestDepartmentOtherwiseDenyAll,
			NewIamAction(
				actionnames.IAMActionS3GetObject,
				testBucketARN,
				testSessionDataTestDepartment,
			),
			true,
			reasonActionIsAllowed,
		},
		{
			"Any action should be allowed if we run with test department session tag 2",
			testPolAllowAllIfTestDepartmentOtherwiseDenyAll,
			NewIamAction(
				actionnames.IAMActionS3ListAllMyBuckets,
				testBucketARN,
				testSessionDataTestDepartment,
			),
			true,
			reasonActionIsAllowed,
		},
		{
			"Any action should be disallowed if we run with deparment session tag different from test",
			testPolAllowAllIfTestDepartmentOtherwiseDenyAll,
			NewIamAction(
				actionnames.IAMActionS3GetObject,
				testBucketARN,
				testSessionDataQaDeparment,
			),
			false,
			reasonExplicitDeny,
		},
		{
			"An explicit deny takes precendence and claims:sub conditions should evaluate correctly master",
			testDenyAllUnlessMasterAsSubject,
			NewIamAction(
				actionnames.IAMActionS3GetObject,
				testBucketARN,
				&PolicySessionData{
					Claims: PolicySessionClaims{
						Subject: "master",
						Issuer: "specificissuer",
					},
				},
			),
			true,
			reasonActionIsAllowed,
		},
		{
			"An explicit deny takes precendence and claims:sub conditions should evaluate correctly non-master",
			testDenyAllUnlessMasterAsSubject,
			NewIamAction(
				actionnames.IAMActionS3GetObject,
				testBucketARN,
				&PolicySessionData{
					Claims: PolicySessionClaims{
						Subject: "dobby",
						Issuer: "specificissuer",
					},
				},
			),
			false,
			reasonExplicitDeny,
		},
		{
			"An explicit deny takes precendence and claims:issuer conditions should evaluate correctly specific-issuer",
			testDenyAllUnlessSpecificIssuer,
			NewIamAction(
				actionnames.IAMActionS3GetObject,
				testBucketARN,
				&PolicySessionData{
					Claims: PolicySessionClaims{
						Subject: "master",
						Issuer: "specificissuer",
					},
				},
			),
			true,
			reasonActionIsAllowed,
		},
		{
			"An explicit deny takes precendence and claims:sub conditions should evaluate correctly other-issuer",
			testDenyAllUnlessSpecificIssuer,
			NewIamAction(
				actionnames.IAMActionS3GetObject,
				testBucketARN,
				&PolicySessionData{
					Claims: PolicySessionClaims{
						Subject: "master",
						Issuer: "other-issuer",
					},
				},
			),
			false,
			reasonExplicitDeny,
		},
	}

	for _, policyTest := range policyTests {
		pe, err := NewPolicyEvaluatorFromStr(policyTest.PolicyString)
		if err != nil {
			t.Errorf("%s: Could not create PolicyEvaluator due to %s for: %s", policyTest.Description, err, policyTest.PolicyString)
		}
		allowed, reason, err := pe.Evaluate(policyTest.Action)
		if err != nil {
			t.Errorf("got error when evaluating policy: %s", err)
		}
		if allowed != policyTest.ShouldBeAllowed {
			t.Errorf("%s: Expected '%t' got '%t'", policyTest.Description, policyTest.ShouldBeAllowed, allowed)
		}
		if reason != policyTest.ExpectedReason {
			t.Errorf("%s: Expected '%s' got '%s'", policyTest.Description, policyTest.ExpectedReason, reason)
		}
	}
	
}
