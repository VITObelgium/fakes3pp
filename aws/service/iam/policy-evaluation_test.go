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

// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
// If the key that you specify in a policy condition is not present in the request context, the values do not match
// and the condition is false. If the policy condition requires that the key is not matched, such as StringNotLike
// or ArnNotLike, and the right key is not present, the condition is true. This logic applies to all condition
// operators except ...IfExists and Null check. These operators test whether the key is present (exists) in the request context.
// So for testDenyUnlessUserIdTagSpecified is aws:PrincipalTag/user_id is not present the condition is true and explicit deny => "A wildcard matches any value as long as the value is provided: scenario no value provided"
//
//	but if aws:PrincipalTag/user_id is present the condition is always false because we match with wildcard we should get allow => "A wildcard matches any value as long as the value is provided: scenario a value provided"
var testDenyUnlessUserIdTagSpecified = `
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
                    "aws:PrincipalTag/user_id": ["*"]
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
				Action:   actionnames.IAMActionS3PutObject,
				Resource: fmt.Sprintf("%s/my_object", allowedWriteARNStart),
			},
			true,
			reasonActionIsAllowed,
		},
		{
			"A PutObject in an not allowed prefix shouldn't be allowed",
			testPolScen1AllowPutWithinPrefix,
			IAMAction{
				Action:   actionnames.IAMActionS3PutObject,
				Resource: fmt.Sprintf("%s/my_object", notAllowedARNStart),
			},
			false,
			reasonNoStatementAllowingAction,
		},
		{
			"A GetObject is not allowed as we only allow puts in our policy",
			testPolScen1AllowPutWithinPrefix,
			IAMAction{
				Action:   actionnames.IAMActionS3GetObject,
				Resource: fmt.Sprintf("%s/my_object", allowedWriteARNStart),
			},
			false,
			reasonNoStatementAllowingAction,
		},
		{
			"A listBucket is allowed if it is under the conditioned prefix",
			testPolScen2AllowListingBucketWithinPrefix,
			IAMAction{
				Action:   actionnames.IAMActionS3ListBucket,
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
				Action:   actionnames.IAMActionS3ListBucket,
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
				Action:   actionnames.IAMActionS3ListBucket,
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
				Action:   actionnames.IAMActionS3ListBucket,
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
						Issuer:  "specificissuer",
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
						Issuer:  "specificissuer",
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
						Issuer:  "specificissuer",
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
						Issuer:  "other-issuer",
					},
				},
			),
			false,
			reasonExplicitDeny,
		},
		{
			"A wildcard matches any value as long as the value is provided: scenario no value provided",
			testDenyUnlessUserIdTagSpecified,
			NewIamAction(
				actionnames.IAMActionS3GetObject,
				testBucketARN,
				&PolicySessionData{
					Claims: PolicySessionClaims{
						Subject: "master",
						Issuer:  "other-issuer",
					},
				},
			),
			false,
			reasonExplicitDeny,
		},
		{
			"A wildcard matches any value as long as the value is provided: scenario a value provided",
			testDenyUnlessUserIdTagSpecified,
			NewIamAction(
				actionnames.IAMActionS3GetObject,
				testBucketARN,
				&PolicySessionData{
					Claims: PolicySessionClaims{
						Subject: "master",
						Issuer:  "other-issuer",
					},
					Tags: session.AWSSessionTags{
						PrincipalTags: map[string][]string{"user_id": {"user-1"}},
					},
				},
			),
			true,
			reasonActionIsAllowed,
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

func TestStringEqualsInPolicyEvaluation(t *testing.T) {
	const polAllowIfExactOrg = `
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": ["*"],
			"Resource": "*",
			"Condition": {
				"StringEquals": {
					"aws:PrincipalTag/org": ["team-*"]
				}
			}
		}
	]
}`
	tests := []struct {
		description string
		action      IAMAction
		want        bool
	}{
		{
			"exact match allows",
			NewIamAction("s3:GetObject", "*", &PolicySessionData{
				Tags: session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"team-*"}}},
			}),
			true,
		},
		{
			"different value does not allow",
			NewIamAction("s3:GetObject", "*", &PolicySessionData{
				Tags: session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"team-b"}}},
			}),
			false,
		},
		{
			"wildcard in value is treated literally by StringEquals",
			NewIamAction("s3:GetObject", "*", &PolicySessionData{
				Tags: session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"team-a"}}},
			}),
			false,
		},
		{
			"missing key does not allow",
			NewIamAction("s3:GetObject", "*", &PolicySessionData{}),
			false,
		},
	}

	pe, err := NewPolicyEvaluatorFromStr(polAllowIfExactOrg)
	if err != nil {
		t.Fatalf("could not build evaluator: %s", err)
	}
	for _, tc := range tests {
		allowed, _, err := pe.Evaluate(tc.action)
		if err != nil {
			t.Errorf("%s: unexpected error: %s", tc.description, err)
		}
		if allowed != tc.want {
			t.Errorf("%s: want %v got %v", tc.description, tc.want, allowed)
		}
	}
}

func TestEvalConditionBlock(t *testing.T) {
	tests := []struct {
		description    string
		conditionBlock map[string]map[string]*policy.ConditionValue
		context        map[string]*policy.ConditionValue
		want           bool
		wantErr        bool
	}{
		{
			"StringEquals matches",
			map[string]map[string]*policy.ConditionValue{
				"StringEquals": {"claims:sub": policy.NewConditionValueString(true, "alice")},
			},
			map[string]*policy.ConditionValue{
				"claims:sub": policy.NewConditionValueString(true, "alice"),
			},
			true, false,
		},
		{
			"StringEquals no match",
			map[string]map[string]*policy.ConditionValue{
				"StringEquals": {"claims:sub": policy.NewConditionValueString(true, "alice")},
			},
			map[string]*policy.ConditionValue{
				"claims:sub": policy.NewConditionValueString(true, "bob"),
			},
			false, false,
		},
		{
			"StringLike wildcard matches",
			map[string]map[string]*policy.ConditionValue{
				"StringLike": {"claims:sub": policy.NewConditionValueString(true, "team-*")},
			},
			map[string]*policy.ConditionValue{
				"claims:sub": policy.NewConditionValueString(true, "team-alpha"),
			},
			true, false,
		},
		{
			"multiple operators all must match",
			map[string]map[string]*policy.ConditionValue{
				"StringEquals": {"claims:sub": policy.NewConditionValueString(true, "alice")},
				"StringLike":   {"claims:iss": policy.NewConditionValueString(true, "https://issuer.*")},
			},
			map[string]*policy.ConditionValue{
				"claims:sub": policy.NewConditionValueString(true, "alice"),
				"claims:iss": policy.NewConditionValueString(true, "https://issuer.example"),
			},
			true, false,
		},
		{
			"multiple operators one fails",
			map[string]map[string]*policy.ConditionValue{
				"StringEquals": {"claims:sub": policy.NewConditionValueString(true, "alice")},
				"StringLike":   {"claims:iss": policy.NewConditionValueString(true, "https://other.*")},
			},
			map[string]*policy.ConditionValue{
				"claims:sub": policy.NewConditionValueString(true, "alice"),
				"claims:iss": policy.NewConditionValueString(true, "https://issuer.example"),
			},
			false, false,
		},
		{
			"nil condition block (default rule) always matches",
			nil,
			map[string]*policy.ConditionValue{
				"claims:sub": policy.NewConditionValueString(true, "anyone"),
			},
			true, false,
		},
		{
			"empty condition block matches",
			map[string]map[string]*policy.ConditionValue{},
			map[string]*policy.ConditionValue{},
			true, false,
		},
		{
			"unsupported operator returns error",
			map[string]map[string]*policy.ConditionValue{
				"NumericEquals": {"aws:RequestedRegion": policy.NewConditionValueString(true, "eu-west-1")},
			},
			map[string]*policy.ConditionValue{
				"aws:RequestedRegion": policy.NewConditionValueString(true, "eu-west-1"),
			},
			false, true,
		},
	}

	for _, tc := range tests {
		got, err := EvalConditionBlock(tc.conditionBlock, tc.context)
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected error but got none", tc.description)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: unexpected error: %s", tc.description, err)
		}
		if got != tc.want {
			t.Errorf("%s: want %v got %v", tc.description, tc.want, got)
		}
	}
}
