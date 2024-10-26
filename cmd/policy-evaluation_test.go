package cmd

import (
	"fmt"
	"testing"

	"github.com/micahhausler/aws-iam-policy/policy"
)


var testBucketName = "bucket1"
const testAllowedPrefix = "okprefix/"
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
`, IAMActionS3PutObject, allowedWriteARN)


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
`, IAMActionS3ListBucket, testBucketARN, testAllowedPrefix)




func TestPolicyEvaluations(t *testing.T) {
	policyTests := []struct {
        Description     string 
		PolicyString    string
		Action          iamAction
		ShouldBeAllowed bool
		ExpectedReason  evalReason
	}{
		{
			"A PutObject in an allowed prefix should be allowed",
			testPolScen1AllowPutWithinPrefix,
			iamAction{
				Action: IAMActionS3PutObject,
				Resource: fmt.Sprintf("%s/my_object", allowedWriteARNStart),
			},
			true,
			reasonActionIsAllowed,
		},
		{
			"A PutObject in an not allowed prefix shouldn't be allowed",
			testPolScen1AllowPutWithinPrefix,
			iamAction{
				Action: IAMActionS3PutObject,
				Resource: fmt.Sprintf("%s/my_object", notAllowedARNStart),
			},
			false,
			reasonNoStatementAllowingAction,
		},
		{
			"A GetObject is not allowed as we only allow puts in our policy",
			testPolScen1AllowPutWithinPrefix,
			iamAction{
				Action: IAMActionS3GetObject,
				Resource: fmt.Sprintf("%s/my_object", allowedWriteARNStart),
			},
			false,
			reasonNoStatementAllowingAction,
		},
		{
			"A listBucket is allowed if it is under the conditioned prefix",
			testPolScen2AllowListingBucketWithinPrefix,
			iamAction{
				Action: IAMActionS3ListBucket,
				Resource: testBucketARN,
				Context: map[string]*policy.ConditionValue{
					IAMConditionS3Prefix: policy.NewConditionValueString(true, fmt.Sprintf("%ssubprefix/", testAllowedPrefix)),
				},
			},
			true,
			reasonActionIsAllowed,
		},
		{
			"A listBucket is not allowed if it is without prefix but policy does specify a conditioned prefix",
			testPolScen2AllowListingBucketWithinPrefix,
			iamAction{
				Action: IAMActionS3ListBucket,
				Resource: testBucketARN,
				Context: map[string]*policy.ConditionValue{
					IAMConditionS3Prefix: policy.NewConditionValueString(true, ""),
				},
			},
			false,
			reasonNoStatementAllowingAction,
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
