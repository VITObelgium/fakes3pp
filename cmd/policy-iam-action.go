package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/micahhausler/aws-iam-policy/policy"
)

type iamAction struct{
	Action string          `json:"action"`
	Resource string        `json:"resource"`
	Context map[string]*policy.ConditionValue `json:"context,omitempty"`
}

func newIamAction(action, resource string, session *PolicySessionData) iamAction{
	context := map[string]*policy.ConditionValue{}
	addGenericSessionContextKeys(context, session)

	return iamAction{
		Action: action,
		Resource: resource,
		Context: context,
	}
}

// For a given IAM action add context specific for the action
func (a iamAction) addContext(context map[string]*policy.ConditionValue) (iamAction){
	for contextKey, ContextKeyValues := range context {
		a.Context[contextKey] = ContextKeyValues
	}
	return a
}

func makeS3BucketArn(bucketName string) string {
	return fmt.Sprintf("arn:aws:s3:::%s", bucketName)
}

func makeS3ObjectArn(bucketName, objectKey string) string {
	return fmt.Sprintf("%s/%s", makeS3BucketArn(bucketName), objectKey)
}

func getS3ObjectFromRequest(req *http.Request) (bucketName string, objectKey string, err error) {
	hostWithoutPort := strings.Split(req.Host, ":")[0]
	if isAS3ProxyFQDN(hostWithoutPort) {
		//Path-style request
		if !strings.HasPrefix(req.URL.Path, "/") {
			return "", "", fmt.Errorf("request uri did not start with '/': %s", req.RequestURI)
		}
		string_parts := strings.Split(req.URL.Path[1:], "/")
		bucketName = string_parts[0]
		objectKey := strings.Join(string_parts[1:], "/")
		return bucketName, objectKey, nil
	} else {
		//Virtual hosting
		return "", "", errors.New("virtual hosting not supported try path-style request")
	}
}

//Add context keys that are added to nearly all requests that contain information about the current session
func addGenericSessionContextKeys(context map[string]*policy.ConditionValue, session *PolicySessionData) {
	addAwsPrincipalTagConditionKeys(context, session)
	addAwsRequestedRegionConditionKey(context, session)
}

//Add aws:PrincipalTag/tag-key keys that are added to nearly all requests that contain information about the current session
//https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principaltag
func addAwsPrincipalTagConditionKeys(context map[string]*policy.ConditionValue, session *PolicySessionData) {
	if session == nil {
		return
	}
	for tagKey, tagValues := range session.Tags.PrincipalTags {
		context[fmt.Sprintf("aws:PrincipalTag/%s", tagKey)] = policy.NewConditionValueString(true, tagValues...)
	}
}

//Add aws:RequestedRegion key that are added to all requests
//https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-requested-region.html
func addAwsRequestedRegionConditionKey(context map[string]*policy.ConditionValue, session *PolicySessionData) {
	if session == nil {
		return
	}
	if session.RequestedRegion != "" {
		context["aws:RequestedRegion"] = policy.NewConditionValueString(true, session.RequestedRegion)
	}
}

//Buid a new IAM action based out of an HTTP Request. The IAM action should resemble the required
//Permissions. The api_action is passed in as a string argument
func newIamActionsFromS3Request(api_action S3ApiAction, req *http.Request, session *PolicySessionData) (actions []iamAction, err error) {
	actions = []iamAction{}
	switch api_action {
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
	case apiS3PutObject, apiS3CreateMultipartUpload, apiS3CompleteMultipartUpload, apiS3UploadPart:
		bucket, key, err := getS3ObjectFromRequest(req)
		if err != nil {
			return nil, err
		}
		a := newIamAction(
			IAMActionS3PutObject,
			makeS3ObjectArn(bucket, key),
			session,
		)
		actions = append(actions, a)
	case apiS3GetObject, apiS3HeadObject:
		bucket, key, err := getS3ObjectFromRequest(req)
		if err != nil {
			return nil, err
		}
		a := newIamAction(
			IAMActionS3GetObject,
			makeS3ObjectArn(bucket, key),
			session,
		)
		actions = append(actions, a)
	case apiS3ListObjectsV2:
		bucket, _, err := getS3ObjectFromRequest(req)
		if err != nil {
			return nil, err
		}
		a := newIamAction(
			IAMActionS3ListBucket,
			makeS3BucketArn(bucket),
			session,
		).addContext(
			map[string]*policy.ConditionValue{
				IAMConditionS3Prefix: policy.NewConditionValueString(true, req.URL.Query().Get("prefix")),
			},
		)
		actions = append(actions, a)
	case apiS3AbortMultipartUpload:
		bucket, key, err := getS3ObjectFromRequest(req)
		if err != nil {
			return nil, err
		}
		a := newIamAction(
			IAMActionS3AbortMultipartUpload,
			makeS3ObjectArn(bucket, key),
			session,
		)
		actions = append(actions, a)
	case apiS3ListBuckets:
		a := newIamAction(
			IAMActionS3ListAllMyBuckets,
			"*",  //Can only be granted on *
			session,
		)
		actions = append(actions, a)
	default:
		return nil, errors.New("cannot get IAM actions due to unsupported api action")
	}
	return actions, nil
}