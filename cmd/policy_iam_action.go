package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/micahhausler/aws-iam-policy/policy"
	"github.com/spf13/viper"
)

type iamAction struct{
	Action string          `json:"action"`
	Resource string        `json:"resource"`
	Context map[string]*policy.ConditionValue `json:"context,omitempty"`
}

func NewIamAction(action, resource string, context map[string]*policy.ConditionValue) iamAction{
	return iamAction{
		Action: action,
		Resource: resource,
		Context: context,
	}
}

func makeS3BucketArn(bucketName string) string {
	return fmt.Sprintf("arn:aws:s3:::%s", bucketName)
}

func makeS3ObjectArn(bucketName, objectKey string) string {
	return fmt.Sprintf("%s/%s", makeS3BucketArn(bucketName), objectKey)
}

func getS3ObjectFromRequest(req *http.Request) (bucketName string, objectKey string, err error) {
	fqdn := viper.GetString(s3ProxyFQDN)
	if strings.HasPrefix(req.Host, fqdn) {
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
		return "", "", errors.New("virtual hosting requests not implemented")
	}
}

//Buid a new IAM action based out of an HTTP Request. The IAM action should resemble the required
//Permissions. The api_action is passed in as a string argument
func NewIamActionsFromS3Request(api_action S3ApiAction, req *http.Request) (actions []iamAction, err error) {
	actions = []iamAction{}
	switch api_action {
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
	case apiS3PutObject, apiS3CreateMultipartUpload, apiS3CompleteMultipartUpload, apiS3UploadPart:
		bucket, key, err := getS3ObjectFromRequest(req)
		if err != nil {
			return nil, err
		}
		a := iamAction{
			Action: IAMActionS3PutObject,
			Resource: makeS3ObjectArn(bucket, key),
		}
		actions = append(actions, a)
	case apiS3GetObject, apiS3HeadObject:
		bucket, key, err := getS3ObjectFromRequest(req)
		if err != nil {
			return nil, err
		}
		a := iamAction{
			Action: IAMActionS3GetObject,
			Resource: makeS3ObjectArn(bucket, key),
		}
		actions = append(actions, a)
	case apiS3ListObjectsV2:
		bucket, _, err := getS3ObjectFromRequest(req)
		if err != nil {
			return nil, err
		}
		a := iamAction{
			Action: IAMActionS3ListBucket,
			Resource: makeS3BucketArn(bucket),
			Context: map[string]*policy.ConditionValue{
				IAMConditionS3Prefix: policy.NewConditionValueString(true, req.URL.Query().Get("prefix")),
			},
		}
		actions = append(actions, a)
	case apiS3AbortMultipartUpload:
		bucket, key, err := getS3ObjectFromRequest(req)
		if err != nil {
			return nil, err
		}
		a := iamAction{
			Action: IAMActionS3AbortMultipartUpload,
			Resource: makeS3ObjectArn(bucket, key),
		}
		actions = append(actions, a)
	case apiS3ListBuckets:
		a := iamAction{
			Action: IAMActionS3ListAllMyBuckets,
			Resource: "*",  //Can only be granted on *
		}
		actions = append(actions, a)
	default:
		return nil, errors.New("cannot get IAM actions due to unsupported api action")
	}
	return actions, nil
}