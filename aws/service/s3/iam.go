package s3

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	"github.com/VITObelgium/fakes3pp/aws/service/iam/actionnames"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/api"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/micahhausler/aws-iam-policy/policy"
)

func makeS3BucketArn(bucketName string) string {
	return fmt.Sprintf("arn:aws:s3:::%s", bucketName)
}

func makeS3ObjectArn(bucketName, objectKey string) string {
	return fmt.Sprintf("%s/%s", makeS3BucketArn(bucketName), objectKey)
}

func getS3ObjectFromRequest(req *http.Request, vhi interfaces.VirtualHosterIdentifier) (bucketName string, objectKey string, err error) {
	if vhi.IsVirtualHostingRequest(req) {
		return "", "", errors.New("virtual hosting not supported try path-style request")
	} else {
		//Path-style request
		if !strings.HasPrefix(req.URL.Path, "/") {
			return "", "", fmt.Errorf("request uri did not start with '/': %s", req.RequestURI)
		}
		string_parts := strings.Split(req.URL.Path[1:], "/")
		bucketName = string_parts[0]
		objectKey := strings.Join(string_parts[1:], "/")
		return bucketName, objectKey, nil
	}
}

//Buid a new IAM action based out of an HTTP Request. The IAM action should resemble the required
//Permissions. The api_action is passed in as a string argument
func newIamActionsFromS3Request(api_action api.S3Operation, req *http.Request, session *iam.PolicySessionData, vhi interfaces.VirtualHosterIdentifier) (actions []iam.IAMAction, err error) {
	actions = []iam.IAMAction{}
	switch api_action {
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
	case api.PutObject, api.CreateMultipartUpload, api.CompleteMultipartUpload, api.UploadPart:
		bucket, key, err := getS3ObjectFromRequest(req, vhi)
		if err != nil {
			return nil, err
		}
		a :=iam.NewIamAction(
			actionnames.IAMActionS3PutObject,
			makeS3ObjectArn(bucket, key),
			session,
		)
		actions = append(actions, a)
	case api.GetObject, api.HeadObject:
		bucket, key, err := getS3ObjectFromRequest(req, vhi)
		if err != nil {
			return nil, err
		}
		a := iam.NewIamAction(
			actionnames.IAMActionS3GetObject,
			makeS3ObjectArn(bucket, key),
			session,
		)
		actions = append(actions, a)
	case api.ListObjectsV2:
		bucket, _, err := getS3ObjectFromRequest(req, vhi)
		if err != nil {
			return nil, err
		}
		a := iam.NewIamAction(
			actionnames.IAMActionS3ListBucket,
			makeS3BucketArn(bucket),
			session,
		).AddContext(
			map[string]*policy.ConditionValue{
				actionnames.IAMConditionS3Prefix: policy.NewConditionValueString(true, req.URL.Query().Get("prefix")),
			},
		)
		actions = append(actions, a)
	case api.AbortMultipartUpload:
		bucket, key, err := getS3ObjectFromRequest(req, vhi)
		if err != nil {
			return nil, err
		}
		a := iam.NewIamAction(
			actionnames.IAMActionS3AbortMultipartUpload,
			makeS3ObjectArn(bucket, key),
			session,
		)
		actions = append(actions, a)
	case api.ListBuckets:
		a := iam.NewIamAction(
			actionnames.IAMActionS3ListAllMyBuckets,
			"*",  //Can only be granted on *
			session,
		)
		actions = append(actions, a)
	default:
		return nil, errors.New("cannot get IAM actions due to unsupported api action")
	}
	return actions, nil
}