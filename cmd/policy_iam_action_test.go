package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	sg "github.com/aws/smithy-go"
	"github.com/micahhausler/aws-iam-policy/policy"
)

type StubJustReturnIamAction struct{
	t *testing.T
}

func (p *StubJustReturnIamAction) Build(action S3ApiAction, presigned bool) http.HandlerFunc{
	return func (w http.ResponseWriter, r *http.Request)  {
		actions, err := NewIamActionsFromS3Request(action, r)
		if err != nil {
			p.t.Error(err)
			return
		}
		bytes, err := json.Marshal(actions)
		if err != nil {
			p.t.Error(err)
			return
		}
		//AWS CLI expects certain structure for ok responses
		//For error we could use the message field to pass a message regardless
		//of the api action. This works often quite well but some operations 
		//intervene client-side of the SDK
		writeS3ErrorResponse(
			buildContextWithRequestID(r),
			w,
			ErrS3AccessDenied,
			errors.New(string(bytes)),
		)
	}
}

func newStubJustReturnIamAction(ti *testing.T) handlerBuilderI {
	var testStub = StubJustReturnIamAction{
		t: ti,
	}
	return &testStub
}


func getAnonymousS3TestClient(t *testing.T) (client *s3.Client, ctx context.Context, cancel context.CancelFunc) {
	cfg := getTestAwsConfig(t)

	endpoint := getS3ProxyUrl()
	client = s3.NewFromConfig(cfg, func (o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.Region = "eu-central-1"
		o.Credentials = aws.AnonymousCredentials{}
		o.UsePathStyle = true //To avoid s3.localhost see https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html
	})
	ctx, cancel = context.WithTimeout(context.Background(), 1000 * time.Second)
	return
}

func runListObjectsV2AndReturnError(t *testing.T) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t)

	input := s3.ListObjectsV2Input{
		Bucket: &testBucketName,
	}
	defer cancel()
	_, err := client.ListObjectsV2(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

var listobjectv2_test_prefix string = "my-prefix"

func runListObjectsV2WithPrefixAndReturnError(t *testing.T) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t)

	input := s3.ListObjectsV2Input{
		Bucket: &testBucketName,
		Prefix: &listobjectv2_test_prefix,
	}
	defer cancel()
	_, err := client.ListObjectsV2(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runListBucketsAndReturnError(t *testing.T) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t)

	input := s3.ListBucketsInput{}
	defer cancel()
	_, err := client.ListBuckets(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

var putObjectTestKey string = "my/test/key"
var putObjectFullObjectARN string = fmt.Sprintf("%s/%s", testBucketARN, putObjectTestKey)

func runPutObjectAndReturnError(t *testing.T) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t)

	input := s3.PutObjectInput{
		Bucket: &testBucketName,
		Key: &putObjectTestKey,
		Body: bytes.NewReader([]byte("This is a test")),
	}
	defer cancel()
	_, err := client.PutObject(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runGetObjectAndReturnError(t *testing.T) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t)

	input := s3.GetObjectInput{
		Bucket: &testBucketName,
		Key: &putObjectTestKey,
	}
	defer cancel()
	_, err := client.GetObject(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

// TODO: Check how to get this under test coverage
// func runHeadObjectAndReturnError(t *testing.T) error {
// 	client, max1Sec, cancel := getAnonymousS3TestClient(t)

// 	input := s3.HeadObjectInput{
// 		Bucket: &testBucketName,
// 		Key: &putObjectTestKey,
// 	}
// 	defer cancel()
// 	_, err := client.HeadObject(max1Sec, &input)
// 	if err == nil {
// 		t.Error("Should have encountered error but did not")
// 	}
// 	return err
// }

func runAbortMultipartUploadAndReturnError(t *testing.T) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t)
	testId := "Thisisjustastringfortesting"
	input := s3.AbortMultipartUploadInput{
		Bucket: &testBucketName,
		Key: &putObjectTestKey,
		UploadId: &testId,
	}
	defer cancel()
	_, err := client.AbortMultipartUpload(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runCreateMultipartUploadAndReturnError(t *testing.T) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t)

	input := s3.CreateMultipartUploadInput{
		Bucket: &testBucketName,
		Key: &putObjectTestKey,
	}
	defer cancel()
	_, err := client.CreateMultipartUpload(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runCompleteMultipartUploadAndReturnError(t *testing.T) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t)
	testId := "Thisisjustastringfortesting"

	input := s3.CompleteMultipartUploadInput{
		Bucket: &testBucketName,
		Key: &putObjectTestKey,
		UploadId: &testId,

	}
	defer cancel()
	_, err := client.CompleteMultipartUpload(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runUploadPartAndReturnError(t *testing.T) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t)
	testId := "Thisisjustastringfortesting"
	var partNumber int32 = 1

	input := s3.UploadPartInput{
		Bucket: &testBucketName,
		Key: &putObjectTestKey,
		UploadId: &testId,
		PartNumber: &partNumber,
	}
	defer cancel()
	_, err := client.UploadPart(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}


type s3CallTestFunc func (*testing.T) error
type contextType map[string]*policy.ConditionValue

type apiAndIAMActionTestCase struct {
	ApiAction     string 
	ApiCall         s3CallTestFunc
	ExpectedActions []iamAction
}

//For each supported API we should add test coverage. This is used in this
//file for checking wether it is mapped to the expected IAMActions and in
//policy_api_action_test.go it is used to see if it is the expected APIAction
func getApiAndIAMActionTestCases() ([]apiAndIAMActionTestCase) {
	iamActionTestCases := []apiAndIAMActionTestCase{
		{
			ApiAction: "ListObjectsV2",
			ApiCall:     runListObjectsV2AndReturnError,
			ExpectedActions: []iamAction{
				NewIamAction(IAMActionS3ListBucket, testBucketARN, contextType{
					IAMConditionS3Prefix: policy.NewConditionValueString(true, ""),
				}),
			},
		},
		{
			ApiAction: "ListObjectsV2",
			ApiCall:     runListObjectsV2WithPrefixAndReturnError,
			ExpectedActions: []iamAction{
				NewIamAction(IAMActionS3ListBucket, testBucketARN, contextType{
					IAMConditionS3Prefix: policy.NewConditionValueString(true, listobjectv2_test_prefix),
				}),
			},
		},
		{
			ApiAction: "PutObject",
			ApiCall:     runPutObjectAndReturnError,
			ExpectedActions: []iamAction{
				NewIamAction(IAMActionS3PutObject, putObjectFullObjectARN, nil),
			},
		},
		{
			ApiAction: "GetObject",
			ApiCall:     runGetObjectAndReturnError,
			ExpectedActions: []iamAction{
				NewIamAction(IAMActionS3GetObject, putObjectFullObjectARN, nil),
			},
		},
		// TODO: HeadObject behaves different client side and overrides the error so our hacky way of testing does not work
		// {
		// 	ApiAction: "HeadObject",
		// 	ApiCall:     runHeadObjectAndReturnError,
		// 	ExpectedActions: []iamAction{
		// 		// https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html
		// 		// To use HEAD, you must have the s3:GetObject permission.
		// 		NewIamAction(IAMActionS3GetObject, putObjectFullObjectARN, nil),
		// 	},
		// },
		{
			ApiAction: "ListBuckets",
			ApiCall:   runListBucketsAndReturnError,
			ExpectedActions: []iamAction{
				NewIamAction(IAMActionS3ListAllMyBuckets, "*", nil),
			},
		},
		{
			ApiAction: "AbortMultipartUpload",
			ApiCall:     runAbortMultipartUploadAndReturnError,
			ExpectedActions: []iamAction{
				NewIamAction(IAMActionS3AbortMultipartUpload, putObjectFullObjectARN, nil),
			},
		},
		{
			ApiAction: "CreateMultipartUpload",
			ApiCall:     runCreateMultipartUploadAndReturnError,
			ExpectedActions: []iamAction{
				//https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
				//You must be allowed to perform the s3:PutObject action on an object to initiate multipart upload.
				NewIamAction(IAMActionS3PutObject, putObjectFullObjectARN, nil),
			},
		},
		{
			ApiAction: "UploadPart",
			ApiCall:     runUploadPartAndReturnError,
			ExpectedActions: []iamAction{
				//https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
				//You must be allowed to perform the s3:PutObject action on an object to initiate multipart upload.
				NewIamAction(IAMActionS3PutObject, putObjectFullObjectARN, nil),
			},
		},
		{
			ApiAction: "CompleteMultipartUpload",
			ApiCall:     runCompleteMultipartUploadAndReturnError,
			ExpectedActions: []iamAction{
				//https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
				//You must be allowed to perform the s3:PutObject action on an object to initiate multipart upload.
				NewIamAction(IAMActionS3PutObject, putObjectFullObjectARN, nil),
			},
		},
	}
	return iamActionTestCases
}

//The idea of this suite of tests is to make sure we generate the IAM action properly for
//AWS actions their requests. It uses a server that just builds the IAM action and returns it
//in the error message then finally we see it is the expected format.
//It is unlikely that the initial implementation is complete BUT changes can impact security!
//Adding additional context should be OK
//Removing/changing context values (e.g. if there are bugs) are breaking changes and should be
//treated as such.
func TestExpectedIamActionsAreReturned(t *testing.T) {
	teardownSuite := setupSuiteProxyS3(t, newStubJustReturnIamAction(t))
	defer teardownSuite(t)

	for _, tc := range getApiAndIAMActionTestCases() {
		err := tc.ApiCall(t)
		smityError, ok := err.(*sg.OperationError) 
		if !ok {
			t.Errorf("err was not smithy error %s", err)
			continue
		}
		accessDeniedParts := strings.Split(smityError.Error(), "AccessDenied: ")
		if len(accessDeniedParts) < 2 {
			t.Errorf("Encountered unexpected error (not Access Denied) %s", smityError)
			continue
		}
		msg := accessDeniedParts[1]
		var actions []iamAction
		err = json.Unmarshal([]byte(msg), &actions)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(actions, tc.ExpectedActions) {
			if len(actions) != len(tc.ExpectedActions) {
				printPointerAndJSONStringComparison(t, tc.ApiAction, tc.ExpectedActions, actions)
			} else {
				//Same amount of actions string and pointer representations might not show the issue let's compare 1-by 1
				for i, action := range actions {
					expectedAction := tc.ExpectedActions[i]
					if !reflect.DeepEqual(action, expectedAction) {
						printPointerAndJSONStringComparison(t, tc.ApiAction, expectedAction, action)
					}
				}
			}
		}
	}
}