package s3

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	"github.com/VITObelgium/fakes3pp/aws/service/iam/actionnames"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/VITObelgium/fakes3pp/testutils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/micahhausler/aws-iam-policy/policy"
)

type StubJustReturnIamAction struct {
	t *testing.T
}

var latestIamActionInStubReturnIamAction []iam.IAMAction = nil

type noVirtualHostRequestsType struct{}

func (*noVirtualHostRequestsType) IsVirtualHostingRequest(req *http.Request) bool {
	return false
}

var noVirtualHostRequests = &noVirtualHostRequestsType{}

func (p *StubJustReturnIamAction) Build(backendManager interfaces.BackendManager, corsHandler interfaces.CORSHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		action := getS3Action(r)
		actions, err := newIamActionsFromS3Request(action, r, nil, noVirtualHostRequests)
		if err != nil {
			p.t.Error(err)
			return
		}
		latestIamActionInStubReturnIamAction = actions
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
			requestctx.NewContextFromHttpRequest(r),
			w,
			ErrS3AccessDenied,
			errors.New(string(bytes)),
		)
	}
}

func newStubJustReturnIamAction(ti *testing.T) interfaces.HandlerBuilderI {
	var testStub = StubJustReturnIamAction{
		t: ti,
	}
	return &testStub
}

func getAnonymousS3TestClient(t *testing.T, s server.Serverable) (client *s3.Client, ctx context.Context, cancel context.CancelFunc) {
	client = testutils.GetTestClientS3(t, "eu-central-1", aws.AnonymousCredentials{}, s)

	ctx, cancel = context.WithTimeout(context.Background(), 1000*time.Second)
	return
}

func runListObjectsV2AndReturnErrorForEndpoint(t *testing.T, s server.Serverable) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t, s)

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

func runListObjectsV2AndReturnError(t *testing.T, s server.Serverable) error {
	return runListObjectsV2AndReturnErrorForEndpoint(t, s)
}

// run listObjectsV2 but use alternate FQDN that is known by S3Proxy.
func runListObjectsV2AndReturnErrorAlternateEndpoint(t *testing.T, s server.Serverable) error {
	_, certFile, certKey := s.GetTls()
	sWithAlternateEndpoint := &S3Server{
		BasicServer: *server.NewBasicServer(s.GetPort(), "localhost2", certFile, certKey, nil),
		fqdns:       []string{"localhost2"},
	}
	return runListObjectsV2AndReturnErrorForEndpoint(t, sWithAlternateEndpoint)
}

var listobjectv2_test_prefix string = "my-prefix"

func runListObjectsV2WithPrefixAndReturnError(t *testing.T, s server.Serverable) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t, s)

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

func runListBucketsAndReturnError(t *testing.T, s server.Serverable) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t, s)

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

func runPutObjectAndReturnError(t *testing.T, s server.Serverable) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t, s)

	input := s3.PutObjectInput{
		Bucket: &testBucketName,
		Key:    &putObjectTestKey,
		Body:   bytes.NewReader([]byte("This is a test")),
	}
	defer cancel()
	_, err := client.PutObject(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runGetObjectAndReturnError(t *testing.T, s server.Serverable) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t, s)

	input := s3.GetObjectInput{
		Bucket: &testBucketName,
		Key:    &putObjectTestKey,
	}
	defer cancel()
	_, err := client.GetObject(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runHeadObjectAndReturnError(t *testing.T, s server.Serverable) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t, s)

	input := s3.HeadObjectInput{
		Bucket: &testBucketName,
		Key:    &putObjectTestKey,
	}
	defer cancel()
	_, err := client.HeadObject(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runAbortMultipartUploadAndReturnError(t *testing.T, s server.Serverable) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t, s)
	testId := "Thisisjustastringfortesting"
	input := s3.AbortMultipartUploadInput{
		Bucket:   &testBucketName,
		Key:      &putObjectTestKey,
		UploadId: &testId,
	}
	defer cancel()
	_, err := client.AbortMultipartUpload(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runCreateMultipartUploadAndReturnError(t *testing.T, s server.Serverable) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t, s)

	input := s3.CreateMultipartUploadInput{
		Bucket: &testBucketName,
		Key:    &putObjectTestKey,
	}
	defer cancel()
	_, err := client.CreateMultipartUpload(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runCompleteMultipartUploadAndReturnError(t *testing.T, s server.Serverable) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t, s)
	testId := "Thisisjustastringfortesting"

	input := s3.CompleteMultipartUploadInput{
		Bucket:   &testBucketName,
		Key:      &putObjectTestKey,
		UploadId: &testId,
	}
	defer cancel()
	_, err := client.CompleteMultipartUpload(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

func runUploadPartAndReturnError(t *testing.T, s server.Serverable) error {
	client, max1Sec, cancel := getAnonymousS3TestClient(t, s)
	testId := "Thisisjustastringfortesting"
	var partNumber int32 = 1

	input := s3.UploadPartInput{
		Bucket:     &testBucketName,
		Key:        &putObjectTestKey,
		UploadId:   &testId,
		PartNumber: &partNumber,
	}
	defer cancel()
	_, err := client.UploadPart(max1Sec, &input)
	if err == nil {
		t.Error("Should have encountered error but did not")
	}
	return err
}

type s3CallTestFunc func(*testing.T, server.Serverable) error
type contextType map[string]*policy.ConditionValue

type apiAndIAMActionTestCase struct {
	ApiAction       string
	ApiCall         s3CallTestFunc
	ExpectedActions []iam.IAMAction
}

// For each supported API we should add test coverage. This is used in this
// file for checking wether it is mapped to the expected IAMActions and in
// policy_api_action_test.go it is used to see if it is the expected APIAction
func getApiAndIAMActionTestCases() []apiAndIAMActionTestCase {
	iamActionTestCases := []apiAndIAMActionTestCase{
		{
			ApiAction: "ListObjectsV2",
			ApiCall:   runListObjectsV2AndReturnError,
			ExpectedActions: []iam.IAMAction{
				iam.NewIamAction(actionnames.IAMActionS3ListBucket, testBucketARN, nil).AddContext(contextType{
					actionnames.IAMConditionS3Prefix: policy.NewConditionValueString(true, ""),
				}),
			},
		},
		{
			ApiAction: "ListObjectsV2",
			ApiCall:   runListObjectsV2WithPrefixAndReturnError,
			ExpectedActions: []iam.IAMAction{
				iam.NewIamAction(actionnames.IAMActionS3ListBucket, testBucketARN, nil).AddContext(contextType{
					actionnames.IAMConditionS3Prefix: policy.NewConditionValueString(true, listobjectv2_test_prefix),
				}),
			},
		},
		{
			ApiAction: "ListObjectsV2",
			ApiCall:   runListObjectsV2AndReturnErrorAlternateEndpoint,
			ExpectedActions: []iam.IAMAction{
				iam.NewIamAction(actionnames.IAMActionS3ListBucket, testBucketARN, nil).AddContext(contextType{
					actionnames.IAMConditionS3Prefix: policy.NewConditionValueString(true, listobjectv2_test_prefix),
				}),
			},
		},
		{
			ApiAction: "PutObject",
			ApiCall:   runPutObjectAndReturnError,
			ExpectedActions: []iam.IAMAction{
				iam.NewIamAction(actionnames.IAMActionS3PutObject, putObjectFullObjectARN, nil),
			},
		},
		{
			ApiAction: "GetObject",
			ApiCall:   runGetObjectAndReturnError,
			ExpectedActions: []iam.IAMAction{
				iam.NewIamAction(actionnames.IAMActionS3GetObject, putObjectFullObjectARN, nil),
			},
		},
		{
			ApiAction: "HeadObject",
			ApiCall:   runHeadObjectAndReturnError,
			ExpectedActions: []iam.IAMAction{
				// https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html
				// To use HEAD, you must have the s3:GetObject permission.
				iam.NewIamAction(actionnames.IAMActionS3GetObject, putObjectFullObjectARN, nil),
			},
		},
		{
			ApiAction: "ListBuckets",
			ApiCall:   runListBucketsAndReturnError,
			ExpectedActions: []iam.IAMAction{
				iam.NewIamAction(actionnames.IAMActionS3ListAllMyBuckets, "*", nil),
			},
		},
		{
			ApiAction: "AbortMultipartUpload",
			ApiCall:   runAbortMultipartUploadAndReturnError,
			ExpectedActions: []iam.IAMAction{
				iam.NewIamAction(actionnames.IAMActionS3AbortMultipartUpload, putObjectFullObjectARN, nil),
			},
		},
		{
			ApiAction: "CreateMultipartUpload",
			ApiCall:   runCreateMultipartUploadAndReturnError,
			ExpectedActions: []iam.IAMAction{
				//https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
				//You must be allowed to perform the s3:PutObject action on an object to initiate multipart upload.
				iam.NewIamAction(actionnames.IAMActionS3PutObject, putObjectFullObjectARN, nil),
			},
		},
		{
			ApiAction: "UploadPart",
			ApiCall:   runUploadPartAndReturnError,
			ExpectedActions: []iam.IAMAction{
				//https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
				//You must be allowed to perform the s3:PutObject action on an object to initiate multipart upload.
				iam.NewIamAction(actionnames.IAMActionS3PutObject, putObjectFullObjectARN, nil),
			},
		},
		{
			ApiAction: "CompleteMultipartUpload",
			ApiCall:   runCompleteMultipartUploadAndReturnError,
			ExpectedActions: []iam.IAMAction{
				//https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
				//You must be allowed to perform the s3:PutObject action on an object to initiate multipart upload.
				iam.NewIamAction(actionnames.IAMActionS3PutObject, putObjectFullObjectARN, nil),
			},
		},
	}
	return iamActionTestCases
}

// The idea of this suite of tests is to make sure we generate the IAM action properly for
// AWS actions their requests. It uses a server that just builds the IAM action and returns it
// in the error message then finally we see it is the expected format.
// It is unlikely that the initial implementation is complete BUT changes can impact security!
// Adding additional context should be OK
// Removing/changing context values (e.g. if there are bugs) are breaking changes and should be
// treated as such.
func TestExpectedIamActionsAreReturned(t *testing.T) {
	teardownSuite, s := setupSuiteProxyS3(t, newStubJustReturnIamAction(t), nil, nil, []middleware.Middleware{RegisterOperation()}, true, nil, nil)
	defer teardownSuite(t)

	for _, tc := range getApiAndIAMActionTestCases() {
		err := tc.ApiCall(t, s)
		if err == nil {
			t.Errorf("%s: by design the stub should return an error but we did not get one.", tc.ApiAction)
			t.FailNow()
		}

		if !reflect.DeepEqual(latestIamActionInStubReturnIamAction, tc.ExpectedActions) {
			printPointerAndJSONStringComparison(t, tc.ApiAction, tc.ExpectedActions, latestIamActionInStubReturnIamAction)
			t.Errorf("unexpected actions got %v, expected %v", latestIamActionInStubReturnIamAction, tc.ExpectedActions)
		}

	}
}
