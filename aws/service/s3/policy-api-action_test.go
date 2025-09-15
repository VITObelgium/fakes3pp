package s3

import (
	"errors"
	"net/http"
	"testing"

	"github.com/VITObelgium/fakes3pp/aws/service/s3/api"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/VITObelgium/fakes3pp/requestctx"
)


type StubJustReturnApiAction struct{
	t *testing.T
}

var globalLastApiActionStubJustReturnApiAction api.S3Operation = api.UnknownOperation

func (p *StubJustReturnApiAction) Build(backendManager interfaces.BackendManager, corsHandler interfaces.CORSHandler) http.HandlerFunc{
	return func (w http.ResponseWriter, r *http.Request)  {
		//AWS CLI expects certain structure for ok responses
		//For error we could use the message field to pass a message regardless
		//of the api action
		action := getS3Action(r)
		globalLastApiActionStubJustReturnApiAction = action
		writeS3ErrorResponse(
			requestctx.NewContextFromHttpRequest(r),
			w,
			ErrS3AccessDenied,
			errors.New(action.String()),
		)
	}
}

func newStubJustReturnApiAction(ti *testing.T) interfaces.HandlerBuilderI {
	var testStub = StubJustReturnApiAction{
		t: ti,
	}
	return &testStub
}

func TestExpectedAPIActionIdentified(t *testing.T) {
	teardownSuite, s := setupSuiteProxyS3(t, newStubJustReturnApiAction(t), nil, nil, []middleware.Middleware{RegisterOperation()}, true, nil, nil)
	defer teardownSuite(t)

	for _, tc := range getApiAndIAMActionTestCases() { //see policy_iam_action_test
		err := tc.ApiCall(t, s)
		if err == nil {
			t.Errorf("%s: an error should have been returned", tc.ApiAction)
		}

		if tc.ApiAction != globalLastApiActionStubJustReturnApiAction.String() {
			t.Errorf("wrong APIAction identified; expected %s, got %s", tc.ApiAction, globalLastApiActionStubJustReturnApiAction)
		}
	}
}