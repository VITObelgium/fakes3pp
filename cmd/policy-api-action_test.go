package cmd

import (
	"errors"
	"net/http"
	"testing"

	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/s3/api"
)


type StubJustReturnApiAction struct{
	t *testing.T
}

var globalLastApiActionStubJustReturnApiAction api.S3Operation = api.UnknownOperation

func (p *StubJustReturnApiAction) Build(presigned bool) http.HandlerFunc{
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

func newStubJustReturnApiAction(ti *testing.T) handlerBuilderI {
	var testStub = StubJustReturnApiAction{
		t: ti,
	}
	return &testStub
}

func TestExpectedAPIActionIdentified(t *testing.T) {
	teardownSuite := setupSuiteProxyS3(t, newStubJustReturnApiAction(t))
	defer teardownSuite(t)

	for _, tc := range getApiAndIAMActionTestCases() { //see policy_iam_action_test
		err := tc.ApiCall(t)
		if err == nil {
			t.Errorf("%s: an error should have been returned", tc.ApiAction)
		}

		if tc.ApiAction != globalLastApiActionStubJustReturnApiAction.String() {
			t.Errorf("wrong APIAction identified; expected %s, got %s", tc.ApiAction, globalLastApiActionStubJustReturnApiAction)
		}
	}
}