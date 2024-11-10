package cmd

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	sg "github.com/aws/smithy-go"
)


type StubJustReturnApiAction struct{
	t *testing.T
}

func (p *StubJustReturnApiAction) Build(action S3ApiAction, presigned bool) http.HandlerFunc{
	return func (w http.ResponseWriter, r *http.Request)  {
		//AWS CLI expects certain structure for ok responses
		//For error we could use the message field to pass a message regardless
		//of the api action
		writeS3ErrorResponse(
			buildContextWithRequestID(r),
			w,
			ErrS3AccessDenied,
			errors.New(string(action)),
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
		smityError, ok := err.(*sg.OperationError) 
		if !ok {
			t.Errorf("err was not smithy error %s", err)
		}
		accessDeniedParts := strings.Split(smityError.Error(), "AccessDenied: ")
		if len(accessDeniedParts) < 2 {
			t.Errorf("Encountered unexpected error (not Access Denied) %s", smityError)
			continue
		}
		msg := accessDeniedParts[1]
		if msg != tc.ApiAction {
			t.Errorf("Expected %s, got %s, bug in router code", tc.ApiAction, msg)
		}
	}
}