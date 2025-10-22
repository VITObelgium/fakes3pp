package usererror_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/VITObelgium/fakes3pp/usererror"
)


func TestUserErrorGiveCorrectString(t *testing.T){
	//Given internal and userfacing error details
	secretDetails := "Very hush hush info"
	internalErr := errors.New(secretDetails)
	publicDetails := "Please contact support with ID 123"

	//When we create a user error out of it
	ue := usererror.New(internalErr, publicDetails)
	
	//Then it should be user facing
	if !usererror.IsUserFacing(ue) {
		t.Error("Error was not user facing")
	}
	//Then it should result in the user facing details
	if publicDetails != ue.Error() {
		t.Errorf("Error was not return correct info got %s, expected %s", ue.Error(), publicDetails)
	}
}

func TestWrappedUserErrorGiveCorrectString(t *testing.T){
	//Given internal and userfacing error details in a user error
	secretDetails := "Very hush hush info"
	internalErr := errors.New(secretDetails)
	publicDetails := "Please contact support with ID 123"
	ue := usererror.New(internalErr, publicDetails)

	//When we wrap the user error
	wrappedErr := fmt.Errorf("While processing secret info xabc we encountered error: %w", ue)

	//THEN the wrapped error is not a user facing error
	if usererror.IsUserFacing(wrappedErr) {
		t.Error("Wrapped error was userfacing but it shouldn't have been")
	}

	//When we use the Get method
	gottenError := usererror.Get(wrappedErr)
	
	//Then the retrieved error is user facing
	if !usererror.IsUserFacing(gottenError) {
		t.Error("Error was not user facing")
	}
	//Then it should result in the user facing details
	if publicDetails != gottenError.Error() {
		t.Errorf("Error was not return correct info got %s, expected %s", ue.Error(), publicDetails)
	}
}

func TestWrappedUserErrorCanStillLogInternalInfoWhenFlattened(t *testing.T) {
	//Given internal and userfacing error details in a user error
	secretDetails := "Very hush hush info"
	internalErr := errors.New(secretDetails)
	publicDetails := "Please contact support with ID 123"
	ue := usererror.New(internalErr, publicDetails)

	//When we wrap the user error
	wrapMsg := "While processing secret info xabc we encountered error"
	wrappedErr := fmt.Errorf("%s: %w", wrapMsg, ue)

	//When we get the flat string representation
	errStr := usererror.AsFlatSensitiveString(wrappedErr)

	//Then flat internal error string should contain the secret info
	if !strings.Contains(errStr, secretDetails) {
		t.Errorf("flat internal error did not contain secret info.")
	}

	//Then the flat internal error string should have the public parts
	if !strings.Contains(errStr, publicDetails) {
		t.Errorf("flat internal error did not contain public details")
	}
}

func TestNormalErrorWorksFineWhenFlattened(t *testing.T) {
	//Given a normal error
	errString := "error"
	e := errors.New(errString)

	//When we get the flat string representation
	flattenedErrStr := usererror.AsFlatSensitiveString(e)

	//Then we expect it to contain the error str
	if !strings.Contains(flattenedErrStr, errString) {
		t.Errorf("flat error did not original error string")
	}
}

func TestNilInputForErrorFlatteningShouldNotPanic(t *testing.T) {
	//When we get the flat string representation
	usererror.AsFlatSensitiveString(nil)

	//Then we do not panic but remain calm
}

func TestGetUserErrorIsSafeOnAllError(t *testing.T) {
	//Given internal error details
	secretDetails := "Very hush hush info"
	internalErr := errors.New(secretDetails)

	//WHEN getting userfacing error from that
	ue := usererror.Get(internalErr)

	//THEN we do not divulge the secret information
	if ue != nil {
		t.Error("Got a user facing error but that should not have been possible", "usererror", ue)
	}
}

func TestGetUserErrorIsSafeOnNil(t *testing.T) {
	//Given an error that is actuall nil
	var err = func() (error) {
		return nil
	}()
	
	//WHEN getting userfacing error from that
	ue := usererror.Get(err)

	//THEN we did not panic and got nil again
	if ue != nil {
		t.Error("Got a user facing error but that should not have been possible", "usererror", ue)
	}
}