package usererror_test

import (
	"errors"
	"fmt"
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