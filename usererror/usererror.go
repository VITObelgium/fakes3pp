package usererror

import (
	"errors"
	"log/slog"
)

type internalTypeUserError string

//For errors that have a userfacing component
type UserError interface {
	//Still adhere to the error interface and have those be regular error (not user facing)
	error
	//Add a userError method which allows to differentiate this interface from others
	userError() internalTypeUserError
	//Get internal error
	Unwrap() error
}


type userError struct {
	//The user facing error message
	userMsg string
	
	//The internal error
	wrapped error
}

//Create a new error that has a user facing message while still tracking the full details for internal usage
func New(wrapped error, userfacingMsg string) UserError {
	if wrapped == nil && userfacingMsg != "" {
		//Likely programming error but setting userfacing to nil is even more risky
		slog.Warn("Internal error should be more descriptive than userfacing error (likely coding bug)", "internal", wrapped, "userfacing", userfacingMsg)
	}
	return &userError{
		wrapped: wrapped,
		userMsg: userfacingMsg,
	}
}

func (e *userError) userError() internalTypeUserError {
	return internalTypeUserError(e.userMsg)
}

func (e *userError) Error() string {
	return e.userMsg
}

//A user error is always triggered by an error so 
func (e *userError) Unwrap() error {
	return e.wrapped
}

func (e *userError) IsUserError() bool {
	return true
}

//Helper to get user error
func Get(e error) (UserError) {
	var ue UserError
	foundUserErrr := errors.As(e, &ue)
	if !foundUserErrr {
		return nil
	}
	return ue
}

//Helper to check whether we are actually user facing
func IsUserFacing(e error) (bool) {
	_, ok := e.(UserError)
	return ok
}