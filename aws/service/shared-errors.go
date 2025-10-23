package service

import (
	"context"
	"net/http"
)

type AWSErrorCode int

//go:generate stringer -type=AWSErrorCode -trimprefix=Err $GOFILE
const (
	ErrAWSNone AWSErrorCode = iota
	ErrAWSInternalError
	ErrAWSInvalidSignature
	ErrAWSAccessDenied
	ErrInvalidAccessKeyId
	ErrAuthorizationHeaderMalformed
)

type ErrorReporter interface {
	WriteErrorResponse(ctx context.Context, w http.ResponseWriter, errCode AWSErrorCode, err error)
}
