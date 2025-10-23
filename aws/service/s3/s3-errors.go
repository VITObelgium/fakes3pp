package s3

//This is almost an exact copy of https://github.com/minio/minio/blob/master/cmd/sts-errors.go
//with a search and replace from sts to s3 (some minor changes due to difference in S3 error structure)
//As such let me copy their copyright notice:

// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import (
	"context"
	"encoding/xml"
	"log/slog"
	"net/http"

	"github.com/VITObelgium/fakes3pp/aws/service"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/usererror"
	"github.com/VITObelgium/fakes3pp/utils"
)

type s3ErrorReporter struct{}

var s3ErrorReporterInstance = &s3ErrorReporter{}

func (er *s3ErrorReporter) WriteErrorResponse(ctx context.Context, w http.ResponseWriter, errCode service.AWSErrorCode, err error) {
	s3ErrCode := toS3ErrorCode(ctx, errCode)
	writeS3ErrorResponse(ctx, w, s3ErrCode, err)

}

var awsToS3ErrorCode = map[service.AWSErrorCode]S3ErrorCode{
	service.ErrAWSAccessDenied:              ErrS3AccessDenied,
	service.ErrAWSInternalError:             ErrS3InternalError,
	service.ErrAWSInvalidSignature:          ErrS3InvalidSignature,
	service.ErrInvalidAccessKeyId:           ErrS3InvalidAccessKeyId,
	service.ErrAuthorizationHeaderMalformed: ErrS3AuthorizationHeaderMalformed,
}

func toS3ErrorCode(ctx context.Context, awsE service.AWSErrorCode) (s3E S3ErrorCode) {
	s3E, ok := awsToS3ErrorCode[awsE]
	if !ok {
		slog.ErrorContext(ctx, "Unsupported error code for S3", "AWSErrorCode", awsE)
		return ErrS3InternalError
	}
	return s3E
}

// writeS3ErrorResponse writes error headers
// If err is a UserError then we return the user error as a description
func writeS3ErrorResponse(ctx context.Context, w http.ResponseWriter, errCode S3ErrorCode, err error) {
	requestctx.SetErrorCode(ctx, errCode)
	s3Err := s3ErrCodes.ToS3Err(errCode)

	// Generate error response.
	s3ErrorResponse := S3ErrorResponse{}
	s3ErrorResponse.Code = s3Err.Code
	s3ErrorResponse.RequestID = requestctx.GetRequestID(ctx)
	s3ErrorResponse.Message = s3Err.Description

	if userFacing := usererror.Get(err); userFacing != nil {
		//Golang doesn't like capitalized error strings but AWS errors seem to prefer it
		s3ErrorResponse.Message = utils.CapitalizeFirstLetter(userFacing.Error())
	}
	switch errCode {
	case ErrS3InternalError:
		slog.ErrorContext(ctx, "Sending S3 error response", "error", usererror.AsFlatSensitiveString(err))
	case ErrS3UpstreamError:
		slog.WarnContext(ctx, "Sending S3 error response", "error", usererror.AsFlatSensitiveString(err))
	default:
		slog.InfoContext(ctx, "Sending S3 error response", "error", usererror.AsFlatSensitiveString(err))
	}
	encodedErrorResponse := service.EncodeResponse(ctx, s3ErrorResponse)
	service.WriteResponse(ctx, w, s3Err.HTTPStatusCode, encodedErrorResponse, service.MimeXML)
}

type S3ErrorResponse struct {
	XMLName   xml.Name `xml:"Error" json:"-"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
	HostId    string   `xml:"HostId"`
}

type S3Error struct {
	Code           string
	Description    string
	HTTPStatusCode int
}

type S3ErrorCode int

//go:generate stringer -type=S3ErrorCode -trimprefix=Err $GOFILE

const (
	ErrS3None S3ErrorCode = iota
	ErrS3AccessDenied
	ErrS3InternalError
	ErrS3UpstreamError
	ErrS3InvalidAccessKeyId
	ErrS3InvalidSignature
	ErrS3InvalidSecurity
	ErrS3InvalidRegion
	ErrS3AuthorizationHeaderMalformed
)

type s3ErrorCodeMap map[S3ErrorCode]S3Error

func (e s3ErrorCodeMap) ToS3Err(errCode S3ErrorCode) S3Error {
	apiErr, ok := e[errCode]
	if !ok {
		return e[ErrS3InternalError]
	}
	return apiErr
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
var s3ErrCodes = s3ErrorCodeMap{
	ErrS3AccessDenied: {
		Code:           "AccessDenied",
		Description:    "Access Denied",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrS3UpstreamError: {
		Code:           "InternalError",
		Description:    "An upstream service required for this operation failed - please try again or contact an administrator.",
		HTTPStatusCode: http.StatusInternalServerError,
	},
	ErrS3InternalError: {
		Code:           "InternalError",
		Description:    "We encountered an internal error, please try again.",
		HTTPStatusCode: http.StatusInternalServerError,
	},
	ErrS3InvalidAccessKeyId: {
		Code:           "InvalidAccessKeyId",
		Description:    "The AWS Access Key Id you provided does not exist in our records.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrS3InvalidSignature: {
		Code:           "InvalidSignature",
		Description:    "The request signature that the server calculated does not match the signature that you provided. Check your AWS secret access key and signing method. For more information, see Signing and authenticating REST requests.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrS3InvalidSecurity: {
		Code:           "InvalidSecurity",
		Description:    "The provided security credentials are not valid.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrS3InvalidRegion: {
		Code:           "InvalidRegion",
		Description:    "The provided region is not valid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrS3AuthorizationHeaderMalformed: {
		Code:           "AuthorizationHeaderMalformed",
		Description:    "The authorization header that you provided is not valid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
}
