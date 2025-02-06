// Code generated by "stringer -type=S3ErrorCode -trimprefix=Err s3-errors.go"; DO NOT EDIT.

package s3

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ErrS3None-0]
	_ = x[ErrS3AccessDenied-1]
	_ = x[ErrS3InternalError-2]
	_ = x[ErrS3UpstreamError-3]
	_ = x[ErrS3InvalidAccessKeyId-4]
	_ = x[ErrS3InvalidSignature-5]
	_ = x[ErrS3InvalidSecurity-6]
	_ = x[ErrS3InvalidRegion-7]
	_ = x[ErrS3AuthorizationHeaderMalformed-8]
}

const _S3ErrorCode_name = "S3NoneS3AccessDeniedS3InternalErrorS3UpstreamErrorS3InvalidAccessKeyIdS3InvalidSignatureS3InvalidSecurityS3InvalidRegionS3AuthorizationHeaderMalformed"

var _S3ErrorCode_index = [...]uint8{0, 6, 20, 35, 50, 70, 88, 105, 120, 150}

func (i S3ErrorCode) String() string {
	if i < 0 || i >= S3ErrorCode(len(_S3ErrorCode_index)-1) {
		return "S3ErrorCode(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _S3ErrorCode_name[_S3ErrorCode_index[i]:_S3ErrorCode_index[i+1]]
}
