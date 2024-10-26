package cmd

type S3ApiAction string

const (
	apiS3ListObjectsV2 S3ApiAction = "ListObjectsV2"
    apiS3GetObject S3ApiAction = "GetObject"
	apiS3ListBuckets S3ApiAction = "ListBuckets"
	apiS3HeadBucket S3ApiAction = "HeadBucket"
	apiS3HeadObject S3ApiAction = "HeadObject"
	apiS3PutObject S3ApiAction = "PutObject"
	apiS3CreateMultipartUpload S3ApiAction = "CreateMultipartUpload"
	apiS3CompleteMultipartUpload S3ApiAction = "CompleteMultipartUpload"
	apiS3AbortMultipartUpload S3ApiAction = "AbortMultipartUpload"
	apiS3UploadPart S3ApiAction = "UploadPart"
)