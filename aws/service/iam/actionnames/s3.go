package actionnames

//S3 IAM actions
const (
	IAMActionS3PutObject = "s3:PutObject"
	IAMActionS3GetObject = "s3:GetObject"
	IAMActionS3ListBucket = "s3:ListBucket"
	IAMActionS3AbortMultipartUpload = "s3:AbortMultipartUpload"
	IAMActionS3ListAllMyBuckets = "s3:ListAllMyBuckets"
)

//S3 Condition keys
const (
	IAMConditionS3Prefix = "s3:prefix"
)