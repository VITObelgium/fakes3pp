package api

type S3Operation int

//go:generate stringer -type=S3Operation $GOFILE
const (
	UnknownOperation S3Operation = iota
	ListObjectsV2
	GetObject
	ListBuckets
	HeadBucket
	HeadObject
	PutObject
	CreateMultipartUpload
	CompleteMultipartUpload
	AbortMultipartUpload
	UploadPart
)
