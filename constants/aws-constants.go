package constants

//The AWS SDK does not seem to provide packages that export these constants :(
const (
	// AmzSecurityTokenKey indicates the security token to be used with temporary credentials
	AmzSecurityTokenKey = "X-Amz-Security-Token"

	// Source: https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/internal/v4a/internal/v4
	
	// EmptyStringSHA256 is the hex encoded sha256 value of an empty string
	EmptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

	// AmzAlgorithmKey indicates the signing algorithm
	AmzAlgorithmKey = "X-Amz-Algorithm"

	// AmzDateKey is the UTC timestamp for the request in the format YYYYMMDD'T'HHMMSS'Z'
	AmzDateKey = "X-Amz-Date"

	//AmzExpiresKey is how long the url is valid for in seconds since X-Amz-Date(AmzDateKey)
	AmzExpiresKey = "X-Amz-Expires"

	// AmzCredentialKey is the access key ID and credential scope
	AmzCredentialKey = "X-Amz-Credential"

	// AmzSignedHeadersKey is the set of headers signed for the request
	AmzSignedHeadersKey = "X-Amz-SignedHeaders"

	// AmzSignatureKey is the query parameter to store the SigV4 signature
	AmzSignatureKey = "X-Amz-Signature"

	// SignatureKey is the query parameter to store a SigV4 signature but used for hmacv1
	SignatureKey = "Signature"

	// AccessKeyId is the query parameter to store the access key for hmacv1
	AccessKeyId = "AWSAccessKeyId"

	// ExpiresKey is the query parameter when the url expires (epoch time)
	ExpiresKey = "Expires"

	// ContentSHAKey is the SHA256 of request body
	AmzContentSHAKey = "X-Amz-Content-Sha256"

	// TimeFormat is the time format to be used in the X-Amz-Date header or query parameter
	TimeFormat = "20060102T150405Z"
)

