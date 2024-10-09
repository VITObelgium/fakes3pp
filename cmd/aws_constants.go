package cmd

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

	// TimeFormat is the time format to be used in the X-Amz-Date header or query parameter
	TimeFormat = "20060102T150405Z"
)

//General HTTP but used in context of AWS
const (
	authorizationHeader = "Authorization"
)