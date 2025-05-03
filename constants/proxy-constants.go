package constants

const (
	// Relax the checking of sigV4 signature that when a head is performed the signature
	// still gets checked as it where a HEAD. GetObject and HeadObject both require the same
	// IAM permissions so why not allow both type of HTTP requests. Note This must be passed
	// as a query parameter BEFORE signing because it is expected to be signed.
	HeadAsGet = "X-Proxy-Head-As-Get"
)
