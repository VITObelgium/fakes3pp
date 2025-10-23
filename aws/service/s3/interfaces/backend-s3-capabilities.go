package interfaces

type S3Capability int

//go:generate stringer -type=S3Capability -trimprefix=S3Capability $GOFILE

// Below are the different supported capabilities. When specifying them in the config file
// just omit the S3Capability part for example "StreamingUnsignedPayloadTrailer"
const (
	//Whether the payload of type STREAMING-UNSIGNED-PAYLOAD-TRAILER is
	//supported by the backend details can be find in issue
	//https://github.com/VITObelgium/fakes3pp/issues/27
	S3CapabilityStreamingUnsignedPayloadTrailer S3Capability = iota
)

var S3CapabilityLookup map[string]S3Capability = map[string]S3Capability{
	S3CapabilityStreamingUnsignedPayloadTrailer.String(): S3CapabilityStreamingUnsignedPayloadTrailer,
}
