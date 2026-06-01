package interfaces

import (
	"github.com/aws/aws-sdk-go-v2/aws"
)

type BackendLocator interface {
	//Takes an id of a backend and returns the endpoint (protocol://hostname:port)
	GetBackendEndpoint(backendId string) (Endpoint, error)

	//Get the ID of the fallback backend
	GetDefaultBackend() string
}

type BackendCredentialRetriever interface {
	// GetBackendCredentials returns the static (default rule) credentials for a backend.
	// This is for callers without request context such as the presign CLI.
	GetBackendCredentials(backendId string) (aws.Credentials, error)
}

// CredentialSelectionContextProvider is an interface for types that can supply a
// CredentialSelectionContext. The concrete type lives in the s3 package; the interface
// here avoids a circular import while still allowing the BackendManager to be generic.
type CredentialSelectionContextProvider interface {
	GetRequestAccessKeyID() string
	GetRequestedRegion() string
	GetClaimsSubject() string
	GetClaimsIssuer() string
	GetPrincipalTags() map[string][]string
}

type BackendCredentialSelector interface {
	// SelectBackendCredentials evaluates credential rules for the given backend using the
	// provided selection context. Returns the matched credentials, the name of the matched
	// rule, and an error. If no rule matches and there is no default rule, the error will
	// wrap ErrNoMatchingCredentialRule and the caller should return AccessDenied.
	SelectBackendCredentials(backendId string, selCtx CredentialSelectionContextProvider) (aws.Credentials, string, error)
}

type BackendManager interface {
	BackendLocator
	BackendCredentialRetriever
	BackendCredentialSelector
	HasCapability(backendId string, capability S3Capability) bool
}

type Endpoint interface {
	//The part of the endpoint without protocol
	GetHost() string

	//The endpoint base URI is of form protocol://hostname and can be used to identify the backend
	//service
	GetBaseURI() string
}
