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
	//Takes an id of a backend and returns the endpoint (protocol://hostname:port)
	GetBackendCredentials(backendId string) (aws.Credentials, error)
}

type BackendManager interface {
	BackendLocator
	BackendCredentialRetriever
	HasCapability(backendId string, capability S3Capability) bool
}

type Endpoint interface {
	//The part of the endpoint without protocol
	GetHost() string
	
	//The endpoint base URI is of form protocol://hostname and can be used to identify the backend
	//service
	GetBaseURI() string
}