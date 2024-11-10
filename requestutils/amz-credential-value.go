package requestutils

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)


type CredentialPart int64

const (
	CredentialPartAccessKeyId CredentialPart = iota
	CredentialPartDate
	CredentialPartRegionName
	CredentialPartServiceName
	CredentialPartType
)


// credential string is the value of a X-Amz_credential and it is meant to follow
// the structure <your-access-key-id>/20130721/us-east-1/s3/aws4_request (when decoded)
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
func GetCredentialPart(credentialString string, credentialPart CredentialPart) (string, error) {
	authorizationHeaderCredentialParts := strings.Split(credentialString, "/")
	if authorizationHeaderCredentialParts[CredentialPartServiceName] != "s3" {
		return "", errors.New("authorization header was not for S3")
	}
	if authorizationHeaderCredentialParts[CredentialPartType] != "aws4_request" {
		return "", errors.New("authorization header was not a supported sigv4")
	}
	return authorizationHeaderCredentialParts[credentialPart], nil
}

const signAlgorithm = "AWS4-HMAC-SHA256"
const expectedAuthorizationStartWithCredential = "AWS4-HMAC-SHA256 Credential="


// Gets a part of the Credential value that is passed via the authorization header
//
func GetSignatureCredentialPartFromRequest(r *http.Request, credentialPart CredentialPart) (string, error) {
	authorizationHeader := r.Header.Get("Authorization")
	var credentialString string
	var err error
	if authorizationHeader != "" {
		credentialString, err = getSignatureCredentialStringFromRequestAuthHeader(authorizationHeader)
		if err != nil {
			return "", err
		}
	} else {
		qParams := r.URL.Query()
		credentialString, err = getSignatureCredentialStringFromRequestQParams(qParams)
		if err != nil {
			return "", err
		}
	}
	return GetCredentialPart(credentialString, credentialPart)
}

// Gets a part of the Credential value that is passed via the authorization header
func getSignatureCredentialStringFromRequestAuthHeader(authorizationHeader string) (string, error) {
	if authorizationHeader == "" {
		return "", fmt.Errorf("programming error should use empty authHeader to get credential part")
	}
	if !strings.HasPrefix(authorizationHeader, expectedAuthorizationStartWithCredential) {
		return "", fmt.Errorf("invalid authorization header: %s", authorizationHeader)
	}
	authorizationHeaderTrimmed := authorizationHeader[len(expectedAuthorizationStartWithCredential):]
	return strings.Split(authorizationHeaderTrimmed, ", ")[0], nil
}

func getSignatureCredentialStringFromRequestQParams(qParams url.Values) (string, error) {
	queryAlgorithm := qParams.Get("X-Amz-Algorithm")
	if queryAlgorithm != signAlgorithm {
		return "", fmt.Errorf("no Authorization header nor x-amz-algorithm query parameter present: %v", qParams)
	}
	queryCredential := qParams.Get("X-Amz-Credential")
	if queryCredential == "" {
		return "", fmt.Errorf("empty X-Amz-Credential parameter: %v", qParams)
	}
	return queryCredential, nil
}