package testutils

import (
	"crypto/tls"
	"net/http"
	"testing"
)


func BuildUnsafeHttpClientThatTrustsAnyCert(t testing.TB) (*http.Client) {
	//https://github.com/aws/aws-sdk-go/issues/2404
	tr := &http.Transport{
        TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
    }
	return &http.Client{Transport: tr}
}