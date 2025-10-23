package presign

import (
	"net/http"
	"slices"
	"testing"
)


func TestGetSignedHeadersWithSpaces(t *testing.T) {
	//GIVEN a test request
	r, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Errorf("Could not create test request")
	}
	//GIVEN an authorizATION HEADER
	r.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20220830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=calculated-signature")
	
	//WHEN getting the signed headers
	signedHeaders, err := getSignedHeadersFromRequest(r)

	//THEN we should not get an error
	if err != nil {
		t.Errorf("Got errror when getting signed headers from request: %s", err)
	}

	//THEN we should have host as signed header
	if !slices.Contains(signedHeaders, "Host") {
		t.Errorf("Host header is signed header and should be returned correctly")
	}

	//Then we should have x-amz-date as signed header
	if !slices.Contains(signedHeaders,  "X-Amz-Date"){
		t.Errorf("X-Amz-Date header is signed header and should be returned correctly")
	}
}

func TestGetSignedHeadersWithoutSpaces(t *testing.T) {
	//GIVEN a test request
	r, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Errorf("Could not create test request")
	}
	//GIVEN an authorizATION HEADER
	r.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20220830/us-east-1/ec2/aws4_request,SignedHeaders=host;x-amz-date,Signature=calculated-signature")
	
	//WHEN getting the signed headers
	signedHeaders, err := getSignedHeadersFromRequest(r)

	//THEN we should not get an error
	if err != nil {
		t.Errorf("Got errror when getting signed headers from request: %s", err)
	}

	//THEN we should not panick
	//THEN we should have host as signed header
	if !slices.Contains(signedHeaders, "Host")  {
		t.Errorf("Host header is signed header and should be returned correctly")
	}

	//Then we should have x-amz-date as signed header
	if !slices.Contains(signedHeaders,  "X-Amz-Date") {
		t.Errorf("X-Amz-Date header is signed header and should be returned correctly")
	}
}
