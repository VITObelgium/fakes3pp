package requestutils

import (
	"fmt"
	"testing"
)


func assertEqualStr(tb testing.TB, reason, expected, got any) {
	if expected != got {
		tb.Errorf("%s\n\texpected: %s\n\tgot     : %s", reason, expected, got)
	}
}

func TestGetSignatureCredentialStringFromRequestAuthHeader(t *testing.T) {
	//GIVEN example Authorization header (from main example https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
	authHeader := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20220830/us-east-1/ec2/aws4_request,SignedHeaders=host;x-amz-date,Signature=calculated-signature"

	//Given expected credentialString
	expectedCredentialString := "AKIAIOSFODNN7EXAMPLE/20220830/us-east-1/ec2/aws4_request"

	//WHEN Getting the Credentialstring
	credStr, err := getSignatureCredentialStringFromRequestAuthHeader(authHeader)

	//THEN it should not error out
	if err != nil {
		t.Errorf("was not able to get credentialstring: %s", err)
	}

	assertEqualStr(t, "Credentialstring validation", expectedCredentialString, credStr)
}

func TestGetSignatureCredentialStringFromRequestAuthHeaderWithSpaces(t *testing.T) {
	//GIVEN example Authorization header (from main example https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
	authHeader := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20220830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=calculated-signature"

	//Given expected credentialString
	expectedCredentialString := "AKIAIOSFODNN7EXAMPLE/20220830/us-east-1/ec2/aws4_request"

	//WHEN Getting the Credentialstring
	credStr, err := getSignatureCredentialStringFromRequestAuthHeader(authHeader)

	//THEN it should not error out
	if err != nil {
		t.Errorf("was not able to get credentialstring: %s", err)
	}

	assertEqualStr(t, "Credentialstring validation", expectedCredentialString, credStr)
}

func TestExtractCredentialParts(t *testing.T) {
	//GIVEN the different credential string parts
	givenAkid := "AKIAIOSFODNN7EXAMPLE"
	givenDate := "20220830"
	givenRegion := "us-east-1"
	givenService := "s3"
	givenSigVersion := "aws4_request"
	//GIVEN a credential string build from the given parts
	credString := fmt.Sprintf(
		"%s/%s/%s/%s/%s",
		givenAkid, givenDate, givenRegion, givenService, givenSigVersion,
	)

	//WHEN extracting different parts
	//THEN we expect the value that was given to construct the header
	akid, err := GetCredentialPart(credString, CredentialPartAccessKeyId)
	if err != nil {
		t.Errorf("was not able to get access key id: %s", err)
	}
	assertEqualStr(t, "akid validation", givenAkid, akid)
	
	date, err := GetCredentialPart(credString, CredentialPartDate)
	if err != nil {
		t.Errorf("was not able to get date key: %s", err)
	}
	assertEqualStr(t, "date validation", givenDate, date)
	
	region, err := GetCredentialPart(credString, CredentialPartRegionName)
	if err != nil {
		t.Errorf("was not able to get region: %s", err)
	}
	assertEqualStr(t, "region validation", givenRegion, region)

	service, err := GetCredentialPart(credString, CredentialPartServiceName)
	if err != nil {
		t.Errorf("was not able to get service: %s", err)
	}
	assertEqualStr(t, "service validation", givenService, service)

	typeStr, err := GetCredentialPart(credString, CredentialPartType)
	if err != nil {
		t.Errorf("was not able to get type: %s", err)
	}
	assertEqualStr(t, "type validation", givenSigVersion, typeStr)
}