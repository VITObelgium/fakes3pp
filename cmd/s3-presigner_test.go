package cmd

import (
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

//START OF GENERATED CONTENT (see s3-presigner_test.py)

var testUrl = "https://s3.test.com/my-bucket/path/to/my_file" 
var testAccessKeyId = "0123455678910abcdef09459"
var testSecretAccessKey = "YWUzOTQyM2FlMDMzNDlkNjk0M2FmZDE1OWE1ZGRkMT"
var testSessionToken = "FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT"
var testExpires = "1727389975"
var testExpectedPresignedUrlTemp = "https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975"
var testExpectedPresignedUrlPerm = "https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=O%2FybXwQdy0cISlo6ly4Lit6s%2BlE%3D&Expires=1727389975"

//END OF GENERATED CONTENT

var testCredsPerm = aws.Credentials{
	AccessKeyID: testAccessKeyId,
	SecretAccessKey: testSecretAccessKey,
}
var testCredsTemp = aws.Credentials{
	AccessKeyID: testAccessKeyId,
	SecretAccessKey: testSecretAccessKey,
	SessionToken: testSessionToken,
}

func TestIfNoExpiresInUrlAndNoExpiryThenWeMustFail(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://s3.test/bucket/key", nil)
	if err != nil {
		t.Error(req)
		t.FailNow()
	}
	_, err = CalculateS3PresignedUrl(req, testCredsTemp, 0)
	if err == nil {
		t.Error("Should have gotten an error")
	}
}

func TestIfExpiresInUrlAndExpiryThenWeMustFail(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, testExpectedPresignedUrlPerm, nil)
	if err != nil {
		t.Error(req)
		t.FailNow()
	}
	_, err = CalculateS3PresignedUrl(req, testCredsPerm, 3600)
	if err == nil {
		t.Error("Should have gotten an error")
	}
}

var testCasesValidUrls = []struct{
	Description string
	Creds       aws.Credentials
	ExpectedUrl string
}{
	{
		"Temporary credentials",
		testCredsTemp,
		testExpectedPresignedUrlTemp,
	},
	{
		"Permanent credentials",
		testCredsPerm,
		testExpectedPresignedUrlPerm,
	},
}

func TestGenerateS3PresignedGetObjectWithTemporaryCreds(t *testing.T) {
	for _, tc := range testCasesValidUrls {
		req, err := http.NewRequest(http.MethodGet, testUrl, nil)
		if err != nil {
			t.Error(req)
			t.FailNow()
		}
		presigned, err := CalculateS3PresignedUrlWithExpiryTime(req, tc.Creds, testExpires)
		if err != nil {
			t.Errorf("%s: %s", tc.Description, err)
			continue
		}
		if presigned != tc.ExpectedUrl {
			t.Errorf("%s: +Expected <> -Calculated:\n\t+%s\n\t-%s", tc.Description, tc.ExpectedUrl, presigned)
		}
	}
}

func TestValidateS3GetPresignedUrlsForValidUrls(t *testing.T){
	for _, tc := range testCasesValidUrls {
		isValid, err := HasGetS3PresignedUrlValidSignature(tc.ExpectedUrl, tc.Creds)
		if err != nil {
			t.Errorf("%s: %s", tc.Description, err)
			continue
		}
		if !isValid {
			t.Errorf("%s: Signature was invalid but expected it to be valid", tc.Description)
		}
	}
}