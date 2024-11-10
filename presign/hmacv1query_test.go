package presign

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

//START OF GENERATED CONTENT (see query_string_test.py)

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
	_, err = CalculateS3PresignedHmacV1QueryUrl(req, testCredsTemp, 0)
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
	_, err = CalculateS3PresignedHmacV1QueryUrl(req, testCredsPerm, 3600)
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
		presigned, err := calculateS3PresignedHmacV1QueryUrlWithExpiryTime(req, tc.Creds, testExpires)
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
	var testExpectedExpiresTime, err = epochStrToTime(testExpires)
	if err != nil {
		t.Errorf("Could not calculated expected expires time")
		t.FailNow()
	}

	for _, tc := range testCasesValidUrls {
		req, err := http.NewRequest(http.MethodGet, tc.ExpectedUrl, nil)
		if err != nil {
			t.Errorf("Could not create request: %s", err)
		}
		presignedUrl, err := MakePresignedUrl(req)
		if err != nil {
			t.Errorf("Could not create presigned url: %s", err)
		}
		_, ok := presignedUrl.(presignedUrlHmacv1Query)
		if !ok {
			t.Errorf("We are testing HMACv1 query URLs so we expect to get correct type from factory")
		}

		var testSecretDeriver = func(s string) (string, error) {
			return tc.Creds.SecretAccessKey, nil
		}

		isValid, creds, expires, err := presignedUrl.GetPresignedUrlDetails(context.Background(), testSecretDeriver)
		if err != nil {
			t.Errorf("%s: %s", tc.Description, err)
			continue
		}
		if !isValid {
			t.Errorf("%s: Signature was invalid but expected it to be valid", tc.Description)
		}
		if creds.AccessKeyID != tc.Creds.AccessKeyID {
			t.Errorf("Got different accessKeyId; got %s, expected %s", creds.AccessKeyID, tc.Creds.AccessKeyID)
		}
		if creds.SessionToken != tc.Creds.SessionToken {
			t.Errorf("Got different sessionToken; got %s, expected %s", creds.SessionToken, tc.Creds.SessionToken)
		}
		if expires != testExpectedExpiresTime {
			t.Errorf("Wrong expires time; Expected %s, got %s", testExpectedExpiresTime, expires)
		}
	}
}