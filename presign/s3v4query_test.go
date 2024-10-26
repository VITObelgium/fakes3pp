package presign

import (
	"context"
	"net/http"
	"testing"

	"github.com/VITObelgium/fakes3pp/constants"
)

//Logging of CONTENT GENERATION (see hmacv1query_test.go for origin of these values)

// export AWS_ACCESS_KEY_ID="0123455678910abcdef09459"
// export AWS_SECRET_ACCESS_KEY="YWUzOTQyM2FlMDMzNDlkNjk0M2FmZDE1OWE1ZGRkMT"
// export AWS_SESSION_TOKEN="FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT"
// export AWS_ENDPOINT_URL_S3="https://s3.test.com"
// # For eu-west-1 (euw1)
// aws s3 presign "s3://my-bucket/path/to/my_file" --expires-in 7200  --endpoint-url "https://s3.test.com"
// # For eu-central-1 (euc1)
// aws s3 presign "s3://my-bucket/path/to/my_file" --expires-in 7200  --endpoint-url "https://s3.test.com" --region eu-central-1

//Gave following output
var testAwsCliPresignedUrlEuw1 = "https://s3.test.com/my-bucket/path/to/my_file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=0123455678910abcdef09459%2F20241009%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Date=20241009T082516Z&X-Amz-Expires=7200&X-Amz-SignedHeaders=host&X-Amz-Security-Token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&X-Amz-Signature=1b93b39ab2886ac528aa17afe626e6c864ee27c705ece48079c01205ffad518a"
var testSigningDateEuw1 = "20241009T082516Z"
var testExpirySeconds = 7200
var testAwsCliPresignedUrlEuc1 = "https://s3.test.com/my-bucket/path/to/my_file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=0123455678910abcdef09459%2F20241009%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20241009T115034Z&X-Amz-Expires=7200&X-Amz-SignedHeaders=host&X-Amz-Security-Token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&X-Amz-Signature=37cd817733138b7f5ba295615b0b7a5ed467b52af6b32a0ad930fcf6ceca76d9"
var testSigningDateEuc1 = "20241009T115034Z"

//END OF GENERATED CONTENT


func TestAwsCliGeneratedURLMustWork(t *testing.T) {
	var testCases = []struct{
		RegionName  string
		ExpectedUrl string
		SignDateStr string
	}{
		{
			"eu-west-1",
			testAwsCliPresignedUrlEuw1,
			testSigningDateEuw1,
		},
		{
			"eu-central-1",
			testAwsCliPresignedUrlEuc1,
			testSigningDateEuc1,
		},
	}
	// Given the credentials used to generate the URL
	creds := testCredsTemp
	ctx := context.Background()



	for _, tc := range testCases {
		signDate, err := XAmzDateToTime(tc.SignDateStr)
		if err != nil {
			t.Errorf("Could not convert signint date: %s", err)
			t.FailNow()
		}

		req, err := http.NewRequest(http.MethodGet, tc.ExpectedUrl, nil)
		queryP := req.URL.Query()
		queryP.Del(constants.AmzSignatureKey)
		req.URL.RawQuery = queryP.Encode()
		if err != nil {
			t.Errorf("Could not create request: %s", err)
			t.FailNow()
		}
	
		signedUri, _, err := PreSignRequestWithCreds(ctx, req, testExpirySeconds, signDate, creds)
		if err != nil {
			t.Errorf("Did not expect error. Got %s", err)
		}
		if s, err := haveSameSigv4QuerySignature(signedUri, tc.ExpectedUrl); !s || err != nil {
			t.Errorf("Mismatch signature:\nGot     :%s\nExpected:%s", signedUri, tc.ExpectedUrl)
		}
	}
}