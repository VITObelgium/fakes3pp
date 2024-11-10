package requestutils_test

import (
	"net/http"
	"testing"

	url "github.com/VITObelgium/fakes3pp/requestutils"
)

func TestGetUrlFromRequest(t *testing.T) {
	var testCasesValidUrls = []struct{
		Description string
		Url         string
	}{
		{
			"Temporary credentials Url",
			"https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
		},
		{
			"Permanent credentials Url",
			"https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=O%2FybXwQdy0cISlo6ly4Lit6s%2BlE%3D&Expires=1727389975",
 		},
	}

	for _, tc := range testCasesValidUrls {
		req := buildGetRequest(tc.Url, t)
		u := url.FullUrlFromRequest(req)
		if u != tc.Url {
			t.Errorf("%s: Got %s, expected %s", tc.Description, u, tc.Url)
		}
	}
}


func buildGetRequest(url string, t *testing.T) *http.Request {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	return req
}