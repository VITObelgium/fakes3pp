package requestutils_test

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	url "github.com/VITObelgium/fakes3pp/requestutils"
)

func TestGetUrlFromRequest(t *testing.T) {
	var testCasesValidUrls = []struct {
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

func TestCompareRequestWithUrl(t *testing.T) {
	var testCases = []struct {
		Description  string
		Url          string
		Req          *http.Request
		isSameScheme bool
		isSameHost   bool
		isSamePath   bool
		isSameQuery  bool
		errContains  string // String representation of the error should contain this
	}{
		{
			"Temporary credentials Url identical",
			"https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
			buildGetRequest("https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975", t),
			true,
			true,
			true,
			true,
			"",
		},
		{
			"Temporary credentials Url invalid input url",
			"://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
			buildGetRequest("https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975", t),
			true,
			true,
			true,
			true,
			"missing protocol scheme",
		},
		{
			"Temporary credentials Url scheme differs",
			"http://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
			buildGetRequest("https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975", t),
			false,
			true,
			true,
			true,
			"",
		},
		{
			"Temporary credentials Url host differs",
			"https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
			buildGetRequest("https://s3.test2.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975", t),
			true,
			false,
			true,
			true,
			"",
		},
		{
			"Temporary credentials url path mismatch",
			"https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
			buildGetRequest("https://s3.test.com/my-bucket/path/to/my_custom_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975", t),
			true,
			true,
			false,
			true,
			"",
		},
		{
			"Temporary credentials Url query values permutated",
			"https://s3.test.com/my-bucket/path/to/my_file?Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&AWSAccessKeyId=0123455678910abcdef09459&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
			buildGetRequest("https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975", t),
			true,
			true,
			true,
			true,
			"",
		},
		{
			"Temporary credentials Url more query_parameters in url",
			"https://s3.test.com/my-bucket/path/to/my_file?test=a&AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
			buildGetRequest("https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975", t),
			true,
			true,
			true,
			false,
			"",
		},
		{
			"Temporary credentials Url multiple_values for a aprameter",
			"https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
			buildGetRequest("https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975", t),
			true,
			true,
			true,
			false,
			"",
		},
		{
			"Temporary credentials Url mismatch in value",
			"https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=fake&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
			buildGetRequest("https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975", t),
			true,
			true,
			true,
			false,
			"",
		},
		{
			"Temporary credentials Url typo in key",
			"https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKey=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975",
			buildGetRequest("https://s3.test.com/my-bucket/path/to/my_file?AWSAccessKeyId=0123455678910abcdef09459&Signature=UAK8QHRI55lzlVoLFM6Fj7T98a8%3D&x-amz-security-token=FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT&Expires=1727389975", t),
			true,
			true,
			true,
			false,
			"",
		},
	}
	slog.SetLogLoggerLevel(slog.LevelDebug)
	for _, tc := range testCases {
		fail := func(reason string) {
			t.Errorf("%s: %s", tc.Description, reason)
			t.FailNow()
		}

		isSameScheme, isSameHost, isSamePath, isSameQuery, err := url.CompareRequestWithUrl(tc.Req, tc.Url)
		if tc.errContains != "" || err != nil {
			if !strings.Contains(err.Error(), tc.errContains) {
				fail(fmt.Sprintf("error is not meeting expectation: got %s", err))
			}
		} else {
			if tc.isSameScheme != isSameScheme {
				fail("scheme not meeting expectation")
			}

			if tc.isSameHost != isSameHost {
				fail("host not meeting expectation")
			}

			if tc.isSamePath != isSamePath {
				fail("path not meeting expectation")
			}

			if tc.isSameQuery != isSameQuery {
				fail("query not meeting expectation")
			}
		}
	}
}
