package cmd

import (
	"net/http"
	"testing"
)


func TestCaptilizeFirstLetter(t *testing.T) {
	testCases := []struct {
        Description string
		input       string
		expected    string
	}{
		{
			"Starts with letter must capitalize",
			"hello world",
			"Hello world",
		},
		{
			"Starts with capital letter must noop",
			"Hello world",
			"Hello world",
		},
		{
			"Starts with digit must noop",
			"1hello world",
			"1hello world",
		},
		{
			"Starts with special character must noop",
			"{hello world}",
			"{hello world}",
		},
	}

	for _, tc := range testCases {
		result := capitalizeFirstLetter(tc.input)
		if result != tc.expected {
			t.Errorf("Got %s, expected %s", result, tc.expected)
		}
	}
}

func buildRequest(url string, t *testing.T) *http.Request {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	return req
}

func TestGetUrlFromRequest(t *testing.T) {
	var testCasesValidUrls = []struct{
		Description string
		Url         string
	}{
		{
			"Temporary credentials Url",
			testExpectedPresignedUrlTemp,
		},
		{
			"Permanent credentials Url",
			testExpectedPresignedUrlPerm,
 		},
	}

	for _, tc := range testCasesValidUrls {
		req := buildRequest(tc.Url, t)
		u := fullUrlFromRequest(req)
		if u != tc.Url {
			t.Errorf("%s: Got %s, expected %s", tc.Description, u, tc.Url)
		}
	}
}

func TestB32Symmetry(t *testing.T) {
	testString := "Just for testing"
	calculated, err := b32_decode(b32(testString))
	if err != nil {
		t.Error(err)
	}
	if testString != calculated {
		t.Errorf("Expected %s, got %s", testString, calculated)
	}
}