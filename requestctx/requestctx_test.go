package requestctx_test

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

func TestGetAccessLogStringInfo(t *testing.T) {
	//Given a new requestObject without context
	r, err := http.NewRequest(http.MethodGet, "http://www.google.be", strings.NewReader(""))
	if err != nil {
		t.Errorf("Could not create test request: %s", err)
		t.FailNow()
	}
	//When getting an entry we expect the empty string
	retrievedStr := requestctx.GetAccessLogStringInfo(r, "s3", "Bucket")
	expectedStr := ""

	//Then we should get an empty string since it did not exist
	if retrievedStr != expectedStr {
		t.Errorf("Expected '%s', got '%s'", expectedStr, retrievedStr)
		t.FailNow()
	}
}

func TestGetAccessLogStringInfoWhenSet(t *testing.T) {
	//Given a new requestObject with context
	r, err := http.NewRequest(http.MethodGet, "http://www.google.be", strings.NewReader(""))
	if err != nil {
		t.Errorf("Could not create test request: %s", err)
		t.FailNow()
	}
	testGroup := "s3"
	testKey := "myKey"
	testValue := "MyTestValue"
	ctx := requestctx.NewContextFromHttpRequestWithStartTime(r, time.Now())
	r = r.WithContext(ctx)
	rCtx, ok := requestctx.FromContext(ctx)
	if !ok {
		t.Errorf("Should never happen but could not get context after setting")
		t.FailNow()
	}
	rCtx.AddAccessLogInfo(testGroup, slog.String(testKey, testValue))

	//When getting an entry we expect the string that was set previously
	retrievedStr := requestctx.GetAccessLogStringInfo(r, testGroup, testKey)
	expectedStr := testValue

	//Then we should get the expected value
	if retrievedStr != expectedStr {
		t.Errorf("Expected '%s', got '%s'", expectedStr, retrievedStr)
		t.FailNow()
	}

	//Then a non-existent string should still return an empty value
	retrievedStr2 := requestctx.GetAccessLogStringInfo(r, "s3", "Bucket")
	expectedStr2 := ""

	if retrievedStr2 != expectedStr2 {
		t.Errorf("Expected '%s', got '%s'", expectedStr, retrievedStr)
		t.FailNow()
	}
}

func TestGetSourceIP(t *testing.T) {
	cases := []struct {
		desc       string
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		{"plain host:port", "192.0.2.1:54321", "", "", "192.0.2.1"},
		{"plain host without port", "192.0.2.2", "", "", "192.0.2.2"},
		{"X-Forwarded-For single", "10.0.0.1:80", "203.0.113.7", "", "203.0.113.7"},
		{"X-Forwarded-For chain takes first", "10.0.0.1:80", "203.0.113.7, 198.51.100.2, 10.0.0.1", "", "203.0.113.7"},
		{"X-Forwarded-For trims whitespace", "10.0.0.1:80", "  203.0.113.7  , 198.51.100.2", "", "203.0.113.7"},
		{"X-Real-IP fallback when XFF absent", "10.0.0.1:80", "", "198.51.100.42", "198.51.100.42"},
		{"X-Forwarded-For wins over X-Real-IP", "10.0.0.1:80", "203.0.113.7", "198.51.100.42", "203.0.113.7"},
		{"IPv6 host:port", "[2001:db8::1]:443", "", "", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "http://example/", strings.NewReader(""))
			if err != nil {
				t.Fatal(err)
			}
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xRealIP != "" {
				r.Header.Set("X-Real-Ip", tc.xRealIP)
			}
			if got := requestctx.GetSourceIP(r); got != tc.want {
				t.Fatalf("want %q got %q", tc.want, got)
			}
		})
	}
}
