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

// TestGetSourceIP_NoTrustedProxies verifies that when no trusted proxies are
// configured, forwarding headers are never used: RemoteAddr is always the
// result.
func TestGetSourceIP_NoTrustedProxies(t *testing.T) {
	// Ensure no trusted proxies are set for this test.
	if err := requestctx.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requestctx.SetTrustedProxies(nil) })

	cases := []struct {
		desc       string
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		{"plain host:port, no forwarding headers", "192.0.2.1:54321", "", "", "192.0.2.1"},
		{"plain host without port", "192.0.2.2", "", "", "192.0.2.2"},
		{"XFF present but peer untrusted — ignored", "10.0.0.1:80", "203.0.113.7", "", "10.0.0.1"},
		{"X-Real-IP present but peer untrusted — ignored", "10.0.0.1:80", "", "198.51.100.42", "10.0.0.1"},
		{"both headers present but peer untrusted — ignored", "10.0.0.1:80", "203.0.113.7", "198.51.100.42", "10.0.0.1"},
		{"IPv6 host:port, no forwarding headers", "[2001:db8::1]:443", "", "", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			r := newReq(t, tc.remoteAddr, tc.xff, tc.xRealIP)
			if got := requestctx.GetSourceIP(r); got != tc.want {
				t.Fatalf("want %q got %q", tc.want, got)
			}
		})
	}
}

// TestGetSourceIP_WithTrustedProxy verifies that forwarding headers are
// honoured when the direct peer is in the trusted set, and still ignored
// when it is not.
func TestGetSourceIP_WithTrustedProxy(t *testing.T) {
	if err := requestctx.SetTrustedProxies([]string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requestctx.SetTrustedProxies(nil) })

	cases := []struct {
		desc       string
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		// --- single-hop cases ---
		{
			desc:       "trusted peer: XFF single value",
			remoteAddr: "10.0.0.1:80", xff: "203.0.113.7",
			want: "203.0.113.7",
		},
		{
			desc:       "trusted peer: XFF trims whitespace",
			remoteAddr: "10.0.0.1:80", xff: "  203.0.113.7  ",
			want: "203.0.113.7",
		},
		{
			desc:       "trusted peer: X-Real-IP when XFF absent",
			remoteAddr: "10.0.0.1:80", xRealIP: "198.51.100.42",
			want: "198.51.100.42",
		},
		{
			desc:       "trusted peer: XFF wins over X-Real-IP",
			remoteAddr: "10.0.0.1:80", xff: "203.0.113.7", xRealIP: "198.51.100.42",
			want: "203.0.113.7",
		},
		{
			desc:       "trusted peer: no forwarding headers — RemoteAddr used",
			remoteAddr: "10.0.0.5:9000",
			want:       "10.0.0.5",
		},

		// --- right-to-left XFF chain cases ---
		{
			// Chain: real-client → untrusted-proxy → trusted-proxy → us
			// Right-to-left: skip 10.0.0.2 (trusted), return 198.51.100.2 (first untrusted)
			desc:       "XFF chain: rightmost untrusted entry is returned",
			remoteAddr: "10.0.0.1:80",
			xff:        "203.0.113.7, 198.51.100.2, 10.0.0.2",
			want:       "198.51.100.2",
		},
		{
			// Spoofing attempt: client prepends a fake IP before the real chain
			// reaches the trusted proxy.
			// Right-to-left: skip 10.0.0.2 (trusted), return 203.0.113.7 (first untrusted).
			// "spoofed" is never reached.
			desc:       "XFF chain: spoofed leftmost entry is never reached",
			remoteAddr: "10.0.0.1:80",
			xff:        "spoofed, 203.0.113.7, 10.0.0.2",
			want:       "203.0.113.7",
		},
		{
			// All entries in XFF are trusted proxies → fall back to leftmost (true origin).
			desc:       "XFF chain: all trusted proxies — leftmost returned",
			remoteAddr: "10.0.0.1:80",
			xff:        "10.0.0.5, 10.0.0.3, 10.0.0.2",
			want:       "10.0.0.5",
		},
		{
			// Single trusted entry in XFF → leftmost fallback applies.
			desc:       "XFF chain: single trusted entry — leftmost returned",
			remoteAddr: "10.0.0.1:80",
			xff:        "10.0.0.9",
			want:       "10.0.0.9",
		},

		// --- untrusted peer ---
		{
			desc:       "untrusted peer: XFF ignored",
			remoteAddr: "172.16.0.1:80", xff: "203.0.113.99",
			want: "172.16.0.1",
		},
		{
			desc:       "untrusted peer: X-Real-IP ignored",
			remoteAddr: "192.168.1.1:80", xRealIP: "203.0.113.99",
			want: "192.168.1.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			r := newReq(t, tc.remoteAddr, tc.xff, tc.xRealIP)
			if got := requestctx.GetSourceIP(r); got != tc.want {
				t.Fatalf("want %q got %q", tc.want, got)
			}
		})
	}
}

// TestGetSourceIP_BareIPTrustedProxy verifies that a bare IP (no CIDR) works
// as a trusted proxy entry.
func TestGetSourceIP_BareIPTrustedProxy(t *testing.T) {
	if err := requestctx.SetTrustedProxies([]string{"10.1.2.3"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = requestctx.SetTrustedProxies(nil) })

	r := newReq(t, "10.1.2.3:5000", "203.0.113.1", "")
	if got := requestctx.GetSourceIP(r); got != "203.0.113.1" {
		t.Fatalf("want 203.0.113.1 got %q", got)
	}

	// A different IP in the same /24 is NOT trusted (bare IP = /32).
	r2 := newReq(t, "10.1.2.4:5000", "203.0.113.1", "")
	if got := requestctx.GetSourceIP(r2); got != "10.1.2.4" {
		t.Fatalf("want 10.1.2.4 (XFF should be ignored) got %q", got)
	}
}

// TestSetTrustedProxies_RejectsInvalidCIDR ensures construction-time
// validation is surfaced immediately.
func TestSetTrustedProxies_RejectsInvalidCIDR(t *testing.T) {
	err := requestctx.SetTrustedProxies([]string{"not-an-ip-or-cidr"})
	if err == nil {
		t.Fatal("expected error for invalid entry, got nil")
	}
}

// newReq creates a minimal *http.Request for testing.
func newReq(t *testing.T, remoteAddr, xff, xRealIP string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "http://example/", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if xRealIP != "" {
		r.Header.Set("X-Real-Ip", xRealIP)
	}
	return r
}
