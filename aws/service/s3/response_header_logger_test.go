package s3

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

// handlerWithResponseHeaders returns an http.HandlerFunc that writes the
// supplied headers into the response and replies 200 OK.
func handlerWithResponseHeaders(headers map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
	}
}

// applyLogResponseHeaders is a test helper that runs the LogResponseHeaders
// middleware around a handler that sets known response headers, records the
// request through a requestctx, and returns the resulting access-log attrs
// stored under the "s3" group.
func applyLogResponseHeaders(
	t testing.TB,
	trackedHeaders []string,
	responseHeaders map[string]string,
) []slog.Attr {
	t.Helper()

	inner := handlerWithResponseHeaders(responseHeaders)
	wrapped := LogResponseHeaders(trackedHeaders)(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := requestctx.NewContextFromHttpRequest(req)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	wrapped(rr, req)

	rCtx, ok := requestctx.FromContext(ctx)
	if !ok {
		t.Fatal("requestctx not found in context")
	}
	return rCtx.GetAccessLogInfo()
}

// findS3GroupAttrs extracts the attributes inside the "s3" slog.Group from a
// flat slice of slog.Attr values returned by GetAccessLogInfo.
func findS3GroupAttrs(attrs []slog.Attr) []slog.Attr {
	for _, a := range attrs {
		if a.Key == "s3" {
			return a.Value.Group()
		}
	}
	return nil
}

// attrValue returns the string value of the first attr with the given key, or
// an empty string if not found.
func attrValue(attrs []slog.Attr, key string) string {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value.String()
		}
	}
	return ""
}

// TestLogResponseHeaders_PresentHeadersAreLogged verifies that headers which
// are both configured and present in the response appear under the "s3" group.
func TestLogResponseHeaders_PresentHeadersAreLogged(t *testing.T) {
	tracked := []string{"x-ratelimit-remaining", "x-ratelimit-limit"}
	responseHdrs := map[string]string{
		"x-ratelimit-remaining": "42",
		"x-ratelimit-limit":     "100",
	}

	logAttrs := applyLogResponseHeaders(t, tracked, responseHdrs)
	s3Attrs := findS3GroupAttrs(logAttrs)

	if got := attrValue(s3Attrs, "x-ratelimit-remaining"); got != "42" {
		t.Errorf("x-ratelimit-remaining: want %q, got %q", "42", got)
	}
	if got := attrValue(s3Attrs, "x-ratelimit-limit"); got != "100" {
		t.Errorf("x-ratelimit-limit: want %q, got %q", "100", got)
	}
}

// TestLogResponseHeaders_AbsentHeadersAreNotLogged verifies that a configured
// header that is NOT present in the response does not produce an attribute at
// all (no empty-valued noise in the log).
func TestLogResponseHeaders_AbsentHeadersAreNotLogged(t *testing.T) {
	tracked := []string{"x-ratelimit-remaining", "x-ratelimit-limit"}
	// Response only sets one of the two configured headers.
	responseHdrs := map[string]string{
		"x-ratelimit-limit": "100",
	}

	logAttrs := applyLogResponseHeaders(t, tracked, responseHdrs)
	s3Attrs := findS3GroupAttrs(logAttrs)

	// "x-ratelimit-limit" must be present.
	if got := attrValue(s3Attrs, "x-ratelimit-limit"); got != "100" {
		t.Errorf("x-ratelimit-limit: want %q, got %q", "100", got)
	}

	// "x-ratelimit-remaining" must NOT be present (no empty attr).
	for _, a := range s3Attrs {
		if a.Key == "x-ratelimit-remaining" {
			t.Errorf("expected no attribute for absent header x-ratelimit-remaining, got %q", a.Value.String())
		}
	}
}

// TestLogResponseHeaders_EmptyListIsNoOp verifies that when no headers are
// configured the middleware adds nothing to the access log.
func TestLogResponseHeaders_EmptyListIsNoOp(t *testing.T) {
	responseHdrs := map[string]string{
		"x-ratelimit-remaining": "42",
	}

	logAttrs := applyLogResponseHeaders(t, nil, responseHdrs)
	s3Attrs := findS3GroupAttrs(logAttrs)

	if len(s3Attrs) != 0 {
		t.Errorf("expected no s3 log attrs for empty header list, got %v", s3Attrs)
	}
}

// TestLogResponseHeaders_HeaderNameLoggedAsConfigured verifies that the key in
// the log entry matches exactly what the operator configured, preserving their
// chosen casing rather than the HTTP canonical form.
func TestLogResponseHeaders_HeaderNameLoggedAsConfigured(t *testing.T) {
	// Operator configures lower-case; Go's net/http canonicalises the header to
	// "X-Ratelimit-Remaining" on the wire, but the log key must stay as typed.
	tracked := []string{"x-ratelimit-remaining"}
	responseHdrs := map[string]string{"x-ratelimit-remaining": "7"}

	logAttrs := applyLogResponseHeaders(t, tracked, responseHdrs)
	s3Attrs := findS3GroupAttrs(logAttrs)

	found := false
	for _, a := range s3Attrs {
		if a.Key == "x-ratelimit-remaining" {
			found = true
			if a.Value.String() != "7" {
				t.Errorf("value: want %q, got %q", "7", a.Value.String())
			}
		}
		// Make sure the canonical form is NOT the key that was stored.
		if a.Key == "X-Ratelimit-Remaining" {
			t.Errorf("header key was canonicalised to %q; want configured form %q", a.Key, "x-ratelimit-remaining")
		}
	}
	if !found {
		t.Errorf("attribute %q not found in s3 log attrs %v", "x-ratelimit-remaining", s3Attrs)
	}
}

// TestLogResponseHeaders_HeaderNameLoggedAsConfigured verifies that the key in
// the log entry matches exactly what the operator configured, preserving their
// chosen casing rather than the HTTP canonical form.
func TestLogResponseHeaders_HeaderNameLoggedAsConfiguredEvenIfResponseDiffersCasing(t *testing.T) {
	// Operator configures lower-case; Go's net/http canonicalises the header to
	// "X-Ratelimit-Remaining" on the wire, but the log key must stay as typed.
	tracked := []string{"x-ratelimit-remaining"}
	responseHdrs := map[string]string{"X-Ratelimit-Remaining": "7"}

	logAttrs := applyLogResponseHeaders(t, tracked, responseHdrs)
	s3Attrs := findS3GroupAttrs(logAttrs)

	found := false
	for _, a := range s3Attrs {
		if a.Key == "x-ratelimit-remaining" {
			found = true
			if a.Value.String() != "7" {
				t.Errorf("value: want %q, got %q", "7", a.Value.String())
			}
		}
		// Make sure the canonical form is NOT the key that was stored.
		if a.Key == "X-Ratelimit-Remaining" {
			t.Errorf("header key was canonicalised to %q; want configured form %q", a.Key, "x-ratelimit-remaining")
		}
	}
	if !found {
		t.Errorf("attribute %q not found in s3 log attrs %v", "x-ratelimit-remaining", s3Attrs)
	}
}
