package s3

import (
	"net/http"
	"testing"

	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/requestctx"
)

func TestForceRequesterPaysAddsHeaderForConfiguredBucket(t *testing.T) {
	mw := ForceRequesterPays(requesterPaysBuckets{"bucket1": {}}, &noVirtualHostRequestsType{})
	req, err := http.NewRequest(http.MethodGet, "https://localhost/bucket1/key", nil)
	if err != nil {
		t.Fatalf("Could not create request: %s", err)
	}
	req = req.WithContext(requestctx.NewContextFromHttpRequest(req))

	mw(func(_ http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(constants.AmzRequestPayerKey); got != constants.AmzRequestPayerRequesterValue {
			t.Fatalf("Expected requester pays header to be set, got %q", got)
		}
	})(nil, req)
}

func TestForceRequesterPaysSkipsNonConfiguredBucket(t *testing.T) {
	mw := ForceRequesterPays(requesterPaysBuckets{"bucket1": {}}, &noVirtualHostRequestsType{})
	req, err := http.NewRequest(http.MethodGet, "https://localhost/bucket2/key", nil)
	if err != nil {
		t.Fatalf("Could not create request: %s", err)
	}
	req = req.WithContext(requestctx.NewContextFromHttpRequest(req))

	mw(func(_ http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(constants.AmzRequestPayerKey); got != "" {
			t.Fatalf("Expected requester pays header to stay empty, got %q", got)
		}
	})(nil, req)
}

func TestForceRequesterPaysSkipsListBuckets(t *testing.T) {
	mw := ForceRequesterPays(requesterPaysBuckets{"bucket1": {}, "": {}}, &noVirtualHostRequestsType{})
	req, err := http.NewRequest(http.MethodGet, "https://localhost/", nil)
	if err != nil {
		t.Fatalf("Could not create request: %s", err)
	}
	req = req.WithContext(requestctx.NewContextFromHttpRequest(req))

	mw(func(_ http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(constants.AmzRequestPayerKey); got != "" {
			t.Fatalf("Expected requester pays header to stay empty, got %q", got)
		}
	})(nil, req)
}
