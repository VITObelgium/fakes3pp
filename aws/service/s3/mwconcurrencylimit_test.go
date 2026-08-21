package s3

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

// okHandler writes HTTP 200 and is used as the "next" handler in all limiter
// middleware tests.
var okHandler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// newLimiterRequest builds a minimal *http.Request whose RemoteAddr is set.
// IP resolution for the per-IP limit relies on requestctx.GetSourceIP, so the
// request is given a full request context (as LogMiddleware would create it)
// so that RemoteIP is populated correctly.
func newLimiterRequest(remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	r.RemoteAddr = remoteAddr
	ctx := requestctx.NewContextFromHttpRequestWithStartTime(r, time.Now())
	return r.WithContext(ctx)
}

// responseCode executes the handler and returns the recorded status code.
func responseCode(handler http.HandlerFunc, r *http.Request) int {
	w := httptest.NewRecorder()
	handler(w, r)
	return w.Code
}

// ----------------------------------------------------------------------------
// Per-IP concurrency limit
// ----------------------------------------------------------------------------

func TestPerIPLimit_AllowsRequestsBelowLimit(t *testing.T) {
	m, _ := NewConcurrencyLimitMiddleware(2, 0)
	handler := m.Middleware()(okHandler)

	for i := 0; i < 2; i++ {
		r := newLimiterRequest("1.2.3.4:1000")
		if code := responseCode(handler, r); code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, code)
		}
	}
}

func TestPerIPLimit_RejectsRequestAtLimit(t *testing.T) {
	m, _ := NewConcurrencyLimitMiddleware(1, 0)

	// Hold a slot open by blocking the next handler on a channel.
	release := make(chan struct{})
	blocking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	handler := m.Middleware()(blocking)

	// First request — acquires the slot, blocks.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		responseCode(handler, newLimiterRequest("5.5.5.5:1001"))
	}()

	// Give the goroutine time to acquire the slot.
	waitForPerIPCount(m, "5.5.5.5", 1)

	// Second request from the same IP — slot is taken, must get 503.
	w := httptest.NewRecorder()
	handler(w, newLimiterRequest("5.5.5.5:1002"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when per-IP limit reached, got %d", w.Code)
	}

	// Unblock and verify slot is released.
	close(release)
	wg.Wait()
	m.mu.Lock()
	count := m.perIPCount["5.5.5.5"]
	m.mu.Unlock()
	if count != 0 {
		t.Errorf("expected per-IP count to be 0 after request finishes, got %d", count)
	}
}

func TestPerIPLimit_DifferentIPsAreIndependent(t *testing.T) {
	m, _ := NewConcurrencyLimitMiddleware(1, 0)

	// Hold IP1's slot open; IP2 completes immediately so we can check its
	// response code while IP1 is still in flight.
	release := make(chan struct{})
	blocking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestctx.GetSourceIP(r) == "10.0.0.1" {
			<-release
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := m.Middleware()(blocking)

	// First request from IP1 — acquires the slot and blocks.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		responseCode(handler, newLimiterRequest("10.0.0.1:100"))
	}()

	// Wait until IP1 is genuinely holding its slot.
	waitForPerIPCount(m, "10.0.0.1", 1)

	// Second request from a different IP — its own slot is free, must get 200
	// even though IP1 is still holding its slot concurrently.
	if code := responseCode(handler, newLimiterRequest("10.0.0.2:100")); code != http.StatusOK {
		t.Errorf("IP2: expected 200 while IP1 holds its slot, got %d", code)
	}

	close(release)
	wg.Wait()
}

func TestPerIPLimit_MapEntryRemovedAfterRequestCompletes(t *testing.T) {
	m, _ := NewConcurrencyLimitMiddleware(1, 0)
	handler := m.Middleware()(okHandler)

	responseCode(handler, newLimiterRequest("9.9.9.9:1000"))

	m.mu.Lock()
	_, exists := m.perIPCount["9.9.9.9"]
	m.mu.Unlock()
	if exists {
		t.Error("expected map entry to be removed after the request completes")
	}
}

// ----------------------------------------------------------------------------
// Global concurrency limit
// ----------------------------------------------------------------------------

func TestGlobalLimit_AllowsRequestsBelowLimit(t *testing.T) {
	m, _ := NewConcurrencyLimitMiddleware(0, 3)

	// Hold all slots open so we can verify all 3 are accepted concurrently
	// before any of them finishes.
	release := make(chan struct{})
	blocking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	handler := m.Middleware()(blocking)

	const n = 3
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = responseCode(handler, newLimiterRequest("1.2.3.4:1000"))
		}()
	}

	// Wait until all 3 requests are concurrently holding a global slot.
	waitForGlobalSemaphoreLen(m, n)

	close(release)
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, code)
		}
	}
}

func TestGlobalLimit_RejectsRequestWhenFull(t *testing.T) {
	m, _ := NewConcurrencyLimitMiddleware(0, 1)

	release := make(chan struct{})
	blocking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	handler := m.Middleware()(blocking)

	// First request — acquires the global slot, blocks.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		responseCode(handler, newLimiterRequest("1.1.1.1:100"))
	}()

	waitForGlobalSemaphoreLen(m, 1)

	// Second request — global cap reached, must get 503.
	w := httptest.NewRecorder()
	handler(w, newLimiterRequest("2.2.2.2:200"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when global limit reached, got %d", w.Code)
	}

	close(release)
	wg.Wait()
	if len(m.globalSemaphore) != 0 {
		t.Errorf("expected global semaphore to be empty after request finishes, got len=%d", len(m.globalSemaphore))
	}
}

// ----------------------------------------------------------------------------
// Combined per-IP + global limit
// ----------------------------------------------------------------------------

func TestCombinedLimits_GlobalBlocksEvenWhenPerIPFree(t *testing.T) {
	// Global=1, per-IP=5: second request from a different IP is blocked by
	// the global cap.
	m, _ := NewConcurrencyLimitMiddleware(5, 1)

	release := make(chan struct{})
	blocking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	handler := m.Middleware()(blocking)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		responseCode(handler, newLimiterRequest("1.1.1.1:1"))
	}()
	waitForGlobalSemaphoreLen(m, 1)

	// Different IP, per-IP count is 0, but global is full → 503.
	w := httptest.NewRecorder()
	handler(w, newLimiterRequest("2.2.2.2:2"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 from global cap, got %d", w.Code)
	}

	close(release)
	wg.Wait()
}

// ----------------------------------------------------------------------------
// NewConcurrencyLimitMiddleware — construction
// ----------------------------------------------------------------------------

func TestNewConcurrencyLimitMiddleware_NilSemaphoreWhenGlobalLimitZero(t *testing.T) {
	m, err := NewConcurrencyLimitMiddleware(0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.globalSemaphore != nil {
		t.Error("expected nil globalSemaphore when globalLimit=0")
	}
	if m.perIPLimit != 0 {
		t.Error("expected perIPLimit=0")
	}
}

// ----------------------------------------------------------------------------
// SlowDown response body
// ----------------------------------------------------------------------------

func TestSlowDown_ResponseBodyContainsSlowDownCode(t *testing.T) {
	m, _ := NewConcurrencyLimitMiddleware(1, 0)

	release := make(chan struct{})
	blocking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	handler := m.Middleware()(blocking)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		responseCode(handler, newLimiterRequest("7.7.7.7:1"))
	}()
	waitForPerIPCount(m, "7.7.7.7", 1)

	w := httptest.NewRecorder()
	handler(w, newLimiterRequest("7.7.7.7:2"))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
	body := w.Body.String()
	if body == "" {
		t.Error("expected non-empty response body")
	}
	if !containsSubstring(body, "SlowDown") {
		t.Errorf("expected body to contain SlowDown, got: %s", body)
	}

	close(release)
	wg.Wait()
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}

func waitForPerIPCount(m *ConcurrencyLimitMiddleware, ip string, want int) {
	for {
		m.mu.Lock()
		got := m.perIPCount[ip]
		m.mu.Unlock()
		if got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForGlobalSemaphoreLen(m *ConcurrencyLimitMiddleware, want int) {
	for {
		if len(m.globalSemaphore) >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
}
