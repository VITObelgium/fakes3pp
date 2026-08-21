package s3

import (
	"log/slog"
	"net/http"
	"sync"

	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/VITObelgium/fakes3pp/requestctx"
)

// ConcurrencyLimitMiddleware caps simultaneous in-flight S3 proxy requests.
//
// Two independent limits can be combined:
//   - per-IP: a single client IP may have at most N requests in flight at
//     the same time.
//   - global: hard ceiling on the total number of in-flight requests across
//     all IPs.
//
// When either limit is exceeded the request is rejected immediately with
// HTTP 503 and XML body <Code>SlowDown</Code>, which matches the real AWS S3
// throttle response. Both aws-sdk-go and boto3 implement automatic
// retry-with-exponential-backoff for 503, so well-behaved clients back off
// without application-level changes.
//
// # Client IP resolution
//
// The per-IP key is taken from requestctx.GetSourceIP, which honours the
// trust-aware IP resolution configured via requestctx.SetTrustedProxies.
// X-Forwarded-For / X-Real-Ip are only used when the direct TCP peer is in
// the trusted proxy set; otherwise RemoteAddr is used and a WARN is logged.
// This prevents a client from spoofing its IP to bypass the per-IP cap.
type ConcurrencyLimitMiddleware struct {
	// perIPLimit is the maximum number of concurrent requests per client IP.
	// 0 means no per-IP limit.
	perIPLimit int

	mu         sync.Mutex
	perIPCount map[string]int

	// globalSemaphore is a buffered channel used as a counting semaphore for
	// the global in-flight cap. nil means no global limit.
	globalSemaphore chan struct{}
}

// NewConcurrencyLimitMiddleware builds a ConcurrencyLimitMiddleware.
// perIPLimit <= 0 disables the per-IP check.
// globalLimit <= 0 disables the global check.
func NewConcurrencyLimitMiddleware(perIPLimit, globalLimit int) (*ConcurrencyLimitMiddleware, error) {
	m := &ConcurrencyLimitMiddleware{
		perIPLimit: perIPLimit,
		perIPCount: make(map[string]int),
	}
	if globalLimit > 0 {
		m.globalSemaphore = make(chan struct{}, globalLimit)
	}
	return m, nil
}

// Middleware returns a middleware.Middleware that enforces the configured
// concurrency limits. It must be placed after LogMiddleware in the chain so
// that requestctx.GetSourceIP has a populated RemoteIP to work with, but
// before authentication so the auth path is also protected.
func (m *ConcurrencyLimitMiddleware) Middleware() middleware.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// --- Global limit ---
			// Try to acquire a slot without blocking. If the channel is full
			// the global cap is exceeded and we reject immediately.
			if m.globalSemaphore != nil {
				select {
				case m.globalSemaphore <- struct{}{}:
					defer func() { <-m.globalSemaphore }()
				default:
					slog.WarnContext(ctx, "Global concurrency limit reached, rejecting request",
						"limit", cap(m.globalSemaphore))
					writeS3ErrorResponse(ctx, w, ErrS3SlowDown, nil)
					return
				}
			}

			// --- Per-IP limit ---
			if m.perIPLimit > 0 {
				ip := requestctx.GetSourceIP(r)
				m.mu.Lock()
				if m.perIPCount[ip] >= m.perIPLimit {
					m.mu.Unlock()
					slog.WarnContext(ctx, "Per-IP concurrency limit reached, rejecting request",
						"ip", ip, "limit", m.perIPLimit)
					writeS3ErrorResponse(ctx, w, ErrS3SlowDown, nil)
					return
				}
				m.perIPCount[ip]++
				m.mu.Unlock()

				defer func() {
					m.mu.Lock()
					m.perIPCount[ip]--
					if m.perIPCount[ip] == 0 {
						delete(m.perIPCount, ip)
					}
					m.mu.Unlock()
				}()
			}

			next(w, r)
		}
	}
}
