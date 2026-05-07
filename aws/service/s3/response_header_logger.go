package s3

import (
	"log/slog"
	"net/http"

	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/VITObelgium/fakes3pp/requestctx"
)

// LogResponseHeaders returns a Middleware that, after the downstream handler
// has run, inspects the response headers and logs any header whose name
// appears in the configured list under the "s3" access-log group.
//
// Header names are matched case-insensitively (Go's net/http canonicalises
// them on the wire) but logged exactly as the operator configured them so
// that the log output matches whatever the operator typed.
//
// If a header from the list is absent in the response it is silently skipped;
// no empty-valued attribute is emitted.
//
// When headers is empty the returned middleware is a no-op pass-through.
func LogResponseHeaders(headers []string) middleware.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			next(w, r)

			if len(headers) == 0 {
				return
			}

			for _, name := range headers {
				value := w.Header().Get(name)
				if value == "" {
					continue
				}
				// Log under the "s3" group so it lands in the existing S3
				// sub-group of the "Request end" access-log entry.
				requestctx.AddAccessLogInfo(r, "s3", slog.String(name, value))
			}
		}
	}
}
