package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/VITObelgium/fakes3pp/httptracking"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/requestctx/authtypes"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

//The log Middleware has as responsibility to make sure to allow for:
// 1. tracking requests via an X-Request-ID header
// 2. creating an access log
//It will enrich the request Context with a requestctx object such that
//other components can have enriched logging.
//It takes a healthcheck function because health checks should not follow other log
//semantics.
func LogMiddleware(requestLogLvl slog.Level, hc HealthChecker, promReg prometheus.Registerer) Middleware {
	var buckets  []float64
	var requestsTotal *prometheus.CounterVec
	var requestDuration *prometheus.HistogramVec
	var requestSize *prometheus.CounterVec
	var responseSize *prometheus.CounterVec
	var requestsFinished *prometheus.CounterVec
	var requestsFailed *prometheus.CounterVec
	if promReg != nil {
		requestsTotal = promauto.With(promReg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_started_total",
				Help: "Tracks the number of HTTP requests.",
			}, []string{"method"},
		)
		requestDuration = promauto.With(promReg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Tracks the latencies for HTTP requests.",
				Buckets: buckets,
			},
			[]string{"operation"},
		)
		requestSize = promauto.With(promReg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_request_size_bytes",
				Help: "Tracks the size of HTTP requests.",
			},
			[]string{"operation"},
		)
		responseSize = promauto.With(promReg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_response_size_bytes",
				Help: "Tracks the size of HTTP responses.",
			},
			[]string{"operation"},
		)
		requestsFinished = promauto.With(promReg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_finished_total",
				Help: "Tracks the number of HTTP requests.",
			}, []string{"method", "operation"},
		)
		requestsFailed = promauto.With(promReg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_failed_total",
				Help: "Tracks the number of HTTP requests that failed.",
			}, []string{"code"},
		)
	}
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()
            //At the final end discard what is being sent.
			//If not some clients might not check the response that is being sent and hang untill timeout
			//An example is boto3 where urllib3 won't check the response if it is still sending data
			if r.Body != nil {
				defer r.Body.Close()
			}
			
			//Make sure we have a requestctx to know about RequestId and to track information
			ctx := requestctx.NewContextFromHttpRequestWithStartTime(r, startTime)
			rCtx, ok := requestctx.FromContext(ctx)
			if !ok {
				panic("Programmer going crazy this cannot happen requestctx must be extractable.")
			}
			r = r.WithContext(ctx)
			trackingW := httptracking.NewTrackingResponseWriter(w, rCtx)
			r.Body = httptracking.NewTrackingBody(r.Body, rCtx)

			logLvl := requestLogLvl
			wasHealthCheck := hc.DoHealthcheckIfNeeded(trackingW, r)
			if wasHealthCheck {
				//For health checks there might be a different level at which logging should occur
				logLvl = hc.GetHCLogLvl()
			}

			slog.LogAttrs(
				ctx,
				logLvl,
				"Request start",
				getRequestCtxLogAttrs(rCtx)...
			)
			slog.DebugContext(
				ctx, "Extra debug details", 
				"contentLength", r.ContentLength,
				"TransferEncoding", r.TransferEncoding,
			)
			defer logFinalRequestDetails(ctx, logLvl, startTime, rCtx)

			if !wasHealthCheck{
				if promReg != nil {
					//We can increase the request counter already
					lbls := prometheus.Labels{"method": r.Method}
					requestsTotal.With(lbls).Inc()
					//But end of action metrics we must defer to the final stage
					defer func() {
						operation := ""
						if rCtx.Operation != nil {
							operation = rCtx.Operation.String()
						}
						opLabel := prometheus.Labels{"operation": operation}
						requestDuration.With(opLabel).Observe(time.Since(startTime).Seconds())
						requestSize.With(opLabel).Add(float64(rCtx.BytesReceived))
						responseSize.With(opLabel).Add(float64(rCtx.BytesSent))
						opmetLabels := prometheus.Labels{"operation": operation, "method": r.Method}
						requestsFinished.With(opmetLabels).Inc()

						if rCtx.Error != nil {
							errLabel := prometheus.Labels{"code": rCtx.Error.String()}
							requestsFailed.With(errLabel).Inc()
						}
					}()
				}
				next.ServeHTTP(trackingW, r.WithContext(ctx))
			}
        }
    }
}

func logFinalRequestDetails(ctx context.Context, lvl slog.Level, startTime time.Time, rCtx *requestctx.RequestCtx) {
	requestLogAttrs := getRequestCtxLogAttrs(rCtx)
	requestLogAttrs = append(requestLogAttrs, slog.Int64("Total ms", time.Since(startTime).Milliseconds()))
	requestLogAttrs = append(requestLogAttrs, slog.Uint64("Bytes sent", rCtx.BytesSent))
	requestLogAttrs = append(requestLogAttrs, slog.Uint64("Bytes received", rCtx.BytesReceived))
	operation := "unknown"
	if rCtx.Operation != nil {
		operation = rCtx.Operation.String()
	}
	requestLogAttrs = append(requestLogAttrs, slog.String("Operation", operation))
	requestLogAttrs = append(requestLogAttrs, slog.String("Error", rCtx.Error.String()))
	requestLogAttrs = append(requestLogAttrs, slog.Int("HTTP status", rCtx.HTTPStatus))
	requestLogAttrs = append(requestLogAttrs, slog.String(authtypes.L_AUTH_TYPE, rCtx.AuthType.String()))
	requestLogAttrs = append(requestLogAttrs, rCtx.GetAccessLogInfo()...)
	slog.LogAttrs(
		ctx,
		lvl,
		"Request end",
		requestLogAttrs...
	)
}


func getRequestCtxLogAttrs(r *requestctx.RequestCtx) (logAttrs []slog.Attr) {
	logAttrs = append(logAttrs, slog.Time("StartTime", r.Time))
	logAttrs = append(logAttrs, slog.String("RemoteIP", r.RemoteIP))
	logAttrs = append(logAttrs, slog.String("RequestURI", r.RequestURI))
	logAttrs = append(logAttrs, slog.String("Referer", r.Referer))
	logAttrs = append(logAttrs, slog.String("UserAgent", r.UserAgent))
	logAttrs = append(logAttrs, slog.String("Host", r.Host))
	return logAttrs
}