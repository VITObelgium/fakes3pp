package httptracking

import (
	"net/http"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

//A writer that updates a requestCtx with the details of the response
type trackingResponseWriter struct {
	rWriter    http.ResponseWriter
	requestCtx *requestctx.RequestCtx
}

// NewTrackingResponseWriter creates a new writer that delegate writes to the wrapped writer
// but that keeps track of the written bytes.
func NewTrackingResponseWriter(w http.ResponseWriter, rCtx *requestctx.RequestCtx) *trackingResponseWriter {
	return &trackingResponseWriter{
		rWriter:      w,
		requestCtx:   rCtx,
	}
}

func (w *trackingResponseWriter) Write(b []byte) (int, error) {
	n, err := w.rWriter.Write(b)
	w.requestCtx.BytesSent += uint64(n)
	return n, err
}

func (w *trackingResponseWriter) Header() http.Header {
	return w.rWriter.Header()
}

func (w *trackingResponseWriter) WriteHeader(statusCode int) {
	w.requestCtx.HTTPStatus = statusCode
	w.rWriter.WriteHeader(statusCode)
}