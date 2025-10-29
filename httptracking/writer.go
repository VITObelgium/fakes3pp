package httptracking

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

// A writer that tracks status which helps statistics and also keeps the corresponding request
// This is because when writing to it we sometimes want to interact with the original request.
type trackingResponseWriter struct {
	rWriter    http.ResponseWriter
	requestCtx *requestctx.RequestCtx
	request    *http.Request
}

// NewTrackingResponseWriter creates a new writer that delegate writes to the wrapped writer
// but that keeps track of the written bytes.
func NewTrackingResponseWriter(w http.ResponseWriter, rCtx *requestctx.RequestCtx, request *http.Request) *trackingResponseWriter {
	return &trackingResponseWriter{
		rWriter:    w,
		requestCtx: rCtx,
		request:    request,
	}
}

func (w *trackingResponseWriter) Write(b []byte) (int, error) {
	n, err := w.rWriter.Write(b)
	if n < 1000000000000000 && w.requestCtx.BytesSent < 1000000000000000 {
		w.requestCtx.BytesSent += uint64(n)
	} else {
		slog.Warn("trackingResponseWriter wrote more than 1 peta-bytes request size will be wrong")
	}
	return n, err
}

func (w *trackingResponseWriter) Header() http.Header {
	return w.rWriter.Header()
}

func (w *trackingResponseWriter) WriteHeader(statusCode int) {
	w.requestCtx.HTTPStatus = statusCode
	w.rWriter.WriteHeader(statusCode)
}

func readAndDiscardAllFromConnectionBody(readable io.Reader, ctxDescription string, ctx context.Context) {
	if readable != nil {
		n, err := io.Copy(io.Discard, readable)
		if n == 0 && err == nil {
			return
		}
		if err != nil && err.Error() == "http: invalid Read on closed Body" {
			//Already closed so nothing to read anyway
			return
		}
		if ctx == nil {
			slog.Error("Closable had bytes", "ctxDescription", ctxDescription, "nrBytes", n, "error", err)
		} else {
			slog.ErrorContext(ctx, "Closable had bytes", "ctxDescription", ctxDescription, "nrBytes", n, "error", err)
		}
		return
	}
}

// For a writer that relates to a HTTP request make sure the corresponding
// request body has been read fully. WARNING: this discards the request body
// so this should only be used on error paths where no useful processing can be done
func (w *trackingResponseWriter) makeSafeToWrite(ctxDescription string) {
	readAndDiscardAllFromConnectionBody(w.request.Body, ctxDescription, w.request.Context())
}

type SafeWriter interface {
	makeSafeToWrite(ctxDescription string)
}

func MakeSafeToWrite(w http.ResponseWriter, ctxDescription string) error {
	safeWriter, ok := w.(SafeWriter)
	if ok {
		safeWriter.makeSafeToWrite(ctxDescription)
		return nil
	} else {
		return errors.New("responsewriter did not know linked request so cannot make safe")
	}
}
