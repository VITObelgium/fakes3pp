package httptracking

import (
	"io"
	"log/slog"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

type trackingReadCloser struct {
	rc         io.ReadCloser
	requestCtx *requestctx.RequestCtx
}

func NewTrackingBody(body io.ReadCloser, rCtx *requestctx.RequestCtx) *trackingReadCloser {
	return &trackingReadCloser{
		rc:         body,
		requestCtx: rCtx,
	}
}

func (t *trackingReadCloser) Close() error {
	return t.rc.Close()
}

func (t *trackingReadCloser) Read(p []byte) (n int, err error) {
	n, err = t.rc.Read(p)
	if n < 1000000000000000 && t.requestCtx.BytesReceived < 1000000000000000 {
		t.requestCtx.BytesReceived += uint64(n)
	} else {
		slog.Warn("trackingResponseWriter wrote more than 1 peta-bytes request size will be wrong")
	}
	return n, err
}
