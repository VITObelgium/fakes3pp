package httptracking

import (
	"io"

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
	t.requestCtx.BytesReceived += uint64(n)
	return n, err
}
