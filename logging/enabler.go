package logging

import (
	"context"
	"log/slog"
	"strings"

	"github.com/VITObelgium/fakes3pp/requestctx"
)


type ForceEnabler interface {
	IsForceEnabled(context.Context, slog.Level) bool
}

//By default we do not force logging to be enabled.
type neverForce struct {}

func (f neverForce) IsForceEnabled(_ context.Context, _ slog.Level) bool {
	return false
}


type forceForRequestIdPrefix struct {
	Prefix string
}

func (f forceForRequestIdPrefix) IsForceEnabled(ctx context.Context, _ slog.Level) bool {
	reqCtx, ok := requestctx.FromContext(ctx)
	if ok {
		return strings.HasPrefix(reqCtx.RequestID, f.Prefix)
	}
	return false
}

func NewForceForRequestIdPrefix(Prefix string) *forceForRequestIdPrefix{
	return &forceForRequestIdPrefix{
		Prefix: Prefix,
	}
}