package logging

import (
	"context"
	"log/slog"
	"os"
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


const ENV_FORCE_LOGGING_FOR_REQUEST_ID_PREFIX = "FORCE_LOGGING_FOR_REQUEST_ID_PREFIX"

//The exection environment decides when to force logging. If it an environment variable
//FORCE_LOGGING_FOR_REQUEST_ID_PREFIX is set then logging will be forced for requests that
//have a request ID that start with that value.
func getDefaultForceEnableLoggingStrategy() ForceEnabler {
	prefix := os.Getenv(ENV_FORCE_LOGGING_FOR_REQUEST_ID_PREFIX)
	if prefix != "" {
		slog.Debug("Enable force logging for prefix", "prefix", prefix)
		return NewForceForRequestIdPrefix(prefix)
	} else {
		slog.Debug("Never force logging.")
		return &neverForce{}
	}
}