package logging

import (
	"context"
	"io"
	"log/slog"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

// JSONRequestCtxHandler is a [Handler] that writes Records to an [io.Writer] as
// line-delimited JSON objects while checking RequestContext.
type JSONRequestCtxHandler struct {
	wrappedHandler slog.Handler

	//A hook to make sure records are logged if they are of a certain level or a specific context was passed 
	forceEnabler ForceEnabler
}

func NewJSONRequestCtxHandler(w io.Writer, opts *slog.HandlerOptions, forceEnabler ForceEnabler) *JSONRequestCtxHandler {
	h := slog.NewJSONHandler(w, opts)
	if forceEnabler == nil {
		forceEnabler = getDefaultForceEnableLoggingStrategy()
	}
	return &JSONRequestCtxHandler{h, forceEnabler}
}

// Enabled reports whether the handler handles records at the given level.
// The handler ignores records whose level is lower.
func (h *JSONRequestCtxHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if h.forceEnabler.IsForceEnabled(ctx, level) {
		return true
	}
	return h.wrappedHandler.Enabled(ctx, level)
}

// WithAttrs returns a new [JSONHandler] whose attributes consists
// of h's attributes followed by attrs.
func (h *JSONRequestCtxHandler) WithAttrs(attrs []slog.Attr) slog.Handler {

	return &JSONRequestCtxHandler{wrappedHandler: h.wrappedHandler.WithAttrs(attrs), forceEnabler: h.forceEnabler}
}

func (h *JSONRequestCtxHandler) WithGroup(name string) slog.Handler {
	return &JSONRequestCtxHandler{wrappedHandler: h.wrappedHandler.WithGroup(name), forceEnabler: h.forceEnabler}
}

func (h *JSONRequestCtxHandler) Handle(ctx context.Context, r slog.Record) error {
	rCtx, ok := requestctx.FromContext(ctx)
	if ok && rCtx.RequestID != "" {
		r.AddAttrs(slog.String("RequestId", rCtx.RequestID))
	}
	
	return h.wrappedHandler.Handle(ctx, r)
}