package utils

import (
	"context"
	"log/slog"
	"net/http"
)

// Whenever we write back we should log if there are errors
func WriteButLogOnError(ctx context.Context, w http.ResponseWriter, bytes []byte) {
	_, err := w.Write(bytes)
	if err != nil {
		slog.WarnContext(ctx, "Could not write HTTP response body", "error", err)
	}
}
