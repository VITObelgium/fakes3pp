package utils

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"strings"
)

func ReadFileFull(filePath string) ([]byte, error) {
	f, err := os.Open(filePath) // #nosec G304
	if err != nil {
		return nil, err
	}
	defer Close(f, fmt.Sprintf("utils.ReadFileFull %s", filePath), nil)
	return io.ReadAll(f)
}

// For a file get the filename itself as well as the path leading up to it (rleativePath)
func GetFilenameAndRelativePath(fullFilename string) (filename, relativePath string) {
	filename = path.Base(fullFilename)
	relativePath = strings.TrimSuffix(fullFilename, filename)
	return filename, relativePath
}

// A helper to have a simple way to defer closing while having error checking
// closeable: the handle that can be closed
// ctxDescription: Information that can be provided by the caller to help identify the cause if things go wrong
// ctx: a Context object to add request context information if available
func Close(closeable io.Closer, ctxDescription string, ctx context.Context) {
	if closeable == nil {
		if ctx == nil {
			slog.Error("Closable was nil", "ctxDescription", ctxDescription)
		} else {
			slog.ErrorContext(ctx, "Closable was nil", "ctxDescription", ctxDescription)
		}
		return
	}
	err := closeable.Close()
	if err != nil {
		if ctx == nil {
			slog.Error("Unable to close", "ctxDescription", ctxDescription)
		} else {
			slog.ErrorContext(ctx, "Unable to close", "ctxDescription", ctxDescription)
		}
	}
}
