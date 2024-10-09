package cmd

import (
	"log/slog"
	"os"
)


func initializeLogging() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
}