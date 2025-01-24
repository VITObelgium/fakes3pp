package cmd

import (
	"log/slog"
	"os"
)

func getLogLevel() (lvl slog.Level) {
	logLevelOS, ok := os.LookupEnv("LOG_LEVEL")
	if !ok {
		return lvl
	}
	err := lvl.UnmarshalText([]byte(logLevelOS))
	if err != nil {
		slog.Warn("Invalid log level", "environ_value", logLevelOS)
	}
	return 

}

func initializeLogging() {
	options := slog.HandlerOptions{
		Level: getLogLevel(),
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &options))
	slog.SetDefault(logger)
}