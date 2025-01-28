package logging

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

var EnvironmentLvl slog.Level = -2147483648


func InitializeLogging(forceEnabler ForceEnabler, lvl slog.Level) {
	if lvl == EnvironmentLvl {
		lvl = getLogLevel()
	}
	options := slog.HandlerOptions{
		Level: lvl,
	}
	logger := slog.New(NewJSONRequestCtxHandler(os.Stdout, &options, forceEnabler))
	slog.SetDefault(logger)
}