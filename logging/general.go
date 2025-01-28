package logging

import (
	"io"
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


//Configure logging
//forceEnabler and sink can be nil and they will get sane defaults based on the environment.
func InitializeLogging(lvl slog.Level, forceEnabler ForceEnabler,  sink io.Writer) {
	if lvl == EnvironmentLvl {
		lvl = getLogLevel()
	}
	options := slog.HandlerOptions{
		Level: lvl,
	}
	if sink == nil {
		sink = os.Stdout
	}
	logger := slog.New(NewJSONRequestCtxHandler(sink, &options, forceEnabler))
	slog.SetDefault(logger)
	if lvl == EnvironmentLvl {
		//Still the place holder value probably misconfiguration of environment
		slog.Warn("LOG_LEVEL environment variable not set! Using sentinel logLvl", "logLvl", lvl)
	}
}