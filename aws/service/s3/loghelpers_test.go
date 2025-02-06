package s3

import (
	"bytes"
	"io"
	"log/slog"
	"testing"

	"github.com/VITObelgium/fakes3pp/logging"
)

//For testing only get lines out of a buffer
func logBufferToLines(tb testing.TB, buf *bytes.Buffer) []string {
	var lines = []string{}
	lineDelimiter := byte('\n')
	for i:=0 ; i < 10000; i++ {
		line, err := buf.ReadString(lineDelimiter)
		if err == nil {
			lines = append(lines, line)
		} else {
			if err == io.EOF {
				return lines
			}
			tb.Errorf("Encountered error while processing log buffer: %s", err)
			tb.FailNow()
		}
	}
	return lines
}

//A fixture to start capturing logs. It returns the following:
// - a teardown callback to stop the log capture.
// - a getCapturedLogLines callback which gets the log lines captured since the last run
func captureLogFixture(tb testing.TB, lvl slog.Level, fe logging.ForceEnabler) (teardown func()(), getCapturedLogLines func()([]string)) {
	loggerBeforeFixture := slog.Default()
	buf := &bytes.Buffer{}
	logging.InitializeLogging(lvl, fe, buf)
	var fixtureActive = true

	teardown = func() {
		if fixtureActive {
			slog.SetDefault(loggerBeforeFixture)
			fixtureActive = false
		}
	}

	getCapturedLogLines = func() (lines []string) {
		lines = logBufferToLines(tb, buf)
		return lines
	}

	return teardown, getCapturedLogLines
}