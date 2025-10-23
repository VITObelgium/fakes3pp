package testutils

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/VITObelgium/fakes3pp/logging"
)

// For testing only get lines out of a buffer
func logBufferToLines(tb testing.TB, buf *bytes.Buffer) []string {
	var lines = []string{}
	lineDelimiter := byte('\n')
	for i := 0; i < 10000; i++ {
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

// A fixture to start capturing logs. It returns the following:
// - a teardown callback to stop the log capture.
// - a getCapturedLogLines callback which gets the log lines captured since the last run
func CaptureLogFixture(tb testing.TB, lvl slog.Level, fe logging.ForceEnabler) (teardown func(), getCapturedLogLines func() []string) {
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

// A fixture to capture structured logs
func CaptureStructuredLogsFixture(tb testing.TB, lvl slog.Level, fe logging.ForceEnabler) (teardown func(), getCapturedLogEntries func() StructuredLogEntries) {
	teardown, getCapturedLogLines := CaptureLogFixture(tb, lvl, fe)

	getCapturedLogEntries = func() StructuredLogEntries {
		capturedEntries := StructuredLogEntries{}
		for _, line := range getCapturedLogLines() {
			entry := StructuredLogEntry{}
			err := json.Unmarshal([]byte(line), &entry)
			if err != nil {
				tb.Errorf("could not convert %s to structured logging entry", line)
				tb.Fail()
			} else {
				capturedEntries = append(capturedEntries, entry)
			}
		}
		return capturedEntries
	}
	return teardown, getCapturedLogEntries
}

type StructuredLogEntry map[string]any
type StructuredLogEntries []StructuredLogEntry

func (s StructuredLogEntry) GetStringField(t testing.TB, fieldName string) string {
	fieldValue, ok := s[fieldName]
	if ok {
		stringValue, ok := fieldValue.(string)
		if ok {
			return stringValue
		}
		t.Errorf("field %s is not a string", fieldName)
	}
	t.Errorf("field %s is not present", fieldName)
	t.FailNow()
	return ""
}

// Default choice by a JSON unmarshaller for a number
func (s StructuredLogEntry) GetFloat64(t testing.TB, fieldName string) float64 {
	fieldValue, ok := s[fieldName]
	if ok {
		floatValue, ok := fieldValue.(float64)
		if ok {
			return floatValue
		}
		t.Errorf("field %s is not a number", fieldName)
	}
	t.Errorf("field %s is not present", fieldName)
	t.FailNow()
	return 0.0
}

func (s StructuredLogEntry) GetLevel(t testing.TB) string {
	return s.GetStringField(t, "level")
}

func (s StructuredLogEntry) GetMsg(t testing.TB) string {
	return s.GetStringField(t, "msg")
}

func (s *StructuredLogEntries) GetEntriesWithMsg(t testing.TB, msgValue string) StructuredLogEntries {
	filteredEntries := StructuredLogEntries{}
	for _, entry := range *s {
		msg := entry.GetMsg(t)
		if msg == msgValue {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	return filteredEntries
}

func (s *StructuredLogEntries) GetEntriesContainingField(t testing.TB, fieldName string) StructuredLogEntries {
	filteredEntries := StructuredLogEntries{}
	for _, entry := range *s {
		_, ok := entry[fieldName]
		if ok {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	return filteredEntries
}
