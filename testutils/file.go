package testutils

import (
	"io"
	"os"
	"testing"
)

func CreateTempTestCopy(t testing.TB, filepath string) (filepathCopy string) {
	f, err := os.Open(filepath)
	if err != nil {
		t.Error("Could not open file to create copy", "error", err)
		t.FailNow()
	}
	defer f.Close()
	copyFile, err := os.CreateTemp(t.TempDir(), "*")
	if err != nil {
		t.Error("Could not open temp file to create copy", "error", err)
		t.FailNow()
	}
	defer copyFile.Close()
	_, err = io.Copy(copyFile, f)
	if err != nil {
		t.Error("Got an error when copying a test file", "error", err, "filepath", filepath)
		t.FailNow()
	}
	return copyFile.Name()
}