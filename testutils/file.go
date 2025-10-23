package testutils

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/VITObelgium/fakes3pp/utils"
)

func CreateTempTestCopy(t testing.TB, filepath string) (filepathCopy string) {
	f, err := os.Open(filepath)
	if err != nil {
		t.Error("Could not open file to create copy", "error", err)
		t.FailNow()
	}
	defer utils.Close(f, fmt.Sprintf("CreateTempTestCopy srcFile %s", filepath), nil)
	
	copyFile, err := os.CreateTemp(t.TempDir(), "*")
	if err != nil {
		t.Error("Could not open temp file to create copy", "error", err)
		t.FailNow()
	}
	defer utils.Close(copyFile, fmt.Sprintf("CreateTempTestCopy copyFile %s", filepath), nil)

	_, err = io.Copy(copyFile, f)
	if err != nil {
		t.Error("Got an error when copying a test file", "error", err, "filepath", filepath)
		t.FailNow()
	}
	return copyFile.Name()
}