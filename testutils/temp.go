package testutils

import (
	"fmt"
	"os"
	"testing"

	"github.com/VITObelgium/fakes3pp/utils"
)

func tempFile(t testing.TB, content, filePattern string) (fileName string) {
	tmpDir := t.TempDir()
	f, err := os.CreateTemp(tmpDir, filePattern)
	if err != nil {
		t.Error("Could not create temp file", "error", err)
		t.FailNow()
	}
	defer utils.Close(f, fmt.Sprintf("testutils.tempFile %s", filePattern), nil)
	fileName = f.Name()
	_, err = f.Write([]byte(content))
	if err != nil {
		t.Error("Problem when writing file content", "error", err)
	}
	return fileName
}


func TempYamlFile(t testing.TB, content string) (fileName string) {
	return tempFile(t, content, "*.yaml")
}

func StagePoliciesInTempDir(t testing.TB, policies map[string]string) (policyDir string) {
	policyDir = t.TempDir()
	for policyArn, policyContent := range policies {
		fileName := fmt.Sprintf("%s.json.tmpl", utils.B32(policyArn))
		fullFilename := fmt.Sprintf("%s/%s", policyDir, fileName)
		func () {
			f, err := os.Create(fullFilename)
			if err != nil {
				t.Error("Could not create temp file", "error", err)
				t.FailNow()
			}
			defer utils.Close(f, "StagePoliciesInTempDir", nil)
			_, err = f.Write([]byte(policyContent))
			if err != nil {
				t.Error("Problem when writing file content", "error", err)
				t.FailNow()
			}
		}()
	}

	return policyDir
}