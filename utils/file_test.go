package utils_test

import (
	"testing"

	"github.com/VITObelgium/fakes3pp/utils"
)

func TestRelativeFilePaths(t *testing.T) {
	testcases := []struct{
		Name string
		FullFilePath string
		ExpectedFilename string
		ExpectedRelativepath string
	}{
		{
			"NoLevel",
			"file.json",
			"file.json",
			"",
		},
		{
			"Simple 1 level up",
			"test/file.json",
			"file.json",
			"test/",
		},
		{
			"Simple 1 level down",
			"../file.json",
			"file.json",
			"../",
		},
		{
			"3 levels down",
			"../../../config.yaml",
			"config.yaml",
			"../../../",
		},
	}
	for _, tc := range testcases {
		filename, relativepath := utils.GetFilenameAndRelativePath(tc.FullFilePath)
		if filename != tc.ExpectedFilename {
			t.Errorf("%s: Expected filename %s, got %s", tc.Name, tc.ExpectedFilename, filename)
		}
		if relativepath != tc.ExpectedRelativepath {
			t.Errorf("%s: Expected relative path %s, got %s", tc.Name, tc.ExpectedRelativepath, relativepath)
		}
	}
}