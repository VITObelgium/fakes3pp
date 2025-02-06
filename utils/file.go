package utils

import (
	"io"
	"os"
	"path"
	"strings"
)


func ReadFileFull(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

//For a file get the filename itself as well as the path leading up to it (rleativePath)
func GetFilenameAndRelativePath(fullFilename string) (filename, relativePath string) {
	filename = path.Base(fullFilename)
	relativePath = strings.TrimSuffix(fullFilename, filename)
	return filename, relativePath
}