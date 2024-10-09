package cmd

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"unicode"
	"unicode/utf8"
)

func readFileFull(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func sha1sum(s string) (sha1_hash string) {
    h := sha1.New()
    h.Write([]byte(s))
    sha1_hash = hex.EncodeToString(h.Sum(nil))
	return
}

// Base32 encoding but with '8' as padding. If you want to mimic this in a shell
// echo 'string_to_encode' | base32 | tr '=' '8'
func b32(s string) (b32 string) {
	return base32.StdEncoding.WithPadding('8').EncodeToString([]byte(s))
}

// Base32 decoding but with '8' as padding. If you want to mimic this in a shell
// echo 'ON2HE2LOM5PXI327MVXGG33EMUFA8888' | tr '8' '=' | base32 -d
func b32_decode(b32encoded string) (s string, err error) {
	encoding := base32.StdEncoding.WithPadding('8')
	maxLen := encoding.DecodedLen(len(b32encoded))
	target := make([]byte, maxLen)
	n, err := encoding.Decode(target, []byte(b32encoded))
	return string(target[:n]), err
}



func capitalizeFirstLetter(s string) string {
	if len(s) == 0 {
		return s
	}
	sBytes := []byte(s)
	r, size := utf8.DecodeRune(sBytes)
	if unicode.IsLetter(r) {
		byteSlices := [][]byte{
			[]byte(string(unicode.ToUpper(r))),
			sBytes[size:],
		}
		return string(
				bytes.Join(byteSlices, []byte("")),
			)
	} else {
		return s
	}
}

func fullUrlFromRequest(req *http.Request) string {
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return fmt.Sprintf(
		"%s://%s%s?%s",
		scheme,
		req.Host,
		req.URL.Path,
		req.URL.RawQuery,
	)
}

// Whenever we write back we should log if there are errors
func WriteButLogOnError(ctx context.Context, w http.ResponseWriter, bytes []byte) {
	_, err := w.Write(bytes)
	if err != nil {
		slog.Warn("Could not write HTTP response body", "error", err, xRequestIDStr, getRequestID(ctx))
	}
}