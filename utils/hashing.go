package utils

import (
	"crypto/sha1"
	"encoding/hex"
)

func Sha1sum(s string) (sha1_hash string) {
    h := sha1.New()
    h.Write([]byte(s))
    sha1_hash = hex.EncodeToString(h.Sum(nil))
	return
}
