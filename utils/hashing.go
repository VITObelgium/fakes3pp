package utils

import (
	"crypto/sha1" // #nosec G505
	"encoding/hex"
)

func Sha1sum(s string) (sha1_hash string) {
	h := sha1.New() // #nosec G401 -- Not used for storing sensitive information
	h.Write([]byte(s))
	sha1_hash = hex.EncodeToString(h.Sum(nil))
	return
}
