package utils

import (
	"bytes"
	"unicode"
	"unicode/utf8"
)


func CapitalizeFirstLetter(s string) string {
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