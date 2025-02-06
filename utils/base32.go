package utils

import "encoding/base32"

// Base32 encoding but with '8' as padding. If you want to mimic this in a shell
// echo 'string_to_encode' | base32 | tr '=' '8'
func B32(s string) (b32 string) {
	return base32.StdEncoding.WithPadding('8').EncodeToString([]byte(s))
}

// Base32 decoding but with '8' as padding. If you want to mimic this in a shell
// echo 'ON2HE2LOM5PXI327MVXGG33EMUFA8888' | tr '8' '=' | base32 -d
func B32Decode(b32encoded string) (s string, err error) {
	encoding := base32.StdEncoding.WithPadding('8')
	maxLen := encoding.DecodedLen(len(b32encoded))
	target := make([]byte, maxLen)
	n, err := encoding.Decode(target, []byte(b32encoded))
	return string(target[:n]), err
}
