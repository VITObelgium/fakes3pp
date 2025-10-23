package testutils

import (
	"crypto/rand"
	"errors"
	"io"
)

// This is a helper to be able to read a random string limited to a size while making it seekable.
// NonDeterministic is an imporant characteristic to be careful with. If you seek the start (offset=0) you can again read N bytes from it but
// they would not be the same as bytes read previously.
// While s3.PutObjectInput takes a Reader it actually requires a ReadSeeker for singing the request (when using HTTPS
// the s3.PutObjectInput does not sign the payload but when sending over HTTP then it will). So we must reset N of the limited reader when we
// Seek because the Signing middle ware would consume the reader and the actual request would have an exhausted LimitedReader if we don't action the
// Seek which would lead in 0-byte objects being sent.
// You can only use this against dummy backends which do not check Payload signature (like moto which is used in our test cases)
type nonDeterministicLimitedRandReadSeeker struct {
	lr io.LimitedReader
	N  int64 //How much can be maximally read
}

func NewNonDeterministicLimitedRandReadSeeker(n int64) *nonDeterministicLimitedRandReadSeeker {
	return &nonDeterministicLimitedRandReadSeeker{
		lr: io.LimitedReader{
			R: rand.Reader,
			N: n,
		},
		N: n,
	}
}

func (ndlrrs *nonDeterministicLimitedRandReadSeeker) Read(b []byte) (n int, err error) {
	return ndlrrs.lr.Read(b)
}

func (ndlrrs *nonDeterministicLimitedRandReadSeeker) Seek(offset int64, whence int) (int64, error) {
	//Reset how much can be read based on the offset seeked
	if offset > ndlrrs.N {
		return -1, errors.New("Seek beyond Limit of Limited reader")
	}
	ndlrrs.lr.N = ndlrrs.N - offset
	return offset, nil
}
