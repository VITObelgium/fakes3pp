package s3

import (
	"net/http"
	"os"
	"strings"

	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/middleware"
	"sigs.k8s.io/yaml"
)

type requesterPaysBuckets map[string]struct{}

func getRequesterPaysBuckets(filename string) (requesterPaysBuckets, error) {
	buf, err := os.ReadFile(filename) // #nosec G304 -- platform provided files
	if err != nil {
		return nil, err
	}
	return getRequesterPaysBucketsFromBytes(buf)
}

func getRequesterPaysBucketsFromBytes(inputBytes []byte) (requesterPaysBuckets, error) {
	var buckets []string
	err := yaml.Unmarshal(inputBytes, &buckets)
	if err != nil {
		return nil, err
	}

	result := make(requesterPaysBuckets, len(buckets))
	for _, bucket := range buckets {
		trimmedBucket := strings.TrimSpace(bucket)
		if trimmedBucket == "" {
			continue
		}
		result[trimmedBucket] = struct{}{}
	}
	return result, nil
}

func (rpb requesterPaysBuckets) shouldForce(bucket string) bool {
	if len(rpb) == 0 || bucket == "" {
		return false
	}
	_, ok := rpb[bucket]
	return ok
}

func ForceRequesterPays(rpb requesterPaysBuckets, vhi interfaces.VirtualHosterIdentifier) middleware.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			bucket, err := getS3BucketFromRequest(r, vhi)
			if err == nil && rpb.shouldForce(bucket) {
				r.Header.Set(constants.AmzRequestPayerKey, constants.AmzRequestPayerRequesterValue)
			}
			next(w, r)
		}
	}
}
