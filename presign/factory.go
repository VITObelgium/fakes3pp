package presign

import (
	"context"
	"fmt"
	"net/http"
	"time"

	url "github.com/VITObelgium/fakes3pp/requestutils"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func MakePresignedUrl(r *http.Request) (u PresignedUrl, err error) {
	if isHmacV1Query(r) {
		//&& r.URL.Query().Get(constants.AmzSecurityTokenKey) != ""
		u = presignedUrlHmacv1queryFromRequest(r)
		return
	} else if isS3V4Query(r) {
		u = presignedUrlS3V4QueryFromRequest(r)
		return
	}

	return nil, fmt.Errorf("unsupported presign request; %s", url.FullUrlFromRequest(r))
}

func IsPresignedUrlWithValidSignature(ctx context.Context, url string, creds aws.Credentials) (isValid, isExpired bool, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	purl, err := MakePresignedUrl(req)
	if err != nil {
		return
	}
	secretDeriver := func(accessKeyId string) (string, error) {
		if creds.AccessKeyID != accessKeyId {
			err = fmt.Errorf("mismatch between provided credential %s and url credential %s", creds.AccessKeyID, accessKeyId)
			return "", err
		}
		return creds.SecretAccessKey, nil
	}
	isValid, _, expires, err := purl.GetPresignedUrlDetails(ctx, secretDeriver)
	isExpired = time.Now().UTC().After(expires)
	return
}
