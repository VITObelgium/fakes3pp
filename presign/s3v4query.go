package presign

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/requestutils"
	"github.com/VITObelgium/fakes3pp/usererror"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type presignedUrlS3V4Query struct {
	*http.Request
}

func presignedUrlS3V4QueryFromRequest(r *http.Request) presignedUrlS3V4Query {
	return presignedUrlS3V4Query{
		r,
	}
}


func isS3V4Query(r *http.Request) bool {
	return r.URL.Query().Get(constants.AmzSignatureKey) != "" && r.URL.Query().Get(constants.AmzCredentialKey) != "" && r.URL.Query().Get(constants.AmzAlgorithmKey) != ""
}

// Get the value of X-Amz-Credential as given for the presigned url
func (u presignedUrlS3V4Query) getAmzCredential() (string) {
	return u.URL.Query().Get(constants.AmzCredentialKey)
}

// Get the value of X-Amz-Security-Token as given for the presigned url
func (u presignedUrlS3V4Query) getAmzSecurityToken() (string) {
	return u.URL.Query().Get(constants.AmzSecurityTokenKey)
}


func (u presignedUrlS3V4Query) getAccessKeyId() (string, error) {
	return requestutils.GetCredentialPart(u.getAmzCredential(), requestutils.CredentialPartAccessKeyId)
}

func (u presignedUrlS3V4Query) getSignTime() (time.Time, error) {
	XAmzDate := u.URL.Query().Get(constants.AmzDateKey)
	return XAmzDateToTime(XAmzDate)
}

func (u presignedUrlS3V4Query) GetPresignedUrlDetails(ctx context.Context, deriver SecretDeriver) (isValid bool, creds aws.Credentials, expires time.Time, err error) {
	accessKeyId, err := u.getAccessKeyId()
	if err != nil {
		return
	} 
	sessionToken := u.getAmzSecurityToken()

	secretAccessKey, err := deriver(accessKeyId)
	if err != nil {
		return
	}
	creds = aws.Credentials{
		AccessKeyID: accessKeyId,
		SecretAccessKey: secretAccessKey,
		SessionToken: sessionToken,
	}
	signDate, err := u.getSignTime()
	if err != nil {
		return
	}
	XAmzExpires := u.URL.Query().Get(constants.AmzExpiresKey)
	expirySeconds, err := strconv.Atoi(XAmzExpires)
	if err != nil {
		err = fmt.Errorf("InvalidSignature: could not get Expire seconds(%s) %s: %s", constants.AmzExpiresKey, XAmzExpires, err)
		return 
	}

	expires = signDate.Add(time.Duration(expirySeconds) * time.Second)
	originalSignature := u.Request.URL.Query().Get(constants.AmzSignatureKey)
	c := u.Clone(ctx)
	if c.Header.Get("Host") == "" {
		c.Header.Add("Host", c.Host)
	}
	_, err = TemporaryRemoveUntrustedHeaders(c)
	if err != nil {
		ue := usererror.New(
			fmt.Errorf("could not temporary remove untrusted headers %v", c.Header), "Invalid authorization header",
		)
		return false, creds, expires, ue
	}
	defaultRegion := ""  // A Sigv4 always has a region specified as part of the X-amz-credentials parameter so no fallback needed.
	signedUri, _, err := PreSignRequestWithCreds(ctx, c, expirySeconds, signDate, creds, defaultRegion)
	if err != nil {
		err = fmt.Errorf("InvalidSignature: encountered error trying to sign a similar req: %s", err)
		return 
	}

	calculatedSignature, err := getSignatureFromV4QueryUrl(signedUri)
	if err != nil {
		return
	}
	isValid = originalSignature == calculatedSignature
	// isValid, err = haveSameSigv4Signature(requestutils.FullUrlFromRequest(u.Request), signedUri)
	return
}

func getSignatureFromV4QueryUrl(inputUrl string) (sig string, err error) {
	q, err := requestutils.GetQueryParamsFromUrl(inputUrl)
    if err != nil {
        return
    }
	signature := q.Get(constants.AmzSignatureKey)
	if signature == "" {
		return signature, fmt.Errorf("url got empty signature: %s", inputUrl)
	}
	return signature, nil
}

//Verify if URLs have the same sigv4 signature. If one of the URLs does not have
//a signature it always returns false.
func haveSameSigv4QuerySignature(url1, url2 string) (same bool, err error) {
	s1, err := getSignatureFromV4QueryUrl(url1)
    if err != nil {
        return false, err
    }
	
	s2, err := getSignatureFromV4QueryUrl(url2)
    if err != nil {
        return false, err
    }

	return s1 == s2, nil
}