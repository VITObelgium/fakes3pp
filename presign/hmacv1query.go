// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTAuthentication.html#RESTAuthenticationQueryStringAuth
// e.g.: https://<s3-endpoing-FQDN>/<bucket>/<key>?AWSAccessKeyId=<aakid>&Signature=<sig>&x-amz-security-token=<tok>&Expires=<expires-epoch>
package presign

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/VITObelgium/fakes3pp/constants"
	ru "github.com/VITObelgium/fakes3pp/requestutils"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type presignedUrlHmacv1Query struct {
	*http.Request
}

func presignedUrlHmacv1queryFromRequest(r *http.Request) presignedUrlHmacv1Query {
	return presignedUrlHmacv1Query{
		r,
	}
}

func isHmacV1Query(r *http.Request) bool {
	return r.URL.Query().Get(constants.SignatureKey) != "" && r.URL.Query().Get(constants.AccessKeyId) != ""
}

//Presigned urls often get different casing (e.g. from boto3 library)
func getHmacV1QuerySecurityToken(r *http.Request) string {
	var result = r.URL.Query().Get("x-amz-security-token")
	if result == "" {
		result = r.URL.Query().Get(constants.AmzSecurityTokenKey)
	}
	return result
}

func (u presignedUrlHmacv1Query) GetPresignedUrlDetails(ctx context.Context, deriver SecretDeriver) (isValid bool, creds aws.Credentials, expires time.Time, err error) {
	accessKeyId := u.URL.Query().Get(constants.AccessKeyId)
	sessionToken := getHmacV1QuerySecurityToken(u.Request)

	secretAccessKey, err := deriver(accessKeyId)
	if err != nil {
		return
	}
	creds = aws.Credentials{
		AccessKeyID: accessKeyId,
		SecretAccessKey: secretAccessKey,
		SessionToken: sessionToken,
	}
	isValid, err = u.hasValidSignature(creds)
	if err != nil {
		return
	}
	expires, err = u.getExpiresTime()
	return
}

func (u presignedUrlHmacv1Query) hasValidSignature(creds aws.Credentials) (bool, error) {
	expectedUrl, err := CalculateS3PresignedHmacV1QueryUrl(u.Request, creds, 0)
	if err != nil {
		return false, err
	}
	//We do not care about schema but signing should be for same path and query
	_, isSameHost, isSamePath, isSameQuery, err := ru.CompareRequestWithUrl(u.Request, expectedUrl)
	if err != nil {
		return false, err
	}
	return isSameHost && isSamePath && isSameQuery, nil
}

func getExpiresFromHmacv1QueryUrl(r *http.Request) string {
	return r.URL.Query().Get(constants.ExpiresKey)
}

// For a presigned url get the epoch string when it expires
func (u presignedUrlHmacv1Query) getExpires() string {
	return getExpiresFromHmacv1QueryUrl(u.Request)
}

// For a presigned url get the time when it expires or return an error if invalid input
func (u presignedUrlHmacv1Query) getExpiresTime() (time.Time, error) {
	return epochStrToTime(u.getExpires())
}

//Calculate a Presigned URL out of a Request using AWS Credentials
//If you want to generate an URL for a new request set expirySeconds >0 to chose how long it will be valid
//If expirySeconds is set to 0 it is expected that a query parameter Expires is passed as part of the URL
//With a value an epoch timestamp
//This function will not make changes to the passed in request
func CalculateS3PresignedHmacV1QueryUrl(req *http.Request, creds aws.Credentials, expirySeconds int) (string, error) {
	var expires = getExpiresFromHmacv1QueryUrl(req)
	if expires == "" && expirySeconds == 0 {
		return "", errors.New("got expirySeconds 0 but no expires in URL, impossible to get expires")
	}
	if expirySeconds > 0 {
		if expires != "" {
			return "", fmt.Errorf("got expirySeconds %d and expires in URL %s, impossible to now which expires to use", expirySeconds, expires)
		}
		expires = getExpiresFromExpirySeconds(expirySeconds)
	}
	return calculateS3PresignedHmacV1QueryUrlWithExpiryTime(req, creds, expires)
}

func calculateS3PresignedHmacV1QueryUrlWithExpiryTime(req *http.Request, creds aws.Credentials, expires string) (string, error) {
	r := req.Clone(context.Background())
	
	assureSecTokenHeader(r, creds)

	cs, err := getCanonicalRequestString(r, expires)
	if err != nil {
		return "", err
	}

	key_for_sign := []byte(creds.SecretAccessKey)
	h := hmac.New(sha1.New, key_for_sign)
	h.Write([]byte(cs))
	hashBytes := h.Sum(nil)
	signature := base64.StdEncoding.EncodeToString(hashBytes)

	return buildHmacV1QueryUrl(r, creds, expires, signature), nil
}

func buildHmacV1QueryUrl(req *http.Request, creds aws.Credentials, expires, signature string) (string) {
	var secToken = ""
	if creds.SessionToken != "" {
		secToken = fmt.Sprintf("&x-amz-security-token=%s", url.QueryEscape(creds.SessionToken))
	}
	var scheme string = "https"
	if req.URL.Scheme != "" {
		scheme = req.URL.Scheme
	}
	
	return fmt.Sprintf(
		"%s://%s%s?AWSAccessKeyId=%s&Signature=%s%s&Expires=%s", 
		scheme, 
		req.URL.Host, 
		req.URL.Path,
		url.QueryEscape(creds.AccessKeyID),
		url.QueryEscape(signature),
		secToken,
		expires,
	)
}

func assureSecTokenHeader(req *http.Request, creds aws.Credentials) {
	if creds.SessionToken == "" {
		return
	}
	for hk := range req.Header {
		lowerHeaderKey := strings.ToLower(hk)
		if lowerHeaderKey == "x-amz-security-token" {
			req.Header.Del(lowerHeaderKey)
		}
	}
	req.Header.Add("x-amz-security-token", creds.SessionToken)
}

//expirySeconds are used to give a lifetime in seconds compared to now
//This function calculates the target time and puts it in the expected epoch format.
func getExpiresFromExpirySeconds(expirySeconds int) string {
	endOfLifeTime := time.Now().Add(time.Second * time.Duration(expirySeconds))
	return strconv.FormatInt(endOfLifeTime.UTC().Unix(), 10)
}

func getCanonicalRequestString(req *http.Request, expires string) (string, error) {
	method := strings.ToUpper(req.Method)
	if method != http.MethodGet && method != http.MethodHead {
		return "", errors.New("only Get and Head are implemented at the moment")
	}
	cs := method + "\n"
	canonicalStandardHeaders := getCanonicalStandardHeaders(req, expires)
	cs += canonicalStandardHeaders + "\n"
	
	canonicalCustomHeaders := getCanonicalCustomHeaders(req)

	cs += canonicalCustomHeaders
	if canonicalCustomHeaders != "" {
		cs += "\n"
	}

	canonicalResource, err := getCanonicalResource(req)
	if err != nil {
		return "", err
	}
	cs += canonicalResource

	return cs, nil
}


//https://github.com/boto/botocore/blob/develop/botocore/auth.py#L229
var interestingHeaders = [...]string{"content-md5", "content-type", "date"}
func getCanonicalStandardHeaders(req *http.Request, expires string) (string) {
	var headersOfInterest = []string{}

	req.Header.Set("Date", expires)
	for _, ih := range interestingHeaders {
		found := false
		for hk := range req.Header {
			if !found && strings.ToLower(hk) == ih {
				headersOfInterest = append(headersOfInterest, strings.Trim(req.Header.Get(hk), " "))
				found = true
			}
		}
		if !found {
			headersOfInterest = append(headersOfInterest, "")
		}
	}

	return strings.Join(headersOfInterest, "\n")
}

func getCommaSeparatedTrimmedHeaderValues(req *http.Request, headerKey string) string {
	values := req.Header.Values(headerKey)
	trimmedValues := []string{}
	for _, v := range values {
		trimmedValues = append(trimmedValues, strings.Trim(v, " "))
	}

	return strings.Join(trimmedValues, ",")
}

func getCanonicalCustomHeaders(req *http.Request) (string) {
	var headersOfInterest = []string{}
	headerKeys := []string{}
	headers := map[string]string{}
	for hk := range req.Header {
		lowerHeaderKey := strings.ToLower(hk)
		if strings.HasPrefix(lowerHeaderKey, "x-amz-") {
			headerKeys = append(headerKeys, lowerHeaderKey)
			headers[lowerHeaderKey] = getCommaSeparatedTrimmedHeaderValues(req, hk)
		}
	}
	slices.Sort(headerKeys)
	for _, key := range headerKeys {
		headersOfInterest = append(headersOfInterest, fmt.Sprintf("%s:%s", key, headers[key]))
	}
	return strings.Join(headersOfInterest, "\n")
}

// https://github.com/boto/botocore/blob/develop/botocore/auth.py#L965
// Let's use a map to be able to do lookups
var queryStringArgumentsOfInterest = map[string]bool{
	"accelerate": true,
	"acl": true,
	"cors": true,
	"defaultObjectAcl": true,
	"location": true,
	"logging": true,
	"partNumber": true,
	"policy": true,
	"torrent": true,
	"versioning": true,
	"versionId": true,
	"versions": true,
	"website": true,
	"uploads": true,
	"uploadId": true,
	"response-content-type": true,
	"response-content-language": true,
	"response-expires": true,
	"response-cache-control": true,
	"response-content-disposition": true,
	"response-content-encoding": true,
	"delete": true,
	"lifecycle": true,
	"tagging": true,
	"restore": true,
	"storageClass": true,
	"notification": true,
	"replication": true,
	"requestPayment": true,
	"analytics": true,
	"metrics": true,
	"inventory": true,
	"select": true,
	"select-type": true,
	"object-lock": true,
}

func getCanonicalResource(req *http.Request) (string, error) {
	if len(req.URL.Query()) > 0 {
		for queryName := range req.URL.Query() {
			_, isOfInterest := queryStringArgumentsOfInterest[queryName]
			if isOfInterest {
				return "", errors.New("processing query parameters of interest is not yet implemented")
				//https://github.com/boto/botocore/blob/develop/botocore/auth.py#L965
			}
		}
	}
	return req.URL.Path, nil
}