package cmd

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

	"github.com/aws/aws-sdk-go-v2/aws"
)

// For a presigned url get the epoch string when it expires
func getS3PresignedUrlExpires(req *http.Request) string {
	return req.URL.Query().Get("Expires")
}

// For a presigned url get the time when it expires or return an error if invalid input
func GetS3PresignedUrlExpiresTime(req *http.Request) (time.Time, error) {
	expiresStr := getS3PresignedUrlExpires(req)
	expiresInt, err := strconv.Atoi(expiresStr)
	if err != nil {
		return time.Now(), err
	}
	return time.Unix(int64(expiresInt), 0), nil
}

//Calculate a Presigned URL out of a Request using AWS Credentials
//If you want to generate an URL for a new request set expirySeconds >0 to chose how long it will be valid
//If expirySeconds is set to 0 it is expected that a query parameter Expires is passed as part of the URL
//With a value an epoch timestamp
//This function will not make changes to the passed in request
func CalculateS3PresignedUrl(req *http.Request, creds aws.Credentials, expirySeconds int) (string, error) {
	var expires string = getS3PresignedUrlExpires(req)
	if expires == "" && expirySeconds == 0 {
		return "", errors.New("got expirySeconds 0 but no expires in URL, impossible to get expiry")
	}
	if expirySeconds > 0 {
		if expires != "" {
			return "", fmt.Errorf("got expirySeconds %d and expires in URL %s, impossible to now which expiry to use", expirySeconds, expires)
		}
		expires = getExpiresFromExpirySeconds(expirySeconds)
	}
	return CalculateS3PresignedUrlWithExpiryTime(req, creds, expires)
}

func UrlDropSchemeFQDNPort(url string) string {
	urlParts := strings.Split(url, "/")
	if len(urlParts) <= 3 {
		return ""
	}
	return strings.Join(urlParts[3:], "/")
}

func HasS3PresignedUrlValidSignature(req *http.Request, creds aws.Credentials) (validSignature bool, err error) {
	testUrl := UrlDropSchemeFQDNPort(fullUrlFromRequest(req))
	expectedUrl, err := CalculateS3PresignedUrl(req, creds, 0)
	expectedUrl = UrlDropSchemeFQDNPort(expectedUrl)
	if err != nil {
		return false, err
	}
	return testUrl == expectedUrl, nil
}


func HasGetS3PresignedUrlValidSignature(testUrl string, creds aws.Credentials) (validSignature bool, err error) {
	req, err := http.NewRequest(http.MethodGet, testUrl, nil)
	if err != nil {
		return false, err
	}
	return HasS3PresignedUrlValidSignature(req, creds)
}

func CalculateS3PresignedUrlWithExpiryTime(req *http.Request, creds aws.Credentials, expires string) (string, error) {
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

	return buildUrl(r, creds, expires, signature), nil
}

func buildUrl(req *http.Request, creds aws.Credentials, expires, signature string) (string) {
	var secToken = ""
	if creds.SessionToken != "" {
		secToken = fmt.Sprintf("&x-amz-security-token=%s", url.QueryEscape(creds.SessionToken))
	}
	
	return fmt.Sprintf(
		"%s://%s%s?AWSAccessKeyId=%s&Signature=%s%s&Expires=%s", 
		req.URL.Scheme, 
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
	if method != http.MethodGet {
		return "", errors.New("only Get is implemented at the moment")
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