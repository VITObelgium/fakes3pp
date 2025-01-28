package presign

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/requestutils"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

//This file just contains helpers to presign for S3 with sigv4

func PreSignRequestWithCreds(ctx context.Context, req *http.Request, expiryInSeconds int, signingTime time.Time, creds aws.Credentials, defaultRegion string) (signedURI string, signedHeaders http.Header, err error){
	if expiryInSeconds <= 0 {
		return "", nil, errors.New("expiryInSeconds must be bigger than 0 for presigned requests")
	}
	signer := v4.NewSigner()

	ctx, creds, req, payloadHash, service, region, signingTime := GetS3SignRequestParams(ctx, req, expiryInSeconds, signingTime, creds, defaultRegion)
	return signer.PresignHTTP(ctx, creds, req, payloadHash, service, region, signingTime)
}

func SignRequestWithCreds(ctx context.Context, req *http.Request, expiryInSeconds int, signingTime time.Time, creds aws.Credentials, defaultRegion string) (err error){
	signer := v4.NewSigner()

	ctx, creds, req, payloadHash, service, region, signingTime := GetS3SignRequestParams(ctx, req, expiryInSeconds, signingTime, creds, defaultRegion)
	return signer.SignHTTP(ctx, creds, req, payloadHash, service, region, signingTime)
}

var signatureQueryParamNames []string = []string{
	constants.AmzAlgorithmKey,
	constants.AmzCredentialKey,
	constants.AmzDateKey,
	constants.AmzSecurityTokenKey,
	constants.AmzSignedHeadersKey,
	constants.AmzSignatureKey,
}

//Sign an HTTP request with a sigv4 signature. If expiry in seconds is bigger than zero then the signature has an explicit limited lifetime
//use a negative value to not set an explicit expiry time
//The requests gets checked to determine the region but if the request does not specify it the defaultRegion aruement will be used as fallback 
func GetS3SignRequestParams(ctx context.Context, req *http.Request, expiryInSeconds int, signingTime time.Time, creds aws.Credentials, defaultRegion string) (context.Context, aws.Credentials, *http.Request, string, string, string, time.Time){
	region := defaultRegion
	regionName, err := requestutils.GetSignatureCredentialPartFromRequest(req, requestutils.CredentialPartRegionName)
	if err == nil {
		region = regionName
	}
	
	query := req.URL.Query()
	for _, paramName := range signatureQueryParamNames {
		query.Del(paramName)
	}
	if expiryInSeconds > 0 {
		expires := time.Duration(expiryInSeconds) * time.Second
		query.Set(constants.AmzExpiresKey, strconv.FormatInt(int64(expires/time.Second), 10))
	}

	req.URL.RawQuery = query.Encode()

	service := "s3"

	payloadHash := req.Header.Get(constants.AmzContentSHAKey)
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	return ctx, creds, req, payloadHash, service, region, signingTime
}


func SignWithCreds(ctx context.Context, req *http.Request, creds aws.Credentials, defaultRegion string) error{
	var signingTime time.Time
	amzDate := req.Header.Get(constants.AmzDateKey)
	if amzDate == "" {
		signingTime = time.Now()
	} else {
		var err error
		signingTime, err = XAmzDateToTime(amzDate)
		if err != nil {
			slog.WarnContext(ctx, "Could not handle X-amz-date", constants.AmzDateKey, amzDate, "error", err)
			signingTime = time.Now()
		}	
	}

	return SignRequestWithCreds(ctx, req, -1, signingTime, creds, defaultRegion)
}
