/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// presignCmd represents the presign command
var presignCmd = &cobra.Command{
	Use:   "presign",
	Short: "An action to generate a pre-signed URL",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		signedURI, err := PreSignRequestForGet(bucket, key, time.Now(), expiry)
		if err != nil {
			fmt.Printf("Encountered erorr %s when trying to creatue url for s3://%s/%s an expiry of %d\n", err, bucket, key, expiry)
			os.Exit(1)
		}
		fmt.Println(signedURI)
	},
}

func checkPresignRequiredFlags() {
	err := cobra.MarkFlagRequired(presignCmd.Flags(), bucket)
	if err != nil {
		slog.Debug("Missing required flag", "error", err)
	}
	err = cobra.MarkFlagRequired(presignCmd.Flags(), key)
	if err != nil {
		slog.Debug("Missing required flag", "error", err)
	}
}

var	bucket string
var	key string
var	expiry int

func init() {
	rootCmd.AddCommand(presignCmd)

	presignCmd.Flags().StringVar(&bucket, "bucket", "", "The bucket for which to create a pre-signed URL.")
	presignCmd.Flags().StringVar(&key, "key", "", "The key for the object for which to create a pre-signed URL.")
	presignCmd.Flags().IntVar(&expiry, "expiry", 600, "The amount of seconds before the URL will expire")
	checkPresignRequiredFlags()
}

//Pre-sign the requests with the credentials that are used by the proxy itself
func PreSignRequestWithServerCreds(req *http.Request, exiryInSeconds int, signingTime time.Time) (signedURI string, signedHeaders http.Header, err error){

	accessKey := viper.GetString(awsAccessKeyId)
	secretKey := viper.GetString(awsSecretAccessKey)

	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	}
	ctx := context.Background()

	return PreSignRequestWithCreds(
		ctx,
		req,
		exiryInSeconds,
		signingTime,
		creds,
	)
}

var signatureQueryParamNames []string = []string{
	AmzAlgorithmKey,
	AmzCredentialKey,
	AmzDateKey,
	AmzSecurityTokenKey,
	AmzSignedHeadersKey,
	AmzSignatureKey,
}

func getQueryParamsFromUrl(inputUrl string) (url.Values, error) {
	u, err := url.Parse(inputUrl)
    if err != nil {
        return nil, err
    }
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
        return nil, err
    }
	return q, nil
}

func getSignatureFromUrl(inputUrl string) (string, error) {
	q, err := getQueryParamsFromUrl(inputUrl)
    if err != nil {
        return "", err
    }
	signature := q.Get(AmzSignatureKey)
	if signature == "" {
		return signature, fmt.Errorf("Url got empty signature: %s", inputUrl)
	}
	return signature, nil
}

//Verify if URLs have the same sigv4 signature. If one of the URLs does not have
//a signature it always returns false.
func haveSameSigv4Signature(url1, url2 string) (same bool, err error) {
	s1, err := getSignatureFromUrl(url1)
    if err != nil {
        return false, err
    }
	
	s2, err := getSignatureFromUrl(url2)
    if err != nil {
        return false, err
    }

	return s1 == s2, nil
}

func PreSignRequestWithCreds(ctx context.Context, req *http.Request, expiryInSeconds int, signingTime time.Time, creds aws.Credentials) (signedURI string, signedHeaders http.Header, err error){
	if expiryInSeconds <= 0 {
		return "", nil, errors.New("expiryInSeconds must be bigger than 0 for presigned requests")
	}
	signer := v4.NewSigner()

	ctx, creds, req, payloadHash, service, region, signingTime := GetSignRequestParams(ctx, req, expiryInSeconds, signingTime, creds)
	return signer.PresignHTTP(ctx, creds, req, payloadHash, service, region, signingTime)
}

func SignRequestWithCreds(ctx context.Context, req *http.Request, expiryInSeconds int, signingTime time.Time, creds aws.Credentials) (err error){
	signer := v4.NewSigner()

	ctx, creds, req, payloadHash, service, region, signingTime := GetSignRequestParams(ctx, req, expiryInSeconds, signingTime, creds)
	return signer.SignHTTP(ctx, creds, req, payloadHash, service, region, signingTime)
}

//Sign an HTTP request with a sigv4 signature. If expiry in seconds is bigger than zero then the signature has an explicit limited lifetime
//use a negative value to not set an explicit expiry time
func GetSignRequestParams(ctx context.Context, req *http.Request, expiryInSeconds int, signingTime time.Time, creds aws.Credentials) (context.Context, aws.Credentials, *http.Request, string, string, string, time.Time){
	region := "eu-west-1"
	regionName, err := getSignatureCredentialPartFromRequest(req, credentialPartRegionName)
	if err == nil {
		region = regionName
	}
	
	query := req.URL.Query()
	for _, paramName := range signatureQueryParamNames {
		query.Del(paramName)
	}
	if expiryInSeconds > 0 {
		expires := time.Duration(expiryInSeconds) * time.Second
		query.Set(AmzExpiresKey, strconv.FormatInt(int64(expires/time.Second), 10))
	}

	req.URL.RawQuery = query.Encode()

	service := "s3"

	payloadHash := req.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	return ctx, creds, req, payloadHash, service, region, signingTime
}

func PreSignRequestForGet(bucket, key string, signingTime time.Time, expirySeconds int) (string, error) {
	url := fmt.Sprintf("https://%s:%d/%s/%s", viper.Get(s3ProxyFQDN), viper.GetInt(s3ProxyPort), bucket, key)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("error when creating a request context for url: %s", err)
	}
	signedURI, _ , err := PreSignRequestWithServerCreds(req, expirySeconds, signingTime)
	return signedURI, err
}