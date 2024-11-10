/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/aws/aws-sdk-go-v2/aws"
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

func getServerCreds() aws.Credentials {
	accessKey := viper.GetString(awsAccessKeyId)
	secretKey := viper.GetString(awsSecretAccessKey)

	return aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	}
}

//Pre-sign the requests with the credentials that are used by the proxy itself
func PreSignRequestWithServerCreds(req *http.Request, exiryInSeconds int, signingTime time.Time) (signedURI string, signedHeaders http.Header, err error){

	
	ctx := context.Background()

	return presign.PreSignRequestWithCreds(
		ctx,
		req,
		exiryInSeconds,
		signingTime,
		getServerCreds(),
	)
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