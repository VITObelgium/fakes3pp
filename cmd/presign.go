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
	"github.com/VITObelgium/fakes3pp/requestutils"
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
		signedURI, err := PreSignRequestForGet(cliBucket, cliKey, cliRegion, time.Now(), cliExpiry)
		if err != nil {
			fmt.Printf("Encountered erorr %s when trying to creatue url for s3://%s/%s an expiry of %d\n", err, cliBucket, cliKey, cliExpiry)
			os.Exit(1)
		}
		fmt.Println(signedURI)
	},
}

func checkPresignRequiredFlags() {
	err := cobra.MarkFlagRequired(presignCmd.Flags(), cliBucket)
	if err != nil {
		slog.Debug("Missing required flag", "error", err)
	}
	err = cobra.MarkFlagRequired(presignCmd.Flags(), cliKey)
	if err != nil {
		slog.Debug("Missing required flag", "error", err)
	}
}

var	cliBucket string
var	cliKey string
var	cliExpiry int
var cliRegion string

func init() {
	rootCmd.AddCommand(presignCmd)

	presignCmd.Flags().StringVar(&cliBucket, "bucket", "", "The bucket for which to create a pre-signed URL.")
	presignCmd.Flags().StringVar(&cliKey, "key", "", "The key for the object for which to create a pre-signed URL.")
	presignCmd.Flags().IntVar(&cliExpiry, "expiry", 600, "The amount of seconds before the URL will expire.")
	presignCmd.Flags().StringVar(&cliRegion, "region", "waw3-1", "The default region to be used.")
	checkPresignRequiredFlags()
}

//Pre-sign the requests with the credentials that are used by the proxy itself
func PreSignRequestWithServerCreds(req *http.Request, exiryInSeconds int, signingTime time.Time, defaultRegion string) (signedURI string, signedHeaders http.Header, err error){

	
	ctx := context.Background()

	region := requestutils.GetRegionFromRequest(req, defaultRegion)
	creds, err := getBackendCredentials(region)
	if err != nil {
		return 
	}

	return presign.PreSignRequestWithCreds(
		ctx,
		req,
		exiryInSeconds,
		signingTime,
		creds,
		region,
	)
}


func PreSignRequestForGet(bucket, key, region string, signingTime time.Time, expirySeconds int) (string, error) {
	url := fmt.Sprintf("https://%s:%d/%s/%s", viper.Get(s3ProxyFQDN), viper.GetInt(s3ProxyPort), bucket, key)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("error when creating a request context for url: %s", err)
	}
	signedURI, _ , err := PreSignRequestWithServerCreds(req, expirySeconds, signingTime, region)
	return signedURI, err
}