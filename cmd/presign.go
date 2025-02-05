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

	"github.com/VITObelgium/fakes3pp/aws/service/s3"
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
		signedURI, err := preSignRequestForGet(cliBucket, cliKey, cliRegion, backendConfigFile, time.Now(), cliExpiry)
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
var backendConfigFile string

func init() {
	rootCmd.AddCommand(presignCmd)

	presignCmd.Flags().StringVar(&cliBucket, "bucket", "", "The bucket for which to create a pre-signed URL.")
	presignCmd.Flags().StringVar(&cliKey, "key", "", "The key for the object for which to create a pre-signed URL.")
	presignCmd.Flags().IntVar(&cliExpiry, "expiry", 600, "The amount of seconds before the URL will expire.")
	presignCmd.Flags().StringVar(&cliRegion, "region", "waw3-1", "The default region to be used.")
	presignCmd.Flags().StringVar(&backendConfigFile, "backendCfgFile", "", "The configuration of possible backends.")
	checkPresignRequiredFlags()
}

//Pre-sign the requests with the credentials that are used by the proxy itself
func preSignRequestWithServerCreds(req *http.Request, exiryInSeconds int, signingTime time.Time, defaultRegion, backendCfgFile string) (signedURI string, signedHeaders http.Header, err error){

	
	ctx := context.Background()

	region := requestutils.GetRegionFromRequest(req, defaultRegion)
	creds, err := s3.GetBackendCredentials(backendCfgFile, region)
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


func preSignRequestForGet(bucket, key, region, backendCfgFile string, signingTime time.Time, expirySeconds int) (string, error) {
	mainS3ProxyFQDN, err := getMainS3ProxyFQDN()
	if err != nil {
		return "", fmt.Errorf("could not get main S3ProxyFQDN: %s", err)
	}
	url := fmt.Sprintf("https://%s:%d/%s/%s", mainS3ProxyFQDN, viper.GetInt(s3ProxyPort), bucket, key)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("error when creating a request context for url: %s", err)
	}
	signedURI, _ , err := preSignRequestWithServerCreds(req, expirySeconds, signingTime, region, backendCfgFile)
	return signedURI, err
}