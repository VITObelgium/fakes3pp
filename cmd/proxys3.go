package cmd

import (
	"fmt"
	"log/slog"

	"github.com/VITObelgium/fakes3pp/aws/service/s3"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const proxys3 = "proxys3"

func buildS3Server() (server.Serverable) {
	BindEnvVariables(proxys3)

		pm, err := initializePolicyManager()
		if err != nil {
			slog.Error("Could not initialize PolicyManager", "error", err)
			panic(fmt.Sprintf("Clould not initialize PolicyManager %s", err))
		}

		fqdns, err := getS3ProxyFQDNs()
		if err != nil {
			slog.Error("Could not get sts proxy fqdns", "error", err)
			panic(fmt.Sprintf("Could not get sts proxy fqdns: %s", err))
		}

		s, err := s3.NewS3Server(
			viper.GetString(s3ProxyJwtPrivateRSAKey),
			viper.GetInt(s3ProxyPort),
			fqdns,
			viper.GetString(s3ProxyCertFile),
			viper.GetString(s3ProxyKeyFile),
			pm,
			viper.GetInt(signedUrlGraceTimeSeconds),
			nil,
			viper.GetString(s3BackendConfigFile),
			viper.GetBool(enableLegacyBehaviorInvalidRegionToDefaultRegion),
		)
		if err != nil {
			slog.Error("Could not create S3 server", "error", err)
			panic(fmt.Sprintf("Could not create S3 server: %s", err))
		}
		return s
}

// proxys3Cmd represents the proxyS3 command
var proxys3Cmd = &cobra.Command{
	Use:   proxys3,
	Short: "A brief description of your command",
	Long: `Spawn a server process that listens for requests and takes API calls
	that follow the S3 API.`,
	Run: func(cmd *cobra.Command, args []string) {
		server.CreateAndStartSync(buildS3Server(), server.ServerOpts{})
	},
}

func init() {
	rootCmd.AddCommand(proxys3Cmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// proxyS3Cmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// proxyS3Cmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
