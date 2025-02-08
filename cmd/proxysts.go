// Copyright (c) 2024 VITObelgium
//
// This file was inspired by https://github.com/minio/minio/blob/master/cmd/sts-handlers.go
// which has the following copyright notic:
//
// Copyright (c) 2015-2021 MinIO, Inc.
//
// # That file was part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
package cmd

import (
	"fmt"
	"log/slog"

	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	"github.com/VITObelgium/fakes3pp/aws/service/sts"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const proxysts = "proxysts"

func initializePolicyManager() (pm *iam.PolicyManager, err error){
	return iam.NewPolicyManagerForLocalPolicies(viper.GetString(rolePolicyPath))
}

func buildSTSServer() (server.Serverable) {
	BindEnvVariables(proxysts)
	pm, err := initializePolicyManager()
	if err != nil {
		slog.Error("Could not initialize PolicyManager", "error", err)
		panic(fmt.Sprintf("Clould not initialize PolicyManager %s", err))
	}

	fqdns, err := getStsProxyFQDNs()
	if err != nil {
		slog.Error("Could not get sts proxy fqdns", "error", err)
		panic(fmt.Sprintf("Could not get sts proxy fqdns: %s", err))
	}

	s, err := sts.NewSTSServer(
		viper.GetString(s3ProxyJwtPrivateRSAKey),
		viper.GetInt(stsProxyPort),
		fqdns,
		viper.GetString(stsProxyCertFile),
		viper.GetString(stsProxyKeyFile),
		viper.GetString(stsOIDCConfigFile),
		pm,
		getMaxStsDurationSeconds(),
	)
	if err != nil {
		slog.Error("Could not create STS server", "error", err)
		panic(fmt.Sprintf("Could not create STS server: %s", err))
	}
	return s
}

func getServerOptsFromViper() server.ServerOpts{
	return server.ServerOpts{
		MetricsPort: viper.GetInt(metricsPort),
	}
}

// proxystsCmd represents the proxysts command
var proxystsCmd = &cobra.Command{
	Use:   proxysts,
	Short: "A brief description of your command",
	Long: `Spawn a server process that listens for requests and takes API calls
	that follow the STS API. There are only few supporte`,
	Run: func(cmd *cobra.Command, args []string) {
		server.CreateAndStartSync(buildSTSServer(), getServerOptsFromViper())
	},
}

func init() {
	rootCmd.AddCommand(proxystsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// proxystsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// proxystsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
