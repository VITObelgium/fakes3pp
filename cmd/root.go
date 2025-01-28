package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/VITObelgium/fakes3pp/logging"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var envFiles string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "fakes3pp",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	logging.InitializeLogging(logging.EnvironmentLvl, nil, nil)
	rootCmd.PersistentFlags().StringVar(&envFiles, "dot-env", "etc/.env", "File paths to .env files comma separated")

	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.fakes3pp.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func loadEnvVarsFromDotEnv() {
	for _, dotEnv := range strings.Split(envFiles, ","){
		if dotEnv == "skip" {
			slog.Info("Skip dotEnv filename %s", "filename", dotEnv)
			return
		}
		if dotEnv == "" {
			continue
		}
		err := godotenv.Load(dotEnv)
		if err != nil {
		  dir, _ := os.Getwd()
		  slog.Error("Error loading .env file", "cwd", dir, "filepath", dotEnv)
		  os.Exit(1)
		}
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".fakes3pp" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".fakes3pp")
	}

	viper.SetEnvPrefix("FAKES3PP")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
	var startupCmd = strings.Join(os.Args, " ")
	slog.Info("Loading env vars from dotenv", "startup_cmd", startupCmd)
	loadEnvVarsFromDotEnv()
}
