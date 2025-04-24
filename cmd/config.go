package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type envVarDef struct {
	//How this config will be retrieved through viper
	viperKey string
	//How this env var is named in the OS env var space
	envVarName string
	//Whether this env var is critical (absolutely required) for execution
	isCritical bool
	//Explain what this env var is for
	description string
	//The cli commands for which it is used
	cmds        []string
}

func (e envVarDef) shouldBeSetFor(cmd string) (bool) {
	for _, applicableCmd := range e.cmds {
		if applicableCmd == cmd {
			return true
		}
	}
	return false
} 

const(
	s3ProxyFQDN = "s3ProxyFQDN"
	s3ProxyPort = "s3ProxyPort"
	s3ProxyCertFile = "s3ProxyCertFile"
	s3ProxyKeyFile = "s3ProxyKeyFile"
	s3ProxyJwtPublicRSAKey = "s3ProxyJwtPublicRSAKey"
	s3ProxyJwtPrivateRSAKey = "s3ProxyJwtPrivateRSAKey"
	stsProxyFQDN = "stsProxyFQDN"
	stsProxyPort = "stsProxyPort"
	stsProxyCertFile = "stsProxyCertFile"
	stsProxyKeyFile = "stsProxyKeyFile"
	stsMinimalDurationSeconds = "stsMinimalDurationSeconds"
	rolePolicyPath = "rolePolicyPath"
	secure = "secure"
	stsOIDCConfigFile = "stsOIDCConfigFile"
	s3BackendConfigFile = "s3BackendConfigFile"
	stsMaxDurationSeconds = "stsMaxDurationSeconds"
	signedUrlGraceTimeSeconds = "signedUrlGraceTimeSeconds"
	enableLegacyBehaviorInvalidRegionToDefaultRegion = "enableLegacyBehaviorInvalidRegionToDefaultRegion"
	logLevel = "logLevel"
	metricsPort = "metricsPort"
	

	//Environment variables are upper cased
	//Unless they are wellknown environment variables they should be prefixed
	FAKES3PP_S3_PROXY_FQDN = "FAKES3PP_S3_PROXY_FQDN"
	FAKES3PP_S3_PROXY_PORT = "FAKES3PP_S3_PROXY_PORT"
	FAKES3PP_S3_PROXY_CERT_FILE = "FAKES3PP_S3_PROXY_CERT_FILE"
	FAKES3PP_S3_PROXY_KEY_FILE = "FAKES3PP_S3_PROXY_KEY_FILE"
	FAKES3PP_S3_PROXY_JWT_PUBLIC_RSA_KEY = "FAKES3PP_S3_PROXY_JWT_PUBLIC_RSA_KEY"
	FAKES3PP_S3_PROXY_JWT_PRIVATE_RSA_KEY = "FAKES3PP_S3_PROXY_JWT_PRIVATE_RSA_KEY"
	FAKES3PP_STS_PROXY_FQDN = "FAKES3PP_STS_PROXY_FQDN"
	FAKES3PP_STS_PROXY_PORT = "FAKES3PP_STS_PROXY_PORT"
	FAKES3PP_STS_PROXY_CERT_FILE = "FAKES3PP_STS_PROXY_CERT_FILE"
	FAKES3PP_STS_PROXY_KEY_FILE = "FAKES3PP_STS_PROXY_KEY_FILE"
	FAKES3PP_STS_MINIMAL_DURATION_SECONDS = "FAKES3PP_STS_MINIMAL_DURATION_SECONDS"
	FAKES3PP_SECURE = "FAKES3PP_SECURE"
	FAKES3PP_STS_OIDC_CONFIG = "FAKES3PP_STS_OIDC_CONFIG"
	FAKES3PP_S3_BACKEND_CONFIG = "FAKES3PP_S3_BACKEND_CONFIG"
	FAKES3PP_ROLE_POLICY_PATH = "FAKES3PP_ROLE_POLICY_PATH"
	FAKES3PP_STS_MAX_DURATION_SECONDS = "FAKES3PP_STS_MAX_DURATION_SECONDS"
	FAKES3PP_SIGNEDURL_GRACE_TIME_SECONDS = "FAKES3PP_SIGNEDURL_GRACE_TIME_SECONDS"
	ENABLE_LEGACY_BEHAVIOR_INVALID_REGION_TO_DEFAULT_REGION = "ENABLE_LEGACY_BEHAVIOR_INVALID_REGION_TO_DEFAULT_REGION"
	LOG_LEVEL = "LOG_LEVEL"
	FAKES3PP_METRICS_PORT = "FAKES3PP_METRICS_PORT"
)

var envVarDefs = []envVarDef{
	{
		s3ProxyFQDN,
		FAKES3PP_S3_PROXY_FQDN,
		true,
		`The fully qualified domain name(s) of this S3 proxy server (e.g. localhost).
		You can specify multiple to allow access via multiple FQDNs but the first one will be used for generating pre-signed urls.
		When specifying multiple they must be comma-separated.`,
		[]string{proxys3},
	},
	{
		s3ProxyPort,
		FAKES3PP_S3_PROXY_PORT,
		true,
		"The port on which this S3 proxy server is reachable (e.g. 8443)",
		[]string{proxys3},
	},
	{
		s3ProxyCertFile,
		FAKES3PP_S3_PROXY_CERT_FILE,
		false,
		"The certificate file used for tls server-side",
		[]string{proxys3},
	},
	{
		s3ProxyKeyFile,
		FAKES3PP_S3_PROXY_KEY_FILE,
		false,
		"The key file used for tls server-side",
		[]string{proxys3},
	},
	{
		s3ProxyJwtPrivateRSAKey,
		FAKES3PP_S3_PROXY_JWT_PRIVATE_RSA_KEY,
		true,
		"The key file used for signing JWT tokens",
		[]string{proxys3, proxysts},
	},
	{
		s3ProxyJwtPublicRSAKey,
		FAKES3PP_S3_PROXY_JWT_PUBLIC_RSA_KEY,
		true,
		"The key file used for signing JWT tokens",
		[]string{proxys3, proxysts},
	},
	{
		stsProxyFQDN,
		FAKES3PP_STS_PROXY_FQDN,
		true,
		"The fully qualified domain name of this STS proxy server (e.g. localhost)",
		[]string{proxysts, proxys3},
	},
	{
		stsProxyPort,
		FAKES3PP_STS_PROXY_PORT,
		true,
		"The port on which this STS proxy server is reachable (e.g. 8444)",
		[]string{proxysts},
	},
	{
		stsProxyCertFile,
		FAKES3PP_STS_PROXY_CERT_FILE,
		false,
		"The certificate file used for tls server-side",
		[]string{proxysts},
	},
	{
		stsProxyKeyFile,
		FAKES3PP_STS_PROXY_KEY_FILE,
		false,
		"The key file used for tls server-side",
		[]string{proxysts},
	},
	{
		secure,
		FAKES3PP_SECURE,
		true,
		"Whether TLS is used",
		[]string{proxysts, proxys3},
	},
	{
		stsOIDCConfigFile,
		FAKES3PP_STS_OIDC_CONFIG,
		true,
		"The configuration of which issuers are trusted for OIDC tokens",
		[]string{proxysts},
	},
	{
		s3BackendConfigFile,
		FAKES3PP_S3_BACKEND_CONFIG,
		true,
		"The configuration of the backends that are proxied. See the sample start config for details how to configure these backends",
		[]string{proxys3},
	},
	{
		rolePolicyPath,
		FAKES3PP_ROLE_POLICY_PATH,
		true,
		"The path in which there are files with names corresponsing to the base32 encoded role name and content the policy",
		[]string{proxysts, proxys3},
	},
	{
		stsMaxDurationSeconds,
		FAKES3PP_STS_MAX_DURATION_SECONDS,
		false,
		"The maximum duration temporary credentials retrieved by STS can be valid for",
		[]string{proxysts},
	},
	{
		signedUrlGraceTimeSeconds,
		FAKES3PP_SIGNEDURL_GRACE_TIME_SECONDS,
		false,
		"The maximum duration in seconds a signed url can be valid past the lifetime of the credentials used to generate it (for GetObject)",
		[]string{proxys3},
	},
	{
		enableLegacyBehaviorInvalidRegionToDefaultRegion,
		ENABLE_LEGACY_BEHAVIOR_INVALID_REGION_TO_DEFAULT_REGION,
		false,
		"If set to true invalid regions will not necessarily fail but will try default region",
		[]string{proxys3},
	},
	{
		logLevel,
		LOG_LEVEL,
		false,
		"The Loglevel at which to run (DEBUG, INFO (default), WARN, ERROR)",
		[]string{proxys3, proxysts},
	},
	{
		metricsPort,
		FAKES3PP_METRICS_PORT,
		false,
		"The port on which to run the /metrics endpoint",
		[]string{proxys3, proxysts},
	},
	{
		stsMinimalDurationSeconds,
		FAKES3PP_STS_MINIMAL_DURATION_SECONDS,
		false,
		"The minimal duration for an STS session in seconds (must be greater than 0 and defaults to 15 minutes",
		[]string{proxysts},
	},
}

func getMinStsDurationSeconds() int {
	minDurationSeconds := viper.GetInt(stsMinimalDurationSeconds)
	if minDurationSeconds == 0 {
		return 15 * 60  // We take same minimum as AWS does: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
	}
	return minDurationSeconds
}

func getMaxStsDurationSeconds() int {
	maxDurationSeconds := viper.GetInt(stsMaxDurationSeconds)
	if maxDurationSeconds == 0 {
		return 12 * 3600
	}
	return maxDurationSeconds
}

func getMaxStsDuration() (time.Duration) {
	return time.Second * time.Duration(getMaxStsDurationSeconds())
}

//The Fully Qualified Domain names for the S3 proxy
var s3ProxyFQDNs []string

func getStsProxyFQDNs() ([]string, error) {
	var fqdns []string
	err := viper.UnmarshalKey(stsProxyFQDN, &fqdns)
	if err != nil {
		return nil, err
	}
	return fqdns, nil
}

func getS3ProxyFQDNs() ([]string, error) {
	var fqdns []string
	err := viper.UnmarshalKey(s3ProxyFQDN, &fqdns)
	if err != nil {
		return nil, err
	}
	return fqdns, nil
}

//TODO: make sure same is used for STS
//get all the FQDNs associated with the S3 Proxy
func getS3ProxyLCFQDNs() ([]string, error) {
	if s3ProxyFQDNs == nil {
		tmpS3ProxyFQDNS, err := getS3ProxyFQDNs()
		if err != nil {
			return nil, err
		}
		s3ProxyFQDNs = make([]string, len(tmpS3ProxyFQDNS))
		for i, tmpFQDN := range tmpS3ProxyFQDNS {
			s3ProxyFQDNs[i] = strings.ToLower(tmpFQDN)
		}
	}	
	return s3ProxyFQDNs, nil
}

//get the main FQDN associated with the S3 proxy
func getMainS3ProxyFQDN() (string, error) {
	fqdns, err := getS3ProxyLCFQDNs()
	if err != nil {
		return "", err
	}
	if len(fqdns) == 0 {
		return "", errors.New("no S3ProxyFQDN available")
	}
	return fqdns[0], nil
}

//Bind the environment variables for a command
func BindEnvVariables(cmd string) {
	for _, evd := range envVarDefs {
		if evd.shouldBeSetFor(cmd) {
			err := viper.BindEnv(evd.viperKey, evd.envVarName)
			if err != nil {
				panic(err)
			}
			checkViperVarNotEmpty(evd)
		}
	}
}

func checkViperVarNotEmpty(evd envVarDef) {
	r := viper.Get(evd.viperKey)
	if r == nil {
		if evd.isCritical {
			slog.Error("Mandatory key is empty", "viperKey", evd.viperKey, "envVarName", evd.envVarName, "description", evd.description)
			fmt.Printf("key %s[%s] is mandatory, aborting\n", evd.viperKey, evd.envVarName)
			os.Exit(1)
		} else {
			slog.Info("Optional key empty", "viperKey", evd.viperKey, "envVarName", evd.envVarName, "description", evd.description)
		}
	}
}