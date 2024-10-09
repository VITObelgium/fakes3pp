package cmd

import (
	"crypto/rsa"
	"fmt"
	"os"
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
	awsAccessKeyId = "awsAccessKeyId"
	awsSecretAccessKey = "awsSecretAccessKey"
	s3ProxyFQDN = "s3ProxyFQDN"
	s3ProxyPort = "s3ProxyPort"
	s3ProxyCertFile = "s3ProxyCertFile"
	s3ProxyKeyFile = "s3ProxyKeyFile"
	s3ProxyJwtPublicRSAKey = "s3ProxyJwtPublicRSAKey"
	s3ProxyJwtPrivateRSAKey = "s3ProxyJwtPrivateRSAKey"
	s3ProxyTarget = "s3ProxyTarget"
	stsProxyFQDN = "stsProxyFQDN"
	stsProxyPort = "stsProxyPort"
	stsProxyCertFile = "stsProxyCertFile"
	stsProxyKeyFile = "stsProxyKeyFile"
	rolePolicyPath = "rolePolicyPath"
	secure = "secure"
	stsOIDCConfigFile = "stsOIDCConfigFile"
	stsMaxDurationSeconds = "stsMaxDurationSeconds"
	signedUrlGraceTimeSeconds = "signedUrlGraceTimeSeconds"

	//Environment variables are upper cased
	//Unless they are wellknown environment variables they should be prefixed
	AWS_ACCESS_KEY_ID = "AWS_ACCESS_KEY_ID"
	AWS_SECRET_ACCESS_KEY = "AWS_SECRET_ACCESS_KEY"
	FAKES3PP_S3_PROXY_FQDN = "FAKES3PP_S3_PROXY_FQDN"
	FAKES3PP_S3_PROXY_PORT = "FAKES3PP_S3_PROXY_PORT"
	FAKES3PP_S3_PROXY_CERT_FILE = "FAKES3PP_S3_PROXY_CERT_FILE"
	FAKES3PP_S3_PROXY_KEY_FILE = "FAKES3PP_S3_PROXY_KEY_FILE"
	FAKES3PP_S3_PROXY_JWT_PUBLIC_RSA_KEY = "FAKES3PP_S3_PROXY_JWT_PUBLIC_RSA_KEY"
	FAKES3PP_S3_PROXY_JWT_PRIVATE_RSA_KEY = "FAKES3PP_S3_PROXY_JWT_PRIVATE_RSA_KEY"
	FAKES3PP_S3_PROXY_TARGET = "FAKES3PP_S3_PROXY_TARGET"
	FAKES3PP_STS_PROXY_FQDN = "FAKES3PP_STS_PROXY_FQDN"
	FAKES3PP_STS_PROXY_PORT = "FAKES3PP_STS_PROXY_PORT"
	FAKES3PP_STS_PROXY_CERT_FILE = "FAKES3PP_STS_PROXY_CERT_FILE"
	FAKES3PP_STS_PROXY_KEY_FILE = "FAKES3PP_STS_PROXY_KEY_FILE"
	FAKES3PP_SECURE = "FAKES3PP_SECURE"
	FAKES3PP_STS_OIDC_CONFIG = "FAKES3PP_STS_OIDC_CONFIG"
	FAKES3PP_ROLE_POLICY_PATH = "FAKES3PP_ROLE_POLICY_PATH"
	FAKES3PP_STS_MAX_DURATION_SECONDS = "FAKES3PP_STS_MAX_DURATION_SECONDS"
	FAKES3PP_SIGNEDURL_GRACE_TIME_SECONDS = "FAKES3PP_SIGNEDURL_GRACE_TIME_SECONDS"
)

var envVarDefs = []envVarDef{
	{
		awsAccessKeyId,
		AWS_ACCESS_KEY_ID,
		true,
		"The AWS_ACCESS_KEY_ID that will be used to go to the upstream S3 API.",
		[]string{proxys3},
	},
	{
		awsSecretAccessKey,
		AWS_SECRET_ACCESS_KEY,
		true,
		"The AWS_SECRET_ACCESS_KEY that will be used to go to the upstream S3 API.",
		[]string{proxys3},
	},
	{
		s3ProxyFQDN,
		FAKES3PP_S3_PROXY_FQDN,
		true,
		"The fully qualified domain name of this S3 proxy server (e.g. localhost)",
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
		true,
		"The certificate file used for tls server-side",
		[]string{proxys3},
	},
	{
		s3ProxyKeyFile,
		FAKES3PP_S3_PROXY_KEY_FILE,
		true,
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
		s3ProxyTarget,
		FAKES3PP_S3_PROXY_TARGET,
		true,
		"The hostname to be used to connect to the backend.",
		[]string{proxys3},
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
		true,
		"The certificate file used for tls server-side",
		[]string{proxysts},
	},
	{
		stsProxyKeyFile,
		FAKES3PP_STS_PROXY_KEY_FILE,
		true,
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
		"The maximum duration in seconds a signed url can be valid past the lifetime of the credentials used to generate it",
		[]string{},
	},
}

func getSignedUrlGraceTimeSeconds() time.Duration {
	n_sec := viper.GetInt(signedUrlGraceTimeSeconds)

	return time.Second * time.Duration(n_sec)
}

var stsProxyIssuer string

var signingKey *rsa.PrivateKey
func getSigningKey() (*rsa.PrivateKey, error) {
	if signingKey == nil {
		privateKeyPath := viper.GetString(s3ProxyJwtPrivateRSAKey)
		key, err := PrivateKeyFromPemFile(privateKeyPath)
		if err != nil {
			return nil, err
		}
		signingKey = key
	}
	return signingKey, nil
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
	stsProxyIssuer = viper.GetString(stsProxyFQDN)
}

func checkViperVarNotEmpty(evd envVarDef) {
	r := viper.Get(evd.viperKey)
	if r == nil {
		fmt.Printf("key %s[%s](%s) is emtpy\n", evd.viperKey, evd.envVarName, evd.description)
		if evd.isCritical {
			fmt.Printf("key %s[%s] is mandatory, aborting\n", evd.viperKey, evd.envVarName)
			os.Exit(1)
		}
	}
}