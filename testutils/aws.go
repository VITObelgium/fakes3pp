package testutils

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/server"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)



func getTestAwsConfig(t testing.TB) (aws.Config) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Error(err)
	}

	cfg.HTTPClient = BuildUnsafeHttpClientThatTrustsAnyCert(t)
	return cfg
}

func GetTestClientSts(t testing.TB, stsServer server.Serverable) (*sts.Client) {
	cfg := getTestAwsConfig(t)

	return sts.NewFromConfig(cfg, func (o *sts.Options) {
		o.BaseEndpoint = aws.String(GetTestServerUrl(stsServer))
	})
}

func GetTestClientS3(t testing.TB, region string, creds aws.CredentialsProvider, s3Server server.Serverable) (*s3.Client) {
	cfg := getTestAwsConfig(t)

	client := s3.NewFromConfig(cfg, func (o *s3.Options) {
		o.BaseEndpoint = aws.String(GetTestServerUrl(s3Server))
		o.Credentials = creds
		o.Region = region
		o.UsePathStyle = true
	})

	return client
}


func AssumeRoleWithWebIdentityAgainstTestStsProxy(t testing.TB, token, roleSessionName, roleArn string, stsServer server.Serverable) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	client := GetTestClientSts(t, stsServer)

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleSessionName: &roleSessionName,
		WebIdentityToken: &token,
		RoleArn: &roleArn,
	}

	max1Sec, cancel := context.WithTimeout(context.Background(), 1000 * time.Second)
	defer cancel()
	result, err := client.AssumeRoleWithWebIdentity(
		max1Sec, input,
	)

	return result, err
}

func GetTestServerUrl(s server.Serverable) string {
	protocol := "http"
	tlsEnabled, _, _ := s.GetTls()
	if tlsEnabled {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%d/", protocol, s.GetListenHost(), s.GetPort())
}