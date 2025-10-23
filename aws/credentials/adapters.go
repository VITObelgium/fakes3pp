package credentials

import "github.com/aws/aws-sdk-go-v2/aws"

func ToAwsSDKCredentials(creds AWSCredentials) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     creds.AccessKey,
		SecretAccessKey: creds.SecretKey,
		SessionToken:    creds.SessionToken,
	}
}
