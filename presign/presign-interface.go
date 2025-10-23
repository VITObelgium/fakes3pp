package presign

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Secret Deriver takes
type SecretDeriver func(accessKeyId string) (secretAccessKey string, err error)

type PresignedUrl interface {
	GetPresignedUrlDetails(context.Context, SecretDeriver) (isValid bool, creds aws.Credentials, expires time.Time, err error)
}
