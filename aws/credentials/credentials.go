package credentials

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AWSCredentials holds access and secret keys.
// These are different from aws.Credentials because these are actually credentials that only
// live in the realm of our Proxy (STS+S3 environment) and they are not actual AWS credentials
type AWSCredentials struct {
	AccessKey    string                 `xml:"AccessKeyId" json:"accessKey,omitempty" yaml:"accessKey"`
	SecretKey    string                 `xml:"SecretAccessKey" json:"secretKey,omitempty" yaml:"secretKey"`
	SessionToken string                 `xml:"SessionToken" json:"sessionToken,omitempty" yaml:"sessionToken"`
	Expiration   time.Time              `xml:"Expiration" json:"expiration,omitempty" yaml:"-"`
}

var ErrInvalidSecretKey = errors.New("invalid secret access key")
var ErrExpiredAwsCredentials = errors.New("expired credentials")

//Check whether an AWSCredential for the proxy is valid
func (cred *AWSCredentials) isValid(signingKey *rsa.PrivateKey) (error) {
	if cred.Expiration.Before(time.Now().UTC()) {
		return ErrExpiredAwsCredentials
	}

	//Are credentials itself valid
	calculatedSecretKey := CalculateSecretKey(cred.AccessKey, signingKey)
	if calculatedSecretKey != cred.SecretKey {
		return ErrInvalidSecretKey
	}

	//Is SessionToken valid
	claims := jwt.MapClaims{}
	keyFunc := func (t *jwt.Token) (interface{}, error)  {
		return &signingKey.PublicKey, nil
	}

	if _, err := jwt.ParseWithClaims(cred.SessionToken, claims, keyFunc); err != nil {
		return err
	}

	return nil
}

func (cred *AWSCredentials) IsValid(getSigningKey getSigningKey) (error) {
	key, err := getSigningKey()
	if err != nil {
		return err
	}
	return cred.isValid(key)
}


func NewAccessKey() (string) {
	uuidString := uuid.New().String()
	return strings.Replace(uuidString, "-", "", -1)
}

//Probably not how AWS or another S3* service calculates the secret key but it doesn't really matter
//As we never pass this on upstream. But we chose to be able to derive the key using a shared secret
//since that allows calculation everywhere without keeping state to lookup secret key for an access key
func CalculateSecretKey(accessKey string, signingkey *rsa.PrivateKey) (string) {
	secretKeyLength := 42
	hasher := sha1.New()
	toHash := fmt.Sprintf("%s%s", accessKey, signingkey.D.String())
    return base64.URLEncoding.EncodeToString(hasher.Sum([]byte(toHash)))[0:secretKeyLength]
}

type getSigningKey func() (*rsa.PrivateKey, error)

//Generate New AWS Credentials out of a JWT and a specified duration
func NewAWSCredentials(token *jwt.Token, expiry time.Duration, getSigningKey getSigningKey) (*AWSCredentials, error) {
	key, err := getSigningKey()
	if err != nil {
		return nil, err
	}
	sessionToken, err :=token.SignedString(key)
	if err != nil {
		return nil, err
	}
	accessKey := NewAccessKey()
	secretKey := CalculateSecretKey(accessKey, key)
	cred := &AWSCredentials{
		AccessKey: accessKey,
		SecretKey: secretKey,
		SessionToken: sessionToken,
		Expiration: time.Now().UTC().Add(expiry),
	}
	return cred, nil
}

//To satisfy the CredentialsProvider interface
func (cred *AWSCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var awsCred = aws.Credentials{
		AccessKeyID: cred.AccessKey,
		SecretAccessKey: cred.SecretKey,
		SessionToken: cred.SessionToken,
		CanExpire: true,
		Expires: cred.Expiration,
		Source: "stsProxy",
		AccountID: "000000000000",
	}
	return awsCred, nil
}