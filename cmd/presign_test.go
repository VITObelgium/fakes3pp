package cmd

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	credentials "github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service/s3"
	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/VITObelgium/fakes3pp/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/viper"
)

var testDefaultBackendRegion = "waw3-1"

func setConfigForPresign(t testing.TB){
	backendConfigFile = stageTestingBackendsConfig(t)
	viper.Set(s3ProxyFQDN, []string{"localhost", "localhost2"})
	viper.Set(s3ProxyPort, 8443)
}

func TestValidPreSignWithServerCreds(t *testing.T) {
	setConfigForPresign(t)
	//Given we have a valid signed URI valid for 1 second
	signedURI, err := preSignRequestForGet("pvb-test", "onnx_dependencies_1.16.3.zip", testDefaultBackendRegion, backendConfigFile, time.Now(), 60)
	if err != nil {
		t.Errorf("could not presign request: %s\n", err)
		t.FailNow()
	}
	credentials, err := s3.GetBackendCredentials(backendConfigFile, testDefaultBackendRegion)
	if err != nil {
		t.Errorf("could not get credentials for %s", testDefaultBackendRegion)
		t.FailNow()
	}
	//When we check the signature within 1 second
	isValid, isExpired, err := presign.IsPresignedUrlWithValidSignature(context.Background(), signedURI, credentials)
	//Then it is a valid signature
	if err != nil {
		t.Errorf("Url should have been valid but %s", err)
	}
	if !isValid{
		t.Error("Url was not valid")
	}
	if isExpired{
		t.Error("Url was expired")
	}
}

func getTestingKeyStorageFromEtc(t testing.TB) utils.KeyPairKeeper {
	viper.Set(s3ProxyJwtPrivateRSAKey, "../etc/jwt_testing_rsa")
	return getTestingKeyStorage(t)
}

func TestValidPreSignWithTempCreds(t *testing.T) {
	setConfigForPresign(t)

	keyStorage := getTestingKeyStorageFromEtc(t)

	accessKeyId := "myAccessKeyId"
	secretKey, err := credentials.CalculateSecretKey(accessKeyId, keyStorage)
	if err != nil {
		t.Error("Could not calculate secret key")
		t.FailNow()
	}

	creds := aws.Credentials{
		AccessKeyID: "myAccessKeyId",
		SecretAccessKey: secretKey,
		SessionToken: "Incredibly secure",
	}

	//Given we have a valid signed URI valid for 1 second
	mainS3ProxyFQDN := viper.GetStringSlice(s3ProxyFQDN)[0]
	url := fmt.Sprintf("https://%s:%d/%s/%s", mainS3ProxyFQDN, viper.GetInt(s3ProxyPort), "bucket", "key")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Errorf("error when creating a request context for url: %s", err)
	}

	uri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 100, time.Now(), creds, testDefaultBackendRegion)
	if err != nil {
		t.Errorf("error when signing request with creds: %s", err)
	}
	

	//When we check the signature within 1 second
	isValid, isExpired, err := presign.IsPresignedUrlWithValidSignature(context.Background(), uri, creds)
	//Then it is a valid signature
	if err != nil {
		t.Errorf("Url should have been valid but %s", err)
	}
	if !isValid {
		t.Error("Url was not valid")
	}
	if isExpired{
		t.Error("Url was expired")
	}
}

func TestExpiredPreSign(t *testing.T) {
	setConfigForPresign(t)
	//Given we have a valid signed URI valid for 1 second
	signedURI, err := preSignRequestForGet("pvb-test", "onnx_dependencies_1.16.3.zip", testDefaultBackendRegion, backendConfigFile, time.Now(), 1)
	if err != nil {
		t.Errorf("could not presign request: %s\n", err)
		t.FailNow()
	}
	credentials, err := s3.GetBackendCredentials(backendConfigFile, testDefaultBackendRegion)
	if err != nil {
		t.Errorf("could not get credentials for %s", testDefaultBackendRegion)
		t.FailNow()
	}
	//When we check the signature within 1 second
	isValid, isExpired, err := presign.IsPresignedUrlWithValidSignature(context.Background(), signedURI, credentials)
	//Then it is a valid signature
	if err != nil {
		t.Errorf("Url should have been valid but %s", err)
	}
	if !isValid {
		t.Errorf("Url was not valid")
	}
	if isExpired{
		t.Error("Url was expired")
	}
	//When we would check the url after 1 second
	time.Sleep(1 * time.Second)
	isValid, isExpired, err = presign.IsPresignedUrlWithValidSignature(context.Background(), signedURI, credentials)
	//Then it is no longer a valid signature
	if err != nil {
		t.Errorf("Url should have been valid but %s", err)
	}
	if !isValid {
		t.Errorf("Url not valid but calculated signatur should be valid only expired")
	}
	if !isExpired{
		t.Error("Url was not yet expired")
	}
}