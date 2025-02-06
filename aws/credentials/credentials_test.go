package credentials_test

import (
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/VITObelgium/fakes3pp/utils"
)


func TestCredential(t *testing.T) {
	pathToTestKey := "../../etc/jwt_testing_rsa"
	keyStorage, err := utils.NewKeyStorage(pathToTestKey)
	if err != nil {
		t.Fatalf("Could not load test key")
		t.FailNow()
	}
	testEgiIssuer := "https://aai.egi.eu/auth/realms/egi"

	token := credentials.CreateRS256PolicyToken("testIssuer", testEgiIssuer, "subject", "policy", time.Minute, session.AWSSessionTags{})
	ac, err := credentials.NewAWSCredentials(token, time.Second, keyStorage)
	if err != nil {
		t.Errorf("Oops got error %s when creating %s", err, ac)
	}
	err = ac.IsValid(keyStorage)
	if err != nil{
		t.Error(err)
	}
	time.Sleep(time.Second)
	err = ac.IsValid(keyStorage)
	if err != credentials.ErrExpiredAwsCredentials {
		t.Errorf("Expected credential to have expired but it has not")
	}
}