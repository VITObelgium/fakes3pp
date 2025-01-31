package cmd

import (
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
)


func TestCredential(t *testing.T) {
	BindEnvVariables(proxysts)
	token := createRS256PolicyToken("testIssuer", testEgiIssuer, "subject", "policy", time.Minute, session.AWSSessionTags{})
	ac, err := credentials.NewAWSCredentials(token, time.Second, getSigningKey)
	if err != nil {
		t.Errorf("Oops got error %s when creating %s", err, ac)
	}
	err = ac.IsValid(getSigningKey)
	if err != nil{
		t.Error(err)
	}
	time.Sleep(time.Second)
	err = ac.IsValid(getSigningKey)
	if err != credentials.ErrExpiredAwsCredentials {
		t.Errorf("Expected credential to have expired but it has not")
	}
}