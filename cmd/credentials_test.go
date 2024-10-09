package cmd

import (
	"testing"
	"time"
)


func TestCredential(t *testing.T) {
	BindEnvVariables(proxysts)
	token := createRS256PolicyToken("testIssuer", testEgiIssuer, "subject", "policy", time.Minute)
	ac, err := NewAWSCredentials(token, time.Second)
	if err != nil {
		t.Errorf("Oops got error %s when creating %s", err, ac)
	}
	key, err := getSigningKey()
	if err != nil {
		t.Error(err)
	}
	err = ac.isValid(key)
	if err != nil{
		t.Error(err)
	}
	time.Sleep(time.Second)
	err = ac.isValid(key)
	if err != errExpiredAwsCredentials {
		t.Errorf("Expected credential to have expired but it has not")
	}
}