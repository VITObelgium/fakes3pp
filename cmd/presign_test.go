package cmd

var testDefaultBackendRegion = "waw3-1"

//TODO: Revive presign tests
// func TestValidPreSignWithServerCreds(t *testing.T) {
// 	backendCfgFile := "..."
// 	//Given we have a valid signed URI valid for 1 second
// 	signedURI, err := preSignRequestForGet("pvb-test", "onnx_dependencies_1.16.3.zip", testDefaultBackendRegion, backendCfgFile, time.Now(), 60)
// 	if err != nil {
// 		t.Errorf("could not presign request: %s\n", err)
// 	}
// 	//When we check the signature within 1 second
// 	isValid, err := presign.IsPresignedUrlWithValidSignature(context.Background(), signedURI, getTestServerCreds(t))
// 	//Then it is a valid signature
// 	if err != nil {
// 		t.Errorf("Url should have been valid but %s", err)
// 	}
// 	if !isValid {
// 		t.Errorf("Url was not valid")
// 	}
// }

// func getMainS3ProxyFQDNForTest(t *testing.T) string {
// 	mainS3ProxyFQDN, err := getMainS3ProxyFQDN()
// 	if err != nil {
// 		t.Errorf("COuld not get Main S3 Proxy FQDN: %s", err)
// 		t.FailNow()
// 	}
// 	return mainS3ProxyFQDN
// }

// func TestValidPreSignWithTempCreds(t *testing.T) {
// 	//Given valid server config
// 	BindEnvVariables("proxys3")

// 	accessKeyId := "myAccessKeyId"
// 	key, err := getSigningKey()
// 	if err != nil {
// 		t.Error("Could not get signing key")
// 		t.FailNow()
// 	}
// 	creds := aws.Credentials{
// 		AccessKeyID: "myAccessKeyId",
// 		SecretAccessKey: credentials.CalculateSecretKey(accessKeyId, key),
// 		SessionToken: "Incredibly secure",
// 	}

// 	//Given we have a valid signed URI valid for 1 second
// 	url := fmt.Sprintf("https://%s:%d/%s/%s", getMainS3ProxyFQDNForTest(t), viper.GetInt(s3ProxyPort), "bucket", "key")
// 	req, err := http.NewRequest(http.MethodGet, url, nil)
// 	if err != nil {
// 		t.Errorf("error when creating a request context for url: %s", err)
// 	}

// 	uri, _, err := presign.PreSignRequestWithCreds(context.Background(), req, 100, time.Now(), creds, testDefaultBackendRegion)
// 	if err != nil {
// 		t.Errorf("error when signing request with creds: %s", err)
// 	}
	

// 	//When we check the signature within 1 second
// 	isValid, err := presign.IsPresignedUrlWithValidSignature(context.Background(), uri, creds)
// 	//Then it is a valid signature
// 	if err != nil {
// 		t.Errorf("Url should have been valid but %s", err)
// 	}
// 	if !isValid {
// 		t.Errorf("Url was not valid")
// 	}
// }

// func TestExpiredPreSign(t *testing.T) {
// 	//Given valid server config
// 	BindEnvVariables("proxys3")
// 	//Pre-sign with server creds so must initialize backend config for testing
// 	if err := initializeGlobalBackendsConfig(); err != nil {
// 		t.Error(err) //Fail hard as no valid backends are configured
// 		t.FailNow()
// 	}
// 	//Given we have a valid signed URI valid for 1 second
// 	signedURI, err := PreSignRequestForGet("pvb-test", "onnx_dependencies_1.16.3.zip", testDefaultBackendRegion, time.Now(), 1)
// 	if err != nil {
// 		t.Errorf("could not presign request: %s\n", err)
// 	}
// 	//When we would check the url after 1 second
// 	time.Sleep(1 * time.Second)
// 	isValid, err := presign.IsPresignedUrlWithValidSignature(context.Background(), signedURI, getTestServerCreds(t))
// 	//Then it is no longer a valid signature TODO check
// 	if err != nil {
// 		t.Errorf("Url should have been valid but %s", err)
// 	}
// 	if !isValid {
// 		t.Errorf("Url was not valid")
// 	}
// }