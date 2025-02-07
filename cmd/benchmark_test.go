package cmd

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/VITObelgium/fakes3pp/testutils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)




func getS3ClientAgainstFakeS3Backend(t testing.TB, region string, creds aws.Credentials) (*s3.Client) {

	backendServer := server.NewBasicServer(fakeTestBackendPorts[region], fakeTestBackendHostnames[region], "", "", nil)
	return testutils.GetTestClientS3(t, region, credentials.FromAwsFormat(creds), backendServer)
}

//This is a helper to be able to read a random string limited to a size while making it seekable.
//NonDeterministic is an imporant characteristic to be careful with. If you seek the start (offset=0) you can again read N bytes from it but
//they would not be the same as bytes read previously. 
//While s3.PutObjectInput takes a Reader it actually requires a ReadSeeker for singing the request (when using HTTPS
//the s3.PutObjectInput does not sign the payload but when sending over HTTP then it will). So we must reset N of the limited reader when we
//Seek because the Signing middle ware would consume the reader and the actual request would have an exhausted LimitedReader if we don't action the
//Seek which would lead in 0-byte objects being sent.
//You can only use this against dummy backends which do not check Payload signature (like moto which is used in our test cases)
type nonDeterministicLimitedRandReadSeeker struct{
	lr io.LimitedReader
	N  int64  //How much can be maximally read
}

func newNonDeterministicLimitedRandReadSeeker(n int64) *nonDeterministicLimitedRandReadSeeker{
	return &nonDeterministicLimitedRandReadSeeker{
		lr: io.LimitedReader{
			R: rand.Reader,
			N: n,
		},
		N: n,
	}
}

func (ndlrrs *nonDeterministicLimitedRandReadSeeker) Read(b []byte) (n int, err error) {
	return ndlrrs.lr.Read(b)
}

func (ndlrrs *nonDeterministicLimitedRandReadSeeker) Seek(offset int64, whence int) (int64, error) {
	//Reset how much can be read based on the offset seeked
	if offset > ndlrrs.N {
		return -1, errors.New("Seek beyond Limit of Limited reader")
	}
	ndlrrs.lr.N = ndlrrs.N - offset
	return offset, nil
}


func createRandomObjectInBackend(c *s3.Client, bucket, key string, size int64) (*s3.PutObjectOutput, error) {
	rr := newNonDeterministicLimitedRandReadSeeker(size)
	putObjectInput := s3.PutObjectInput{
		Bucket: &bucket,
		Key: &key,
		Body: rr,
		ContentLength: &size,
	}
	max120Sec, cancel := context.WithTimeout(context.Background(), 120 * time.Second)
	defer cancel()

	return c.PutObject(
		max120Sec,
		&putObjectInput,
		
	)
}



func getTestBucketObjectContentReadLength(t testing.TB, client s3.Client, objectKey string) (int64, smithy.APIError){	
	max10Sec, cancel := context.WithTimeout(context.Background(), 10 * time.Second)

	input := s3.GetObjectInput{
		Bucket: &testingBucketNameBackenddetails,
		Key: &objectKey,
	}
	defer cancel()
	s3ObjectOutput, err := client.GetObject(max10Sec, &input)
	if err != nil {
		var oe smithy.APIError
		if !errors.As(err, &oe) {
				t.Errorf("Could not convert smity error")
				t.FailNow()
		}
		return 0, oe
	}
	written, err := io.Copy(io.Discard, s3ObjectOutput.Body)
	if err != nil {
		t.Errorf("Encountered error %s", err)
		t.FailNow()
	}
	return written, nil
}

//This is a testing fixture but where sts and s3 proxy are running in plaintext mode
//This is not really a common deployment setup but if we use TLS for our proxy but not for our testing backend
//Then we get misleading performance metrics as mentioned in https://github.com/VITObelgium/fakes3pp/pull/21#issuecomment-2620902233
//Using plain text will be a fairer comparison.
func testingFixturePlainTextProxy(t testing.TB) (
	tearDown func ()(), getToken func(subject string, d time.Duration, tags session.AWSSessionTags) string, stsServer server.Serverable, s3Server server.Serverable){
	resetEnv := fixture_with_environment_values(t, map[string]string{
		FAKES3PP_SECURE: "false",
	})
	tearDown1, getSignedToken, stsServer, s3Server := testingFixture(t)
	tearDown = func() {
		tearDown1()
		resetEnv()
	}
	return tearDown, getSignedToken, stsServer, s3Server
}


func BenchmarkFakeS3Proxy(b *testing.B) {
	initializeTestLogging()
	tearDown, getSignedToken, stsServer, s3Server := testingFixturePlainTextProxy(b)
	defer tearDown()
	token := getSignedToken("mySubject", time.Minute * 20, session.AWSSessionTags{PrincipalTags: map[string][]string{"org": {"a"}}})
	//Given credentials that use the policy that allow everything in Region1
	creds := getCredentialsFromTestStsProxy(b, token, "my-session", testPolicyAllowAllInRegion1ARN, stsServer)

	backendClient := getS3ClientAgainstFakeS3Backend(b, testRegion1, creds)
	proxyClient := testutils.GetTestClientS3(b, testRegion1, credentials.FromAwsFormat(creds), s3Server)

	testObject128MBName := "BenchmarkRandomS3Object"
	testObject128MBSize := int64(128*1024*1024)

	var targets = map[string]*s3.Client{
		"FakeS3Backend": backendClient,
		"S3ProxyBeforeFakeS3Backend": proxyClient,
	}

	testListBucketObjects := func (b *testing.B, testCase string, client *s3.Client) {
		b.StartTimer()
		listObjects, err := _listTestBucketObjects(b, "", client)
		b.StopTimer()
		//THEN it should just succeed as any action is allowed
		if err != nil {
			b.Errorf("Could not get objects in bucket due to error %s", err)
		} 
		//THEN it should report the known objects "region.txt" and "team.txt"
		assertObjectInBucketListing(b, listObjects, "region.txt")
		assertObjectInBucketListing(b, listObjects, "team.txt")
	}

	testGetBucketObjectContentReadLength := func (b *testing.B, testCase string, client *s3.Client) {
		b.StartTimer()
		bytesRead, err := getTestBucketObjectContentReadLength(b, *backendClient, testObject128MBName)
		b.StopTimer()
		//THEN it should just succeed as any action is allowed
		if err != nil {
			b.Errorf("Could not get objects in bucket due to error %s", err)
		} 
		if bytesRead != testObject128MBSize {
			b.Errorf("Read %d bytes but uploaded %d bytes", bytesRead, testObject128MBSize)
		}
	}


	createRandomObject128MB := func(b *testing.B, testCase string, client *s3.Client) {
		b.StartTimer()
		_, err := createRandomObjectInBackend(client, testingBucketNameBackenddetails, testObject128MBName, testObject128MBSize)
		b.StopTimer()
		//THEN it should just succeed as any action is allowed
		if err != nil {
			b.Errorf("Could not create object in bucket due to error %s", err)
		} 
	}

	var testCases = []struct{
		Name string
		Func func (*testing.B, string, *s3.Client)
	} {
		{"createRandomObject256MB", createRandomObject128MB},
		{"listBucketObjects", testListBucketObjects},
		{"getBucketObjectContentReadLength", testGetBucketObjectContentReadLength},
	}

	b.ResetTimer()
	b.StopTimer()
	for targetName, targetClient := range targets {
		for _, testCase := range testCases {
			testName := fmt.Sprintf("%s-%s", targetName, testCase.Name)
			b.Run(testName, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					testCase.Func(b, testName, targetClient)
				}
			})
		}
	}
}