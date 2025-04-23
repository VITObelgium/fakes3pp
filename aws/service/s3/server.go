package s3

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/VITObelgium/fakes3pp/utils"
)


type S3Server struct{
	server.BasicServer

	//The Key material that is used for signing JWT tokens. Needed for verification.
	jwtKeyMaterial utils.KeyPairKeeper

	fqdns []string

	pm *iam.PolicyManager

	signedUrlGracePeriod time.Duration

	proxyHB interfaces.HandlerBuilderI

	//A manager that knows about the proxied backends
	s3BackendManager interfaces.BackendManager

	//middleware chains for requests
	mws []middleware.Middleware

}

func (s *S3Server) GetListenHost() string {
	return s.fqdns[0]
}

func NewS3Server(
	jwtPrivateRSAKeyFilePath string,
	serverPort int,
	fqdns []string,
	tlsCertFilePath string,
	tlsKeyFilePath string,
	pm *iam.PolicyManager,
	signedUrlGraceTimeSeconds int,
	proxyHB interfaces.HandlerBuilderI,
	s3BackendConfigFilePath string,
	backendLegacyBehaviorDefaultRegion bool,
) (s server.Serverable, err error) {
	s3BackendCfg, err := getBackendsConfig(s3BackendConfigFilePath, backendLegacyBehaviorDefaultRegion)
	if err != nil {
		return nil, err
	}
	if proxyHB == nil {
		proxyHB = justProxied
	}
	return newS3Server(
		jwtPrivateRSAKeyFilePath,
		serverPort,
		fqdns,
		tlsCertFilePath,
		tlsKeyFilePath,
		pm,
		signedUrlGraceTimeSeconds,
		proxyHB,
		s3BackendCfg,
		nil,
	)
}
func newS3Server(
	jwtPrivateRSAKeyFilePath string,
	serverPort int,
	fqdns []string,
	tlsCertFilePath string,
	tlsKeyFilePath string,
	pm *iam.PolicyManager,
	signedUrlGraceTimeSeconds int,
	proxyHB interfaces.HandlerBuilderI,
	s3BackendManager interfaces.BackendManager,
	mws []middleware.Middleware ,
) (s *S3Server, err error) {
	key, err := utils.NewKeyStorage(jwtPrivateRSAKeyFilePath)
	if err != nil {
		return nil, err
	}
	if len(fqdns) == 0 {
		return nil, errors.New("must at least pass in 1 fqdn to create a server")
	}
	basicServer := server.NewBasicServer(serverPort, fqdns[0], tlsCertFilePath, tlsKeyFilePath, nil)
	signedUrlGraceTimeDuration := time.Duration(signedUrlGraceTimeSeconds) * time.Second

	s = &S3Server{
		BasicServer: *basicServer,
		jwtKeyMaterial: key,
		fqdns: fqdns,
		pm: pm,
		signedUrlGracePeriod: signedUrlGraceTimeDuration,
		proxyHB: proxyHB,
		s3BackendManager: s3BackendManager,
		mws: mws,
	}

	if len(mws) == 0 {
		presignAuthOptions := middleware.AuthenticationOptions{Leeway: signedUrlGraceTimeDuration}
		mws = []middleware.Middleware{
			RegisterOperation(),
			middleware.AWSAuthN(key, s3ErrorReporterInstance, s3BackendManager, &presignAuthOptions),
			AWSAuthZS3(key, s3BackendManager, pm, s, s), 
		}
	}
	s.mws = mws
	s.SetHandlerFunc(s.BuildHandlerfunc())
	return s, nil
}

// The cutoff of expiry time lies in the past because we allow presigned urls
// to outlive the credentials lifetime. So if we allow 2 hours of grace time
// then the cutoff we use to check validity is 2 hours ago.
func (s *S3Server)GetCutoffForPresignedUrl() time.Time {
	return time.Now().UTC().Add(
		-s.signedUrlGracePeriod,
	)
}

func (s *S3Server)IsVirtualHostingRequest(req *http.Request) bool {
	hostWithoutPort := strings.ToLower(strings.Split(req.Host, ":")[0])
	for _, fqdn := range s.fqdns {
		lcfqdn := strings.ToLower(fqdn)
		if lcfqdn == hostWithoutPort{
			//Official fqdn is used so this is Path-based hosting.
			return false
		}
	}
	return true
}

//Register routes to S3 router
//For real cases the proxyHB HandlerBuilder should build a handler function
//that sends the request upstream and passes back the response.
func (s *S3Server) BuildHandlerfunc() http.HandlerFunc{
	h := s.proxyHB.Build(s.s3BackendManager)
	return middleware.Chain(h, s.mws...)
}