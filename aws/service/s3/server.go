package s3

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/VITObelgium/fakes3pp/utils"
	"github.com/minio/mux"
)


type S3Server struct{
	//The Key material that is used for signing JWT tokens. Needed for verification.
	jwtKeyMaterial utils.KeyPairKeeper

	fqdns []string

	port  int

	//The TLS certificate used to encrypt traffic with if omitted HTTP server will be spawned
	tlsCertFilePath string

	//The TLS key used to encrypt traffic with if omitted HTTP server will be spawned
	tlsKeyFilePath string

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

	if mws == nil || len(mws) == 0 {
		mws = []middleware.Middleware{
			RegisterOperation(),
			middleware.AWSAuthN(key, s3ErrorReporterInstance, s3BackendManager),
		}
	}
	
	s = &S3Server{
		jwtKeyMaterial: key,
		fqdns: fqdns,
		port: serverPort,
		tlsCertFilePath: tlsCertFilePath,
		tlsKeyFilePath: tlsKeyFilePath,
		pm: pm,
		signedUrlGracePeriod: time.Duration(signedUrlGraceTimeSeconds) * time.Second,
		proxyHB: proxyHB,
		s3BackendManager: s3BackendManager,
		mws: mws,
	}
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


func (s *S3Server) GetPort() (int) {
	return s.port
}

func (s *S3Server) GetTls() (enabled bool, certFile string, keyFile string) {
	enabled = true
	if certFile == "" {
		slog.Debug("Disabling TLS", "reason", "no certFile provided")
		enabled = false
	} else if keyFile == "" {
		slog.Debug("Disabling TLS", "reason", "no keyFile provided")
		enabled = false
	}
	return enabled, s.tlsCertFilePath, s.tlsKeyFilePath
}

//Register routes to S3 router
//For real cases the proxyHB HandlerBuilder should build a handler function
//that sends the request upstream and passes back the response.
func (s *S3Server) RegisterRoutes(router *mux.Router) error {
	normalAuthHandler := s.proxyHB.Build(
		false,
		s.s3BackendManager,
		s.pm,
		s.jwtKeyMaterial,
		s,
		s,
	)
	presignAuthHandler := s.proxyHB.Build(
		true,
		s.s3BackendManager,
		s.pm,
		s.jwtKeyMaterial,
		s,
		s,
	)

	s3Router := router.NewRoute().PathPrefix(server.SlashSeparator).Subrouter()
	s3Router.Methods(http.MethodGet).Queries("list-type", "2").HandlerFunc(
		middleware.Chain(normalAuthHandler, s.mws...),	
	)
	s3Router.Methods(http.MethodGet).Queries(
		"Signature", "{sig:.*}",
		"x-amz-security-token", "{xast:.*}",
		"AWSAccessKeyId", "{akid:.*}",
	).HandlerFunc(middleware.Chain(presignAuthHandler, s.mws...))
	s3Router.Methods(http.MethodGet).Queries("X-Amz-Algorithm", "{alg:.*}", "X-Amz-Signature", "{sig:.*}").HandlerFunc(
		middleware.Chain(presignAuthHandler, s.mws...)) //TODO: Fix matching to really be GetObject
	s3Router.Methods(http.MethodGet).Path("/").HandlerFunc(
		middleware.Chain(normalAuthHandler, s.mws...))
	s3Router.Methods(http.MethodGet).HandlerFunc(
		middleware.Chain(normalAuthHandler, s.mws...))
	s3Router.Methods(http.MethodHead).Path("/").HandlerFunc(
		middleware.Chain(normalAuthHandler, s.mws...))
	s3Router.Methods(http.MethodHead).HandlerFunc(
		middleware.Chain(normalAuthHandler, s.mws...))

	s3Router.Methods(http.MethodPut).Queries("partNumber", "{pn:.*}", "uploadId", "{ui:.*}").HandlerFunc(
		middleware.Chain(normalAuthHandler, s.mws...))
	s3Router.Methods(http.MethodPut).HandlerFunc(
		middleware.Chain(normalAuthHandler, s.mws...))

	// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html
	s3Router.Methods(http.MethodPost).Queries("uploads", "").HandlerFunc(
		middleware.Chain(normalAuthHandler, s.mws...))
	s3Router.Methods(http.MethodPost).Queries("uploadId", "{id:.*}").HandlerFunc(
		middleware.Chain(normalAuthHandler, s.mws...))

	s3Router.Methods(http.MethodDelete).Queries("uploadId", "{id:.*}").HandlerFunc(
		middleware.Chain(normalAuthHandler, s.mws...))

	s3Router.PathPrefix("/").HandlerFunc(justLog)
	s3Router.NewRoute().HandlerFunc(justLog)
	return nil
}

func justLog(w http.ResponseWriter, r *http.Request) {
	slog.InfoContext(r.Context(), "Unknown/Unsupported type of operation")
}