package cmd

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/VITObelgium/fakes3pp/aws/service/s3/api"
	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/minio/mux"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const proxys3 = "proxys3"

// proxys3Cmd represents the proxyS3 command
var proxys3Cmd = &cobra.Command{
	Use:   proxys3,
	Short: "A brief description of your command",
	Long: `Spawn a server process that listens for requests and takes API calls
	that follow the S3 API.`,
	Run: func(cmd *cobra.Command, args []string) {
		BindEnvVariables(proxys3)
		initializePolicyManager()
		err := initializeS3ProxyKeyFunc(viper.GetString(s3ProxyJwtPublicRSAKey))
		if err != nil {
			panic(err) //Fail hard
		}
		
		if err := initializeGlobalBackendsConfig(); err != nil {
			panic(err) //Fail hard as no valid backends are configured
		}
		s3Proxy()
	},
}

func initializeGlobalBackendsConfig() error {
	cfg, err := getBackendsConfig()
	globalBackendsConfig = cfg
	return err
}

func createAndStartS3Proxy(proxyHB handlerBuilderI) (*sync.WaitGroup, *http.Server, error) {
	s3ProxyDone := &sync.WaitGroup{}
	s3ProxyDone.Add(1)


	portNr := viper.GetInt(s3ProxyPort)
	certFile := viper.GetString(s3ProxyCertFile)
	keyFile := viper.GetString(s3ProxyKeyFile)
	secure := viper.GetBool(secure)
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()

	registerS3Router(router, proxyHB)
	listenAddress := fmt.Sprintf(":%d", portNr)
	slog.Debug("Started listening", "port", portNr)

	srv := &http.Server{Addr: listenAddress}
	srv.Handler = middleware.NewMiddlewarePrefixedHandler(
		router, 
		middleware.LogMiddleware(slog.LevelInfo, middleware.NewPingPongHealthCheck(slog.LevelDebug),),
	)

	// Start proxy in the background but manage waitgroup
	go func() {
		defer s3ProxyDone.Done()
		var err error
		if secure {
			slog.Debug("Starting ListenAndServeTLS", "secure", secure)
			err = srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			slog.Debug("Starting ListenAndServe", "secure", secure)
			err = srv.ListenAndServe()
		}

		if err != http.ErrServerClosed {
			slog.Error(err.Error())
		}
	}()

	err := awaitServerOnPort(portNr, secure)
	if err != nil {
		s3ProxyDone.Done()
		return nil, nil, err
	}

	return s3ProxyDone, srv, nil
}

func s3Proxy() {
	proxyDone, _, err := createAndStartS3Proxy(justProxied)
	if err != nil {
		panic(err)
	}
	proxyDone.Wait()
}

func init() {
	rootCmd.AddCommand(proxys3Cmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// proxyS3Cmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// proxyS3Cmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}

const SlashSeparator = "/"

//Register routes to S3 router
//For real cases the proxyHB HandlerBuilder should build a handler function
//that sends the request upstream and passes back the response.
func registerS3Router(router *mux.Router, proxyHB handlerBuilderI) {
	s3Router := router.NewRoute().PathPrefix(SlashSeparator).Subrouter()
	s3Router.Methods(http.MethodGet).Queries("list-type", "2").HandlerFunc(
		middleware.Chain(proxyHB.Build(false), middleware.RegisterOperation(api.ListObjectsV2)),	
	)
	s3Router.Methods(http.MethodGet).Queries(
		"Signature", "{sig:.*}",
		"x-amz-security-token", "{xast:.*}",
		"AWSAccessKeyId", "{akid:.*}",
	).HandlerFunc(middleware.Chain(proxyHB.Build(true), middleware.RegisterOperation(api.GetObject), middleware.AuthNPresigned()))
	s3Router.Methods(http.MethodGet).Queries("X-Amz-Algorithm", "{alg:.*}", "X-Amz-Signature", "{sig:.*}").HandlerFunc(
		middleware.Chain(proxyHB.Build(true), middleware.RegisterOperation(api.GetObject), middleware.AuthNPresigned())) //TODO: Fix matching to really be GetObject
	s3Router.Methods(http.MethodGet).Path("/").HandlerFunc(
		middleware.Chain(proxyHB.Build(false), middleware.RegisterOperation(api.ListBuckets)))
	s3Router.Methods(http.MethodGet).HandlerFunc(
		middleware.Chain(proxyHB.Build(false), middleware.RegisterOperation(api.GetObject)))
	s3Router.Methods(http.MethodHead).Path("/").HandlerFunc(
		middleware.Chain(proxyHB.Build(false), middleware.RegisterOperation(api.HeadBucket)))
	s3Router.Methods(http.MethodHead).HandlerFunc(
		middleware.Chain(proxyHB.Build(false), middleware.RegisterOperation(api.HeadObject)))

	s3Router.Methods(http.MethodPut).Queries("partNumber", "{pn:.*}", "uploadId", "{ui:.*}").HandlerFunc(
		middleware.Chain(proxyHB.Build(false), middleware.RegisterOperation(api.UploadPart)))
	s3Router.Methods(http.MethodPut).HandlerFunc(
		middleware.Chain(proxyHB.Build(false), middleware.RegisterOperation(api.PutObject)))

	// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html
	s3Router.Methods(http.MethodPost).Queries("uploads", "").HandlerFunc(
		middleware.Chain(proxyHB.Build(false), middleware.RegisterOperation(api.CreateMultipartUpload)))
	s3Router.Methods(http.MethodPost).Queries("uploadId", "{id:.*}").HandlerFunc(
		middleware.Chain(proxyHB.Build(false), middleware.RegisterOperation(api.CompleteMultipartUpload)))

	s3Router.Methods(http.MethodDelete).Queries("uploadId", "{id:.*}").HandlerFunc(
		middleware.Chain(proxyHB.Build(false), middleware.RegisterOperation(api.AbortMultipartUpload)))

	s3Router.PathPrefix("/").HandlerFunc(justLog)
	s3Router.NewRoute().HandlerFunc(justLog)
}

func justLog(w http.ResponseWriter, r *http.Request) {
	slog.InfoContext(r.Context(), "Unknown/Unsupported type of operation")
}
