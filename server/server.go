package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"sync"

	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/minio/mux"
)

//Start a server in the background but return a waitGroup.
//
func CreateAndStart(s Serverable) (*sync.WaitGroup, *http.Server, error) {
	serverDone := &sync.WaitGroup{}
	serverDone.Add(1)
	portNr := s.GetPort()
	tlsEnabled, tlsCertFile, tlsKeyFile := s.GetTls()
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()

	err := s.RegisterRoutes(router)
	if err != nil {
		return nil, nil, err
	}
	listenAddress := fmt.Sprintf(":%d", portNr)
	slog.Info("Started listening", "port", portNr)

	srv := &http.Server{Addr: listenAddress}
	srv.Handler = middleware.NewMiddlewarePrefixedHandler(
		router, 
		middleware.LogMiddleware(slog.LevelInfo, middleware.NewPingPongHealthCheck(slog.LevelInfo),),
	)

	// Start proxy in the background but manage waitgroup
	go func() {
		defer serverDone.Done()
		var err error
		iType := reflect.TypeOf(s)
		if tlsEnabled {
			slog.Info("Starting ListenAndServeTLS", "secure", tlsEnabled, "type", iType)
			err = srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
		} else {
			slog.Info("Starting ListenAndServe", "secure", tlsEnabled, "type", iType)
			err = srv.ListenAndServe()
		}

		if err != http.ErrServerClosed {
			slog.Error(err.Error())
		}
	}()
	return serverDone, srv, nil
}

//Create a server and await until its health check is passing
func CreateAndAwaitHealthy(s Serverable) (*sync.WaitGroup, *http.Server, error) {
	serverDone, srv, err := CreateAndStart(s)
	if err != nil {
		return serverDone, srv, err
	}
	tlsEnabled, _, _ := s.GetTls()
	err = awaitServerOnPort(s.GetPort(), tlsEnabled)
	if err != nil {
		err2 := srv.Shutdown(context.Background())
		if err2 != nil {
			err = fmt.Errorf("error shutting down unhealthy server: %w", err2)
		}
		serverDone.Wait()
		return nil, nil, err
	}

	return serverDone, srv, nil
}

func CreateAndStartSync(s Serverable) {
	proxyDone, _, err := CreateAndAwaitHealthy(s)
	if err != nil {
		panic(err)
	}
	proxyDone.Wait()
}

func getProtocol(tlsEnabled bool) string {
	if tlsEnabled {
		return "https"
	} else {
		return "http"
	}
}

func awaitServerOnPort(port int, tlsEnabled bool) error {
	attempts := 100
	if tlsEnabled{
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s://localhost:%d/ping", getProtocol(tlsEnabled), port), nil)
	var lastErr error
	i := 0
	for i < attempts{
		i += 1
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("server not listening on port %d after %d checks, last err %s", port, attempts, lastErr)
}