package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Defines optional configuration for a Serverable
type ServerOpts struct {
	//The default of 0 means no metrics are exposed
	MetricsPort int

	//The loglevel at which request start and stop events are logged
	RequestLogLvl slog.Level

	//The healthchecker used
	healthchecker middleware.HealthChecker
}

func StartPrometheusMetricsServer(port int) (func(), prometheus.Registerer) {
	if port == 0 {
		return nil, nil
	}
	// Create non-global registry.
	reg := prometheus.NewRegistry()

	// Add go runtime metrics and process collectors.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	mux := http.NewServeMux()
	// Expose /metrics HTTP endpoint using the created custom registry.
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	var addr = fmt.Sprintf(":%d", port)

	metricsSrvDone := &sync.WaitGroup{}
	metricsSrvDone.Add(1)
	var metricsSrv = &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 3 * time.Second, //Protect against potential slowloeris attack
	}
	metricsSrv.Handler = mux

	go func() {
		defer metricsSrvDone.Done()
		err := metricsSrv.ListenAndServe()

		if err != http.ErrServerClosed {
			slog.Error(err.Error())
		}
	}()

	shutdownMetricsServerSync := func() {
		err := metricsSrv.Shutdown(context.Background())
		if err != nil {
			panic(err)
		}
	}

	return shutdownMetricsServerSync, reg
}

// Start a server in the background but return a waitGroup.
func CreateAndStart(s Serverable, opts ServerOpts) (*sync.WaitGroup, *http.Server, error) {
	shutdownMetricsServerSync, reg := StartPrometheusMetricsServer(opts.MetricsPort)

	serverDone := &sync.WaitGroup{}
	serverDone.Add(1)
	portNr := s.GetPort()
	tlsEnabled, tlsCertFile, tlsKeyFile := s.GetTls()

	listenAddress := fmt.Sprintf(":%d", portNr)
	slog.Info("Started listening", "port", portNr)

	srv := &http.Server{
		Addr:              listenAddress,
		ReadHeaderTimeout: 3 * time.Second, //Protect against potential slowloeris attack
	}
	if shutdownMetricsServerSync != nil {
		srv.RegisterOnShutdown(shutdownMetricsServerSync)
	}
	healthchecker := opts.healthchecker
	if healthchecker == nil {
		healthchecker = middleware.NewPingPongHealthCheck(slog.LevelDebug)
	}
	srv.Handler = middleware.NewMiddlewarePrefixedHandler(
		s,
		middleware.LogMiddleware(opts.RequestLogLvl, healthchecker, reg),
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

// Create a server and await until its health check is passing
func CreateAndAwaitHealthy(s Serverable, opts ServerOpts) (*sync.WaitGroup, *http.Server, error) {
	serverDone, srv, err := CreateAndStart(s, opts)
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

func CreateAndStartSync(s Serverable, opts ServerOpts) {
	proxyDone, _, err := CreateAndAwaitHealthy(s, opts)
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
	if tlsEnabled {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- for localhost check
	}
	client := &http.Client{}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s://localhost:%d/ping", getProtocol(tlsEnabled), port), nil)
	var lastErr error
	i := 0
	for i < attempts {
		i += 1
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("server not listening on port %d after %d checks, last err %s", port, attempts, lastErr)
}
