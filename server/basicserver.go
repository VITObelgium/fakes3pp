package server

import (
	"log/slog"
	"net/http"
)

// A dummy server mostly to convey access info
type BasicServer struct {
	// The port on which to listen for incoming requests
	port int

	//The hostname at which the server is reachable
	hostname string

	//The TLS certificate used to encrypt traffic with if omitted HTTP server will be spawned
	tlsCertFilePath string

	//The TLS key used to encrypt traffic with if omitted HTTP server will be spawned
	tlsKeyFilePath string

	handlerFunc http.HandlerFunc

	//If this is not 0 then an HTTP listener will be started on this port
	extraHttpPort int
}

func (s *BasicServer) GetTLSPort() int {
	return s.port
}

func (s *BasicServer) GetListenHost() string {
	return s.hostname
}

func (s *BasicServer) GetTls() (enabled bool, certFile string, keyFile string) {
	enabled = true
	if s.tlsCertFilePath == "" {
		slog.Debug("Disabling TLS", "reason", "no certFile provided")
		enabled = false
	} else if s.tlsKeyFilePath == "" {
		slog.Debug("Disabling TLS", "reason", "no keyFile provided")
		enabled = false
	} else if s.port == 0 {
		slog.Debug("Disabling TLS", "reason", "port was set to 0")
		enabled = false
	}
	return enabled, s.tlsCertFilePath, s.tlsKeyFilePath
}

func (s *BasicServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.handlerFunc != nil {
		s.handlerFunc(w, r)
	}
}

func NewBasicServer(port int, hostname string, tlsCertFilePath string,
	tlsKeyFilePath string, handlerFunc http.HandlerFunc, extraHttpPort int) *BasicServer {
	return &BasicServer{
		port:            port,
		hostname:        hostname,
		tlsCertFilePath: tlsCertFilePath,
		tlsKeyFilePath:  tlsKeyFilePath,
		handlerFunc:     handlerFunc,
		extraHttpPort:   extraHttpPort,
	}
}

func (s *BasicServer) SetHandlerFunc(f http.HandlerFunc) {
	s.handlerFunc = f
}

func (s *BasicServer) GetHTTPPort() int {
	//For testing we do not need to
	return s.extraHttpPort
}
