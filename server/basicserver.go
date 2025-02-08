package server

import (
	"log/slog"
	"net/http"
)

//A dummy server mostly to convey access info
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
}

func (s *BasicServer) GetPort() int {
	return s.port
}

func (s *BasicServer) GetListenHost() string {
	return s.hostname
}

func (s *BasicServer) GetTls() (enabled bool, certFile string, keyFile string) {
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

func (s *BasicServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.handlerFunc != nil {
		s.handlerFunc(w, r)
	}
}

func NewBasicServer(port int, hostname string, tlsCertFilePath string,
	tlsKeyFilePath string, handlerFunc http.HandlerFunc) *BasicServer {
	return &BasicServer{
		port: port,
		hostname: hostname,
		tlsCertFilePath: tlsCertFilePath,
		tlsKeyFilePath: tlsKeyFilePath,
		handlerFunc: handlerFunc,
	}
}

func (s *BasicServer) SetHandlerFunc(f http.HandlerFunc) {
	s.handlerFunc = f
}