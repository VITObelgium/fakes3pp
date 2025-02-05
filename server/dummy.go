package server

import "github.com/minio/mux"

//A dummy server mostly to convey access info
type dummyServer struct {
	port int
	hostname string
}

func (s *dummyServer) GetPort() int {
	return s.port
}

func (s *dummyServer) GetListenHost() string {
	return s.hostname
}

func (s *dummyServer) GetTls() (enabled bool, certFile string, keyFile string) {
	return
}

func (s *dummyServer) RegisterRoutes(router *mux.Router) (error) {
	return nil
}

func NewHttpDummyServer(port int, hostname string) Serverable {
	return &dummyServer{
		port: port,
		hostname: hostname,
	}
}