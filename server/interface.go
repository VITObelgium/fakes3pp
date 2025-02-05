package server

import "github.com/minio/mux"

type Serverable interface {
	//Get the port name on which to listen
	GetPort() int

	//Get the hostname on which we are listening
	GetListenHost() string

	//Get information to setup TLS
	GetTls() (enabled bool, certFile string, keyFile string)

	//Callback to add routes to a router
	RegisterRoutes(router *mux.Router) (error)
}

