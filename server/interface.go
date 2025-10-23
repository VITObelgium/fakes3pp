package server

import (
	"net/http"
)

type Serverable interface {
	http.Handler

	//Get the port name on which to listen
	GetPort() int

	//Get the hostname on which we are listening
	GetListenHost() string

	//Get information to setup TLS
	GetTls() (enabled bool, certFile string, keyFile string)
}
