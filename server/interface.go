package server

import (
	"net/http"
)

type Serverable interface {
	http.Handler

	//Get the port name on which to listen
	GetTLSPort() int

	//Get the hostname on which we are listening
	GetListenHost() string

	//Get information to setup TLS
	GetTls() (enabled bool, certFile string, keyFile string)

	//Get an additional http port this is only to be used when requiring both http and https port
	GetHTTPPort() int
}
