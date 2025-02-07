package server_test

import (
	"net/http"
)


type SimpleTestServer struct {
	port int
	hostname string
	h http.HandlerFunc
}

