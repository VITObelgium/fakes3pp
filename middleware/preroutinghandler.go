package middleware

import "net/http"

//A handler that can have middleware applied to requests prior to calling the handler (see NewMiddlewarePrefixedHandler)
type middlewarePrefixedHandler struct {
	//We do not want to have actions when performing requests so we just keep a materialized Handler
	serveHTTP func(w http.ResponseWriter, r *http.Request)
}


func (h *middlewarePrefixedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.serveHTTP(w, r)
}

//Create a handler for which requests are going through middleware components and only then end up with the handler
func NewMiddlewarePrefixedHandler(h http.Handler, prefixMws... Middleware) (*middlewarePrefixedHandler){
	var serveHTTP = h.ServeHTTP

	for i := len(prefixMws) -1 ; i >= 0 ; i--  {
		serveHTTP = prefixMws[i](serveHTTP)
	}

	return &middlewarePrefixedHandler{
		serveHTTP: serveHTTP,
	}
}