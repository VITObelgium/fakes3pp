package middleware

import "net/http"

type Middleware func(http.HandlerFunc) http.HandlerFunc

//Chain middlewares
func Chain(h http.HandlerFunc, mws... Middleware) http.HandlerFunc{
	if len(mws) == 0 {
		return h
	}
	for i := len(mws) -1 ; i >= 0 ; i--  {
		h = mws[i](h)
	}

	return h
}