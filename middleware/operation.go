package middleware

import (
	"fmt"
	"net/http"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

//Register an operation into the requestctx such that it can be retrieved by the context
//
func RegisterOperation(operation fmt.Stringer) Middleware {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
			requestctx.SetOperation(r, operation)
			next.ServeHTTP(w, r)
        }
    }
}