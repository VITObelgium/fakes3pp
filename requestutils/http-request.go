package requestutils

import (
	"fmt"
	"net/http"
)

//Given a request try to reconstruct the full URL for that request
//including protocol, hostname, path and query parameter names and values
func FullUrlFromRequest(req *http.Request) string {
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return fmt.Sprintf(
		"%s://%s%s?%s",
		scheme,
		req.Host,
		req.URL.Path,
		req.URL.RawQuery,
	)
}