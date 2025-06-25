package requestutils

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
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

func CompareRequestWithUrl(req *http.Request, inputUrl string) (isSameScheme, isSameHost, isSamePath, isSameQuery bool, err error) {
	u, err := url.Parse(inputUrl)
    if err != nil {
        return
    }
	isSameScheme = u.Scheme == req.URL.Scheme
	isSameHost = u.Host == req.URL.Host
	isSamePath = u.Path == req.URL.Path
	isSameQuery = IsSameQuery(req.Context(), u.Query(), req.URL.Query())
	return
}

func IsSameQuery(ctx context.Context, qVals1 url.Values, qVals2 url.Values) bool {
	if len(qVals1) != len(qVals2) {
		slog.DebugContext(ctx, "Not the same query size mismatch", "vals1", qVals1, "vals2", qVals2)
		return false
	}
	for valKey1, valVals1 := range qVals1 {
		valVals2, exists := qVals2[valKey1]
		if !exists {
			slog.DebugContext(ctx, "Not the same query, key only found in firstVals", "key", valKey1, "vals1", qVals1, "vals2", qVals2)
			return false
		}
		if len(valVals1) != len(valVals2) {
			slog.DebugContext(ctx, "Not the same query, key with different amount of values", "key", valKey1, "valuess1", valVals1, "values2", valVals2)
			return false
		}
		for _, v := range valVals1 {
			if !slices.Contains(valVals2, v) {
				slog.DebugContext(ctx, "Not the same query, key with different value", "key", valKey1, "value", v, "valuess1", valVals1, "values2", valVals2)
				return false
			}
		}
	}
	return true
}