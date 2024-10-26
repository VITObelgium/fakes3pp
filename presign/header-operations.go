package presign

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
)


var cleanableHeaders = map[string]bool{
	"accept-encoding": true,
	"x-forwarded-for": true,
	"x-forwarded-host": true,
	"x-forwarded-port": true,
	"x-forwarded-proto": true,
	"x-forwarded-server": true,
	"x-real-ip": true,
	"amz-sdk-invocation-id": true, //Added by AWS SDKs after signing
	"amz-sdk-request": true, //Added by AWS SDKs after signing
	"content-length": true,
}

func isCleanable(headerName string) bool {
	value, ok := cleanableHeaders[strings.ToLower(headerName)]
	if ok && value {
		return true
	}
	return false
}

func CleanHeadersTo(ctx context.Context, req *http.Request, toKeep map[string]string) {
	var cleaned = []string{}
	var skipped = []string{}
	var signed = []string{}

	allHeadersInRequest := []string{}
	for hearderName := range req.Header {
		allHeadersInRequest = append(allHeadersInRequest, hearderName)
	}

	for _, header := range allHeadersInRequest {
		_, ok := toKeep[strings.ToLower(header)]
		if ok {
			signed = append(signed, header)
			continue
		}
		if isCleanable(header) {
			//If content-length is to be cleaned it should
			//also be <=0 otherwise it is taken in the signature
			//-1 means unknown so let's fall back to that
			if strings.ToLower(header) == "content-length" {
				req.ContentLength = -1
			}
			req.Header.Del(header)
			cleaned = append(cleaned, header)
		} else {
			skipped = append(skipped, header)
		}
	}
	if len(skipped) > 0 {
		slog.Warn("Cleaning of headers done", "cleaned", cleaned, "skipped", skipped, "toKeep", signed)
	}
}
