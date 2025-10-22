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
	"sec-fetch-user": true,
	"priority": true,
	"te": true,
	"accept": true,
	"upgrade-insecure-requests": true,
	"sec-fetch-dest": true,
	"sec-fetch-mode": true,
	"sec-fetch-Site": true,
	"accept-language": true,
}

//It is not always clear which headers are OK to skip cleaning. These headers
//have been skipped without issues.
//Each entry should be lower case. The value is not used.
var okToSkipHeadersForCleaning = map[string]bool {
	"user-agent": true,
	"authorization": true,
	"expect": true,
}

func isCleanable(headerName string) bool {
	value, ok := cleanableHeaders[strings.ToLower(headerName)]
	if ok && value {
		return true
	}
	return false
}

type CleanerOptions struct{
	//If set we do not check against a list of headers that is safe to clean
	//We just clean all that are not explicitly set to keep
	AlwaysClean bool
}

//
func CleanHeadersTo(ctx context.Context, req *http.Request, toKeep map[string]string, opts CleanerOptions) {
	var cleaned = []string{}
	var skipped = []string{}
	var signed = []string{}
	var riskySkips = 0

	allHeadersInRequest := []string{}
	for hearderName := range req.Header {
		allHeadersInRequest = append(allHeadersInRequest, hearderName)
	}

	for _, header := range allHeadersInRequest {
		headerLC := strings.ToLower(header)
		_, ok := toKeep[headerLC]
		if ok {
			signed = append(signed, header)
			continue
		}
		if isCleanable(header) || opts.AlwaysClean {
			//If content-length is to be cleaned it should
			//also be <=0 otherwise it is taken in the signature
			//-1 means unknown so let's fall back to that
			if headerLC == "content-length" {
				slog.DebugContext(
					req.Context(),
					"Cleaning Content-Length",
					"header", req.Header.Get(header),
					"reqValue", req.ContentLength,
				)
				req.ContentLength = -1
			}
			req.Header.Del(header)
			cleaned = append(cleaned, header)
		} else {
			_, ok := okToSkipHeadersForCleaning[headerLC]
			if !ok {
				riskySkips += 1
			}
			skipped = append(skipped, header)
		}
	}
	if riskySkips > 0 {
		slog.WarnContext(ctx, "Cleaning of headers done but some where skipped.", "cleaned", cleaned, "skipped", skipped, "toKeep", signed)
	}
}
