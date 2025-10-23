package presign

import (
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"slices"
	"strings"

	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/usererror"
)

// Temporary remove headers and return callback to reinstantiate headers
func temporaryRemoveHeaders(r *http.Request, headersToKeep []string) (reAddHeaders func(*http.Request)) {
	headers := map[string]string{}

	for headerName := range r.Header {
		if slices.Contains(headersToKeep, headerName) {
			continue
		}
		headers[headerName] = r.Header.Get(headerName)
		r.Header.Del(headerName)
	}

	reAddHeaders = func(req *http.Request) {
		for headerName, headerVal := range headers {
			req.Header.Add(headerName, headerVal)
		}
	}

	return reAddHeaders
}

// Headers that are added by our middleware and which should never be filtered.
var alwaysSignHeaders = []string{
	"X-Amz-Content-Sha256",
	"Host",
	"Authorization", //Not really signed but during signing it gets replaced anyway
}

func TemporaryRemoveUntrustedHeaders(r *http.Request) (reAddHeaders func(*http.Request), err error) {
	signedHeaders, err := requestctx.GetSignedHeaders(r)
	if err != nil || len(signedHeaders) == 0 {
		signedHeaders, err = getSignedHeadersFromRequest(r)
		if err != nil {
			return nil, err
		}
		addSignedHeadersToRequestCtx(r, signedHeaders)
	}
	signedHeaders = append(signedHeaders, alwaysSignHeaders...)
	return temporaryRemoveHeaders(r, signedHeaders), nil
}

const signedHeadersPrefix = "SignedHeaders="

// Inspect a http.Request and return a slice with header names in their canonical form
// It handles requests with authorization headers as well as query parameters
func getSignedHeadersFromRequest(req *http.Request) (signedHeaders []string, err error) {
	signedHeaders = make([]string, 0)
	ah := req.Header.Get(constants.AuthorizationHeader)
	if ah == "" {
		queryVals := req.URL.Query()
		if queryVals.Has("Expires") && queryVals.Has("Signature") && queryVals.Has("AWSAccessKeyId") {
			//sigv1
			signedHeaders = append(signedHeaders, textproto.CanonicalMIMEHeaderKey("host"))
		} else {
			signedHeadersString := queryVals.Get("X-Amz-SignedHeaders")
			switch signedHeadersString {
			case "host", "Host":
				signedHeaders = append(signedHeaders, textproto.CanonicalMIMEHeaderKey(signedHeadersString))
			case "":
				return signedHeaders, errors.New("no authorization header nor X-Amz-SignedHeaders query value")
			default:
				return signedHeaders, usererror.New(
					fmt.Errorf("unsupported  X-Amz-SignedHeaders value: %s", signedHeadersString),
					"Unsupported query value this is an error from the s3 proxy",
				)
			}
		}
		return signedHeaders, nil

	}
	authorizationParts := strings.Split(ah, ",")
	if len(authorizationParts) != 3 {
		return signedHeaders, usererror.New(
			fmt.Errorf("signature not as expected; got: %s", ah),
			"Authorization header has invalid structure",
		)
	}
	signedHeadersPart := strings.TrimLeft(authorizationParts[1], " ")
	if !strings.HasPrefix(signedHeadersPart, signedHeadersPrefix) {
		return signedHeaders, usererror.New(
			fmt.Errorf("signature did not have expected signed headers prefix; got: %s", ah),
			"Authorization header has invalid structure",
		)
	}
	signedHeadersPart = signedHeadersPart[len(signedHeadersPrefix):]
	for _, signedHeader := range strings.Split(signedHeadersPart, ";") {
		signedHeaders = append(signedHeaders, textproto.CanonicalMIMEHeaderKey(signedHeader))
	}
	return signedHeaders, nil
}

func addSignedHeadersToRequestCtx(r *http.Request, signedHeaders []string) {
	requestctx.SetSignedHeaders(r, signedHeaders)
}
