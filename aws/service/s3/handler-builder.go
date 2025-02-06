package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/VITObelgium/fakes3pp/aws/service/s3/api"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/constants"
	"github.com/VITObelgium/fakes3pp/presign"
	"github.com/VITObelgium/fakes3pp/requestctx"
)

// A handler builder builds http handlers
type handlerBuilder struct {
	//How proxying is done to the backend
	proxyFunc func(context.Context, http.ResponseWriter, *http.Request, string, interfaces.BackendManager)
}

var justProxied interfaces.HandlerBuilderI = handlerBuilder{proxyFunc: justProxy}

func getS3Action(r *http.Request) (api.S3Operation) {
	action, actionOk := requestctx.GetOperation(r).(api.S3Operation)
	if !actionOk{
		slog.WarnContext(r.Context(), "Could not get operation for authorization")
		action = api.UnknownOperation
	}
	return action
}

func (hb handlerBuilder) Build(backendManager interfaces.BackendManager) (http.HandlerFunc) {
	if backendManager == nil {
		panic("This is a programming mistake and server should not even start.")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		targetRegion, err := requestctx.GetTargetRegion(r)
		if err != nil {
			writeS3ErrorResponse(ctx, w, ErrS3InternalError, errors.New("could not get target region from requestctx"))
			return
		}
		hb.proxyFunc(ctx, w, r, targetRegion, backendManager)
	}
}

func justProxy(ctx context.Context, w http.ResponseWriter, r *http.Request, targetBackendId string,  backendManager interfaces.BackendManager) {
	err := reTargetRequest(ctx, r, targetBackendId, backendManager)
	if err == errInvalidBackendErr {
		slog.WarnContext(ctx, "Invalid region was specified in the request", "error", err, "backendId", targetBackendId)
		writeS3ErrorResponse(ctx, w, ErrS3InvalidRegion, nil)
		return
	} else if err != nil {
		slog.ErrorContext(ctx, "Could not re-target request with permanent credentials", "error", err, "backendId", targetBackendId)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	creds, err := backendManager.GetBackendCredentials(targetBackendId)
	if err != nil {
		slog.ErrorContext(ctx, "Could not get credentials for request", "error", err, "backendId", targetBackendId)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	err = presign.SignWithCreds(ctx, r, creds, targetBackendId)
	if err != nil {
		slog.ErrorContext(ctx, "Could not sign request with permanent credentials", "error", err, "backendId", targetBackendId)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}

	client := &http.Client{}
	slog.DebugContext(ctx, "Going to perform request", "method", r.Method, "host", r.Host, "url", r.URL, "headers", r.Header)
	resp, err := client.Do(r)
	if err != nil {
		slog.ErrorContext(ctx, "Error making request", "error", err)
		return
	}
	defer resp.Body.Close()

	slog.DebugContext(ctx, "Response status", "status", resp.StatusCode)
	for hk, hvs := range resp.Header {
		for _, hv := range hvs {
			w.Header().Add(hk, hv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	i, err := io.Copy(w, resp.Body)
	if err != nil {
		slog.ErrorContext(ctx, "Context had error", "error", err, "context_error", ctx.Err())
	} else {
		slog.InfoContext(ctx, "End of proxying", "bytes", i, "error", err, "status", resp.Status, "headers", resp.Header)
	}
}

// Take a request that is signed but strip signature and point it to new target.
// Drop the old signature (Authorization header)
// Adapt Host to the new target
// We also have to clear RequestURI and set URL appropriately as explained in
// https://stackoverflow.com/questions/19595860/http-request-requesturi-field-when-making-request-in-go
func reTargetRequest(ctx context.Context, r *http.Request, backendId string, backendResolver interfaces.BackendLocator) (error) {
	// Old signature
	r.Header.Del("Authorization")
	// Old session token
	r.Header.Del(constants.AmzSecurityTokenKey)
	r.Header.Del("Host")
	endpoint, err := backendResolver.GetBackendEndpoint(backendId)
	if err != nil {
		return err
	}
	r.Header.Add("Host", endpoint.GetHost())
	r.Host = endpoint.GetHost()
	origRawQuery := r.URL.RawQuery
	slog.DebugContext(ctx, "Stored orig RawQuery", "raw_query", origRawQuery)

	u, err := url.Parse(fmt.Sprintf("%s%s", endpoint.GetBaseURI(), r.RequestURI))
    if err != nil {
        return err
    }
	r.RequestURI = ""
	r.RemoteAddr = ""
    r.URL = u

	r.URL.RawQuery = origRawQuery
	slog.DebugContext(ctx, "RawQuery that is put in place", "raw_query", r.URL.RawQuery)
	return nil
}