package requestctx

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)


type RequestCtx struct{
	//A request ID which is used to correlate log entries to a request. Each request gets a random ID
	//which will be most likely a globally unique ID. The Requester could however chose a Request ID
	//in case they want to do multiple requests with a single ID (e.g. for troubleshooting).
	RequestID string
	// -> Request info (See S3 access log for inspiration)
}

type key int
var requestCtxKey key

func getRandomRequestId() string {
	return uuid.New().String()
}

const XRequestID string = "X-Request-ID"

func getRequestIdFromHttpRequest(req *http.Request) string {
	reqId := req.Header.Get(XRequestID)
	if reqId == "" {
		return getRandomRequestId()
	} else {
		return reqId
	}
}

func NewContextFromHttpRequest(req *http.Request) context.Context{
	rCtx := RequestCtx{
		RequestID: getRequestIdFromHttpRequest(req),
	}
	return NewContext(req.Context(), &rCtx)
}

func NewContext(ctx context.Context, rCtx *RequestCtx) context.Context{
	return context.WithValue(ctx, requestCtxKey, rCtx)
}

func FromContext(ctx context.Context) (*RequestCtx, bool) {
	rCtx, ok := ctx.Value(requestCtxKey).(*RequestCtx)
	return rCtx, ok
}

func GetRequestID(ctx context.Context) string {
	rCtx, ok := FromContext(ctx)
	if ok {
		return rCtx.RequestID
	}
	return ""
}