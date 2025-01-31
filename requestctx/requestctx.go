package requestctx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type LogAttrs []slog.Attr


type RequestCtx struct{
	//A request ID which is used to correlate log entries to a request. Each request gets a random ID
	//which will be most likely a globally unique ID. The Requester could however chose a Request ID
	//in case they want to do multiple requests with a single ID (e.g. for troubleshooting).
	RequestID string
	
	//Request information available at the start
    //  - Time "The time at which the request was received; these dates and times are in Coordinated Universal Time (UTC). The format, using strftime() terminology, is as follows: [%d/%b/%Y:%H:%M:%S %z]"
    Time      time.Time
	
	//  - Remote IP "The apparent IP address of the requester. Intermediate proxies and firewalls might obscure the actual IP address of the machine that's making the request."
    RemoteIP  string
	
    //  - Request-URI: The Request-URI part of the HTTP request message
	RequestURI string

	//  - Referer: The value of the HTTP Referer header, if present. HTTP user-agents (for example, browsers) typically set this header to the URL of the linking or embedding page when making a request.
    Referer    string

	//  - User-Agent: The value of the HTTP User-Agent header.
    UserAgent  string

	//  - Host Header
	Host       string

	//  - HTTP Status: The numeric HTTP status code of the response
	HTTPStatus int

	//  - Bytes Sent: The number of response bytes sent, excluding HTTP protocol overhead, or - if zero.
	BytesSent  uint64
	
	//  - Bytes Received: The number of request bytes received excluding HTTP protocol overhead, or - if zero.
	BytesReceived  uint64

	//Miscelaneous info for logging these are grouped and can contain all kind of info for example:
	// -> Request info (See S3 access log for inspiration)
	//  - Target "The backend used by the proxy"
    //  - Bucket "The name of the bucket that the request was processed against."
    //  - Key: The Key (object name) part of the request (-) if none
    //  - Operation: the type of action that was performed
    //  - Error Code: The S3 Error response or - if no error occured
	//  - Requester: The ARN used by the requester (e.g. role ARN)
	//  - Authentication Type: AuthHeader for authentication headers, QueryString for query string (presigned URL), or a -
	accessLogAttrs map [string]LogAttrs

	//miscData to track data that is set by certain middleware and consumed by
	//other middleware.
	data map[string]any

	//The API operation
	Operation fmt.Stringer
}

func (c *RequestCtx)AddAccessLogInfo(groupName string, attrs... slog.Attr) {
	existing_group, ok := c.accessLogAttrs[groupName]
	if !ok {
		existing_group = []slog.Attr{}
	}
	c.accessLogAttrs[groupName] = append(existing_group, attrs...)
}

func SetOperation(r *http.Request, operation fmt.Stringer) {
	if rCtx := get(r); rCtx != nil {
		rCtx.Operation = operation
		return		
	}
	slog.Error(
		"Attempting to set operation without existing request context",
		"request", r,
		"operation", operation.String(),
	)
}

func GetOperation(r *http.Request) fmt.Stringer{
	if rCtx := get(r); rCtx != nil {
		return rCtx.Operation
	}
	return nil
}

func get(r *http.Request) *RequestCtx {
	rCtx, ok := FromContext(r.Context())
	if !ok {
		return nil
	}
	return rCtx
}

//Add information for access log for an HTTP request.
//This request expects that a requestCtx was already created and is part of
//the context of the HTTP request
func AddAccessLogInfo(r *http.Request, groupName string, attrs... slog.Attr) {
	if rCtx := get(r); rCtx != nil {
		rCtx.AddAccessLogInfo(groupName, attrs...)
		return		
	}
	slog.Error(
		"Attempting to add access log info without request context",
		"group_name", groupName,
		"attributes", attrs,
		"request", r,
	)
}

func (c *RequestCtx)GetAccessLogInfo() (LogAttrs) {
	additionalLogInfo := []slog.Attr{}
	for groupName, groupAttrs := range c.accessLogAttrs {
		additionalLogInfo = append(
			additionalLogInfo, 
			slog.Attr{
				Key: groupName, 
				Value: slog.GroupValue(groupAttrs...)},
		)
	}
	return additionalLogInfo
}

func (c *RequestCtx)SetDataKey(key string, value any) {
	c.data[key] = value
}

var ErrNoSuchKey = errors.New("no such key")
var ErrInvalidType = errors.New("invalid type for key")

func (c *RequestCtx)GetStringData(key string) (string, error){
	v, ok := c.data[key]
	if !ok {
		return "", ErrNoSuchKey
	}
	s, ok := v.(string)
	if !ok {
		return "", ErrInvalidType
	}
	return s, nil
}

type key int
var requestCtxKey key

func getRandomRequestId() string {
	return uuid.New().String()
}

const XRequestID string = "X-Request-ID"

//A heuristic to cheaply check whether a structure is UUID4-like
//version info is not checked as the goal is mostly to have consistent
//logging format and lengths
func hasUUID4Format(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[23] != '-' {
		return false
	}
	return true
}

//Get the RequestId for a request. If none is provided a Unique uuid4
//will be generated and provided lower case. If the request provided
//it via the X-Request-ID 
func getRequestIdFromHttpRequest(req *http.Request) string {
	reqId := req.Header.Get(XRequestID)
	if reqId == "" || ! hasUUID4Format(reqId) {
		return getRandomRequestId()  //This is a lower case string
	} else {
		return strings.ToUpper(reqId) //We force this to be upper case
	}
}

func NewContextFromHttpRequest(req *http.Request) context.Context{
	return NewContextFromHttpRequestWithStartTime(req, time.Now())
}

func NewContextFromHttpRequestWithStartTime(req *http.Request, reqStartTime time.Time) context.Context{
	rCtx := RequestCtx{
		RequestID: getRequestIdFromHttpRequest(req),
		Time: reqStartTime,
		RemoteIP: req.RemoteAddr,
		RequestURI: req.RequestURI,
		Referer: req.Referer(),
		UserAgent: req.UserAgent(),
		Host: req.Host,
		accessLogAttrs: map[string]LogAttrs{},
		data: map[string]any{},
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