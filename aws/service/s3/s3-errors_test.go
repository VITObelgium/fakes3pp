package s3

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

const accessDeniedResponseTpl = `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>REQUESTID</RequestId><HostId></HostId></Error>`

func removeNewlines(s string) string {
	return strings.Replace(s, "\n", "", -1)
}

func TestS3Error(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "https://localhost:8443/noAccess", nil)
	if err != nil{
		t.Errorf("Could not build request for TestS3Error %s", err)
	}
	var testReqID = "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
	r.Header.Set(requestctx.XRequestID, testReqID)
	rr := httptest.NewRecorder()
	ctx := requestctx.NewContextFromHttpRequest(r)
	writeS3ErrorResponse(ctx, rr, ErrS3AccessDenied, nil)
	bodyBytes, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Errorf("Could not read response body %s", err)
	}
	expectedXML := removeNewlines(strings.Replace(accessDeniedResponseTpl, "REQUESTID", testReqID, 1))
	returnedString := removeNewlines(string(bodyBytes))
	if expectedXML != returnedString {
		t.Errorf("Did not get expected error:\n  %s\n<>\n  %s", expectedXML, returnedString)
	}
}