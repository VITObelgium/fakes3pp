package requestctx_test

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

func TestGetAccessLogStringInfo(t *testing.T) {
	//Given a new requestObject without context
	r, err := http.NewRequest(http.MethodGet, "http://www.google.be", strings.NewReader(""))
	if err != nil {
		t.Errorf("Could not create test request: %s", err)
		t.FailNow()
	}
	//When getting an entry we expect the empty string
	retrievedStr := requestctx.GetAccessLogStringInfo(r, "s3", "Bucket")
	expectedStr := ""

	//Then we should get an empty string since it did not exist
	if retrievedStr != expectedStr {
		t.Errorf("Expected '%s', got '%s'", expectedStr, retrievedStr)
		t.FailNow()
	}
}

func TestGetAccessLogStringInfoWhenSet(t *testing.T) {
	//Given a new requestObject with context
	r, err := http.NewRequest(http.MethodGet, "http://www.google.be", strings.NewReader(""))
	if err != nil {
		t.Errorf("Could not create test request: %s", err)
		t.FailNow()
	}
	testGroup := "s3"
	testKey := "myKey"
	testValue := "MyTestValue"
	ctx := requestctx.NewContextFromHttpRequestWithStartTime(r, time.Now())
	r = r.WithContext(ctx)
	rCtx, ok := requestctx.FromContext(ctx)
	if !ok {
		t.Errorf("Should never happen but could not get context after setting")
		t.FailNow()
	}
	rCtx.AddAccessLogInfo(testGroup, slog.String(testKey, testValue))

	//When getting an entry we expect the string that was set previously
	retrievedStr := requestctx.GetAccessLogStringInfo(r, testGroup, testKey)
	expectedStr := testValue

	//Then we should get the expected value
	if retrievedStr != expectedStr {
		t.Errorf("Expected '%s', got '%s'", expectedStr, retrievedStr)
		t.FailNow()
	}

	//Then a non-existent string should still return an empty value
	retrievedStr2 := requestctx.GetAccessLogStringInfo(r, "s3", "Bucket")
	expectedStr2 := ""

	if retrievedStr2 != expectedStr2 {
		t.Errorf("Expected '%s', got '%s'", expectedStr, retrievedStr)
		t.FailNow()
	}
}
