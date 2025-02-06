package s3

import (
	"encoding/json"
	"fmt"
	"testing"
)

var testBucketName = "bucket1"
var testBucketARN = fmt.Sprintf("arn:aws:s3:::%s", testBucketName)

func printPointerAndJSONStringComparison(t *testing.T, description string, expected, got any) {
	//Different amount of actions returned so should be rather obvious
	expectedStr, err := json.Marshal(expected)
	if err != nil {
		t.Errorf("%s: expected %#v, got %#v", description, expected, got)
	}
	gotStr, err := json.Marshal(got)
	if err != nil {
		t.Errorf("%s: expected %#v, got %#v", description, expected, got)
	}
	t.Errorf("%s:\n\t+expected\n\t-got\n\n\t+%s\n\t-%s\n\n\t+%#v\n\t-%#v", description, string(expectedStr), string(gotStr), expected, got)
}
