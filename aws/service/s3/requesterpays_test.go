package s3

import "testing"

func TestRequesterPaysBucketsFromBytes(t *testing.T) {
	buckets, err := getRequesterPaysBucketsFromBytes([]byte("- bucket1\n- bucket2\n"))
	if err != nil {
		t.Fatalf("Could not parse requester pays config: %s", err)
	}
	if !buckets.shouldForce("bucket1") {
		t.Fatal("Expected bucket1 to be configured")
	}
	if !buckets.shouldForce("bucket2") {
		t.Fatal("Expected bucket2 to be configured")
	}
	if buckets.shouldForce("bucket3") {
		t.Fatal("Did not expect bucket3 to be configured")
	}
}

func TestRequesterPaysBucketsFromBytesInvalidYaml(t *testing.T) {
	_, err := getRequesterPaysBucketsFromBytes([]byte("buckets: [unterminated"))
	if err == nil {
		t.Fatal("Expected invalid requester pays config to fail")
	}
}
