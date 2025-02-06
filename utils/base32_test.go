package utils_test

import (
	"testing"

	"github.com/VITObelgium/fakes3pp/utils"
)


func TestB32Symmetry(t *testing.T) {
	testString := "Just for testing"
	calculated, err := utils.B32Decode(utils.B32(testString))
	if err != nil {
		t.Error(err)
	}
	if testString != calculated {
		t.Errorf("Expected %s, got %s", testString, calculated)
	}
}