package utils_test

import (
	"testing"

	"github.com/VITObelgium/fakes3pp/utils"
)


func TestCaptilizeFirstLetter(t *testing.T) {
	testCases := []struct {
        Description string
		input       string
		expected    string
	}{
		{
			"Starts with letter must capitalize",
			"hello world",
			"Hello world",
		},
		{
			"Starts with capital letter must noop",
			"Hello world",
			"Hello world",
		},
		{
			"Starts with digit must noop",
			"1hello world",
			"1hello world",
		},
		{
			"Starts with special character must noop",
			"{hello world}",
			"{hello world}",
		},
	}

	for _, tc := range testCases {
		result := utils.CapitalizeFirstLetter(tc.input)
		if result != tc.expected {
			t.Errorf("Got %s, expected %s", result, tc.expected)
		}
	}
}

