package testutils

import (
	"os"
	"testing"
)

// utility function to avoid slowing down all unittest runs
func SkipIfNoSlowUnittests(t testing.TB) {
	//HASTE AND SPEED IS RARELY GOOD is too Flenglish:-)
	if os.Getenv("HASTE_MAKES_WASTE") == "" {
		t.Skip("Skipping this test because no we are in a hurry.")
	}
}
