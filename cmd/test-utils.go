package cmd

import (
	"encoding/json"
	"os"
	"testing"
)


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


//utility function to not run a test if there are no testing backends in the build environment.
func skipIfNoTestingBackends(t *testing.T) {
  if os.Getenv("NO_TESTING_BACKENDS") != "" {
    t.Skip("Skipping this test because no testing backends and that is a dependency for thist test.")
  }
}