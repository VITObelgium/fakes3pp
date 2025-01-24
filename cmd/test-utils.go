package cmd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
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
func skipIfNoTestingBackends(t testing.TB) {
  if os.Getenv("NO_TESTING_BACKENDS") != "" {
    t.Skip("Skipping this test because no testing backends and that is a dependency for thist test.")
  }
}

//checkErrorTestDependency check for errors to pracitce safe programming but where you do not really
//expect problems (but cannot guarantee them not happening e.g. because of the execution environment).
//This is only to be used in test cases and will fail the test you can use msg to pass extra context info
func checkErrorTestDependency(err error, t *testing.T, msg ...string) {
	var strMsg string
	if len(msg) > 0 {
		strMsg = strings.Join(msg, ", ")
	}
	if err != nil {
		t.Errorf("Encountered error %s which should not occure. %s", err, strMsg)
		t.FailNow()
	}
}

type predicateFunction func() bool

//isTrueWithinDueTime takes a function that takes no arguments but returns a boolean
//and will await for maximum the first waitTime (which defaults to 5 seconds) and will
//check every second waitTime (defaults to 10 milliseconds)
func isTrueWithinDueTime(callable predicateFunction, waitTimes ...time.Duration) bool {
	var maxWaitTime time.Duration = 5 * time.Second
	var waitTimeBetweenChecks time.Duration = 10 * time.Millisecond

	if len(waitTimes) > 0 {
		maxWaitTime = waitTimes[0]
	}
	giveUpTime := time.Now().Add(maxWaitTime)

	if len(waitTimes) > 1 {
		waitTimeBetweenChecks = waitTimes[1]
	}
	
	for { //infinite loop
		if callable() {
			return true
		}
		if time.Now().After(giveUpTime) {
			return false  // time to give up
		}
		time.Sleep(waitTimeBetweenChecks)
	}

}