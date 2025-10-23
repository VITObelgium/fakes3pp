package iam

import (
	"strings"
	"testing"
	"time"
)

type predicateFunction func() bool

//isTrueWithinDueTime takes a function that takes no arguments but returns a boolean
//and will await for maximum the first waitTime (which defaults to 5 seconds) and will
//check every second waitTime (defaults to 10 milliseconds)
func isTrueWithinDueTime(callable predicateFunction, waitTimes ...time.Duration) bool {
	var maxWaitTime = 5 * time.Second
	var waitTimeBetweenChecks = 10 * time.Millisecond

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