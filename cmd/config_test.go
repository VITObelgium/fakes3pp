package cmd

import (
	"testing"
	"time"
)

func TestGetMaxSTSDuration(t *testing.T) {
	//Given no user defined config
	maxDur := getMaxStsDuration()

	if maxDur != time.Hour*12 {
		t.Error("Max default duration should have been half a day")
	}
}
