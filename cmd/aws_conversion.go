package cmd

import "time"

//Convert query parameter like X-Amz-Date=20240914T190903Z
func XAmzDateToTime(XAmzDate string) (time.Time, error) {
	return time.Parse(TimeFormat, XAmzDate)
}

func XAmzExpiryToTime(XAmzDate string, expirySeconds uint) (time.Time, error) {
	t, err := XAmzDateToTime(XAmzDate)
	return t.Add(time.Duration(expirySeconds) * time.Second), err
}