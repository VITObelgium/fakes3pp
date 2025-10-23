package iam

import "time"

func YYYYmmdd(t time.Time) string {
	return t.Format("20060102")
}

func YYYYmmddSlashed(t time.Time) string {
	return t.Format("2006/01/02")
}

func Now() time.Time {
	return time.Now()
}

func Add1Day(t time.Time) time.Time {
	return t.Add(time.Hour * time.Duration(24))
}
