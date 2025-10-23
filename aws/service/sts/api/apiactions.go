package api

type STSOperation int

//go:generate stringer -type=STSOperation $GOFILE
const (
	UnknownOperation STSOperation = iota
	AssumeRoleWithWebIdentity
)
