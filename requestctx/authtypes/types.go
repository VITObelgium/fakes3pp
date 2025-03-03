package authtypes

const L_AUTH_TYPE = "AuthType"

type AuthType int

//go:generate stringer -type=AuthType -trimprefix=AuthType $GOFILE

const (
	AuthTypeUnknown AuthType = iota
	AuthTypeNone
	AuthTypeQueryString
	AuthTypeAuthHeader
)
