package middleware

import (
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthenticationOptions struct {
	//How long signatures can be expired before denying them
	Leeway time.Duration

	//Which query parameters should be removed for presigned urls
	//They will be removed prior to checking authentication
	RemovableQueryParams []*regexp.Regexp
}

func (a *AuthenticationOptions) GetParserOptions() []jwt.ParserOption {
	var options = make([]jwt.ParserOption, 0)
	options = append(options, jwt.WithLeeway(a.Leeway))
	return options
}
