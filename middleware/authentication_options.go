package middleware

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)


type AuthenticationOptions struct {
	//How long signatures can be expired before denying them
	Leeway time.Duration
}

func (a *AuthenticationOptions) GetParserOptions() ([]jwt.ParserOption) {
	var options = make([]jwt.ParserOption, 0)
	options = append(options, jwt.WithLeeway(a.Leeway))
	return options
}
