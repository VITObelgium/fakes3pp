package credentials

import (
	"errors"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/VITObelgium/fakes3pp/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type IDPClaims struct {
	//The optional session tags
	Tags session.AWSSessionTags `json:"https://aws.amazon.com/tags,omitempty"` 
	jwt.RegisteredClaims
}

func NewIDPClaims(issuer, subject string, expiry time.Duration, tags session.AWSSessionTags) (*IDPClaims) {
	return &IDPClaims{
		tags,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
			Issuer:    issuer,
			Subject:   subject,
			ID:        uuid.New().String(),
		},
	}

}

type SessionClaims struct {
	RoleARN string `json:"role_arn"`
	//The issuer of the initial OIDC refresh token
	IIssuer string `json:"initial_issuer"`
	IDPClaims

	AccessKeyID string `json:"access_key_id"`
}


//AWSSessionTokenClaims follow the jwt Claims interface but additionally
//allows to embed an AccessKeyId during signing
type AWSSessionTokenClaims interface {
	jwt.Claims

	SetAccessKeyId(akid string) ()
	GetAccessKeyId() string
}

func (s *SessionClaims) SetAccessKeyId(akid string) () {
	s.AccessKeyID = akid
}

func (s *SessionClaims) GetAccessKeyId() (string) {
	return s.AccessKeyID
}

func CreateRS256PolicyToken(issuer, iIssuer, subject, roleARN string, expiry time.Duration, tags session.AWSSessionTags) (*jwt.Token) {
	claims := &SessionClaims{
		roleARN,
		iIssuer,
		IDPClaims{
			tags,
			jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiry)),
				IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
				NotBefore: jwt.NewNumericDate(time.Now().UTC()),
				Issuer:    issuer,
				Subject:   subject,
				ID:        uuid.New().String(),
			},
		},
		"",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token
}

func CreateSignedToken(t *jwt.Token, keyStorage utils.PrivateKeyKeeper) (string, error) {
	signingKey, err := keyStorage.GetPrivateKey()
	if err != nil {
		return "", err
	}
	tokenStr, err := t.SignedString(signingKey)
	return tokenStr, err
}


// ExtractOIDCTokenClaims extracts JWT claims from a security token using the public key of the
// OIDC provider if the OIDC provider is registered key
func ExtractOIDCTokenClaims(token string, oidcKeyFunc jwt.Keyfunc) (*SessionClaims, error) {
	return ExtractTokenClaims(token, oidcKeyFunc)
}


// ExtractTokenClaims extracts JWT claims using a key functions
func ExtractTokenClaims(token string, keyFunc jwt.Keyfunc) (*SessionClaims, error) {
	if token == "" {
		return nil, errors.New("invalid argument")
	}

	policyClaims := SessionClaims{}

	var err error
	if keyFunc == nil {
		_, _, err = jwt.NewParser().ParseUnverified(token, &policyClaims)
	} else {
	    _, err = jwt.ParseWithClaims(token, &policyClaims, keyFunc)
	}
	if err != nil {
		return nil, err
	}

	return &policyClaims, nil
}