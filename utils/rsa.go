package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	jwt "github.com/golang-jwt/jwt/v5"
)

func PrivateKeyFromPem(pemBytes []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(pemBytes)
    key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func PrivateKeyFromPemFile(filePath string) (*rsa.PrivateKey, error) {
	pemBytes, err := ReadFileFull(filePath)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromPem(pemBytes)
}

func PublicKeyFromPem(pemBytes []byte) (*rsa.PublicKey, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err == nil {
		pk, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("could build public key")
		}
		return pk, err
	} else {
		//Try other format
		pubKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
		return pubKey, err
	}
	
}

func PublickKeyFromPemFile(filePath string) (*rsa.PublicKey, error) {
	pemBytes, err := ReadFileFull(filePath)
	if err != nil {
		return nil, err
	}
	return PublicKeyFromPem(pemBytes)
}

type PrivateKeyKeeper interface {
	GetPrivateKey() (*rsa.PrivateKey, error)
}
type PublicKeyKeeper interface {
	GetPublicKey() (*rsa.PublicKey, error)
}

type KeyPairKeeper interface {
	PrivateKeyKeeper
	PublicKeyKeeper
	JWTVerifier
}

type JWTVerifier interface {
	GetJwtKeyFunc() (jwt.Keyfunc)
}

//This is just a very basic privateKeyStorage container which only contains a single
//keypair
type privateKeyStorage struct {
	privateKey *rsa.PrivateKey
}

func (s *privateKeyStorage) GetPrivateKey() (*rsa.PrivateKey, error) {
	return s.privateKey, nil 
}

func (s *privateKeyStorage) GetPublicKey() (*rsa.PublicKey, error) {
	return &s.privateKey.PublicKey, nil 
}


func (s *privateKeyStorage) GetJwtKeyFunc() (jwt.Keyfunc) {
	return func(t *jwt.Token) (interface{}, error) {
		//Give that there is only 1 keypair no real checking based on key info is to be done.
		return s.GetPublicKey()
	}
}

func NewKeyStorage(pathToPemEncodedPrivateKey string) (KeyPairKeeper, error) {
	key, err := PrivateKeyFromPemFile(pathToPemEncodedPrivateKey)
	if err != nil {
		return nil, err
	}
	return &privateKeyStorage{
		privateKey: key,
	}, nil
}

