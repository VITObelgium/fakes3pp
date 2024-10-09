package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	pemBytes, err := readFileFull(filePath)
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
	pemBytes, err := readFileFull(filePath)
	if err != nil {
		return nil, err
	}
	return PublicKeyFromPem(pemBytes)
}