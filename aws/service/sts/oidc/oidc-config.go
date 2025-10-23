package oidc

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/VITObelgium/fakes3pp/utils"
	jwt "github.com/golang-jwt/jwt/v5"
	"sigs.k8s.io/yaml"
)

type OIDCVerifier interface {
	//
	GetKeyFunc() jwt.Keyfunc
}

func NewOIDCVerifierFromConfigFile(cfgFile string) (OIDCVerifier, error) {
	return loadOidcConfigFile(cfgFile)
}

type oidcProviderConfig struct {
	Realm           string `json:"realm" yaml:"realm"`
	PublicKey       string `json:"public_key" yaml:"public_key"`
	TokenService    string `json:"token-service" yaml:"token-service"`
	AccountService  string `json:"account-service" yaml:"account-service"`
	TokensNotBefore int    `json:"tokens-not-before" yaml:"tokens-not-before"`
	// issuer url will be used to load other fields if not all required info is there
	Iss string `json:"iss" yaml:"iss"`
}

func (c *oidcProviderConfig) getPublicKey() (*rsa.PublicKey, error) {
	pemKey := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", c.PublicKey)
	return utils.PublicKeyFromPem([]byte(pemKey))
}

type oidcConfig struct {
	Providers map[string]*oidcProviderConfig `yaml:"providers"`
	//Issuers to provider names
	Issuers map[string]string
}

func (c *oidcConfig) getProviderNames() []string {
	providerNames := []string{}
	for providerName := range c.Providers {
		providerNames = append(providerNames, providerName)
	}
	return providerNames
}

func (c *oidcConfig) String() string {
	bytes, err := yaml.Marshal(c)
	if err != nil {
		return "Failed marshalling OIDConfig"
	}
	return string(bytes)
}

func loadOidcConfigFile(configFile string) (*oidcConfig, error) {
	configBytes, err := utils.ReadFileFull(configFile)
	if err != nil {
		return nil, err
	}
	slog.Info("Read OIDC fonfig", "content", string(configBytes))
	oidcConfig, err := loadOidcConfig(configBytes)
	if err != nil {
		return nil, err
	}
	return oidcConfig, nil
}

func loadOidcConfig(inCfg []byte) (*oidcConfig, error) {
	var cfg oidcConfig
	err := yaml.Unmarshal(inCfg, &cfg)
	if err != nil {
		slog.Error("Could not unmarshal OIDC config", "error", err)
		return nil, err
	}
	slog.Info("OIDC config unmarshalled", "config", cfg)
	slog.Debug("Process config")
	cfg.Issuers = map[string]string{}

	for _, providerName := range cfg.getProviderNames() {
		slog.Info("Loading OIDC provider config", "provider", providerName)
		providerCfg := cfg.Providers[providerName]
		if providerCfg.PublicKey == "" {
			slog.Info("Missing required info for provider", "provider", providerName)
			if providerCfg.Iss == "" {
				return nil, fmt.Errorf("not all required info available and no iss url invalid OIDC config for %s", providerName)
			}
			issCfg, err := getOidcProviderConfigFromIss(providerCfg.Iss)
			if err != nil {
				return nil, err
			}
			issCfg.Iss = providerCfg.Iss
			cfg.Providers[providerName] = issCfg
		}
		_, err := cfg.Providers[providerName].getPublicKey()
		if err != nil {
			slog.Error("Could not get public key for", "issuer", providerCfg.Iss, "error", err)
			panic("Let's not run when we know we cannot do our tasks")
		}
		cfg.Issuers[providerCfg.Iss] = providerName
	}
	slog.Info("Finished loading OIDC config", "config", cfg)
	return &cfg, nil
}

func (cfg *oidcConfig) GetKeyFunc() jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		issuer, err := t.Claims.GetIssuer()
		if err != nil {
			return nil, fmt.Errorf("could not get Issuer from token: %s", err)
		}
		providerName, ok := cfg.Issuers[issuer]
		if ok {
			issuerConfig, ok := cfg.Providers[providerName]
			if !ok {
				slog.Warn("No such OIDC provider", "providerName", providerName)
			} else {
				return issuerConfig.getPublicKey()
			}
		}
		issuerConfig, ok := cfg.Providers[issuer]
		if !ok {
			return nil, fmt.Errorf("could not find issuer: %s", issuer)
		}
		publicKey, err := issuerConfig.getPublicKey()
		if err != nil {
			return nil, fmt.Errorf("could not find public key config for issuer: %s", issuer)
		}
		return publicKey, nil
	}
}

func getOidcProviderConfigFromIss(iss string) (*oidcProviderConfig, error) {
	resp, err := http.Get(iss) // #nosec G107 -- variable url but under platform control
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		slog.Error("Not OK for getting iss", " statusCode", resp.StatusCode)
		return nil, errors.New("unsupported statuscode")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var p oidcProviderConfig
	err = json.Unmarshal(body, &p)
	return &p, err
}
