package s3

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/aws/aws-sdk-go-v2/aws"
	"sigs.k8s.io/yaml"
)

type backendConfigFileEntry struct {
  RegionName string             `yaml:"region" json:"region"`
  Credentials map[string]string `yaml:"credentials" json:"credentials"`
  Endpoint string               `yaml:"endpoint" json:"endpoint"`
}


type awsBackendCredentialFile struct {
	AccessKey    string                 `yaml:"aws_access_key_id" json:"aws_access_key_id"`
	SecretKey    string                 `yaml:"aws_secret_access_key" json:"aws_secret_access_key"`
	SessionToken string                 `yaml:"aws_session_token,omitempty" json:"aws_session_token,omitempty"`
}

//The config file could host different types of credentials. Check cases 1 by one
//and fail if there was no valid type of credentials found
func (entry backendConfigFileEntry) getCredentials() (creds aws.Credentials, err error) {
	filePath, ok := entry.Credentials["file"]
	if ok {
		// We are indeed a file 
		buf, err := os.ReadFile(filePath)
		if err != nil {
			return creds, fmt.Errorf("could not read credentials file %s; %s", filePath, err)
		}

		c := &awsBackendCredentialFile{}
		err = yaml.Unmarshal(buf, c)
		if err != nil {
			return creds, fmt.Errorf("error unmarshalling file %s; %s", filePath, err)
		}
		if c.AccessKey == "" {
			return creds, errors.New("invalid credentials file, missing access key")
		}
		creds.AccessKeyID = c.AccessKey
		if c.SecretKey == "" {
			return creds, errors.New("invalid credentials file, missing secret key")
		}
		creds.SecretAccessKey = c.SecretKey
		if c.SessionToken != "" {
			creds.SessionToken = c.SessionToken
			creds.CanExpire = true
		}
		return creds, nil
	}
	return creds, errors.New("unable to find a valid type of credentials")
}

type backendsConfigFile struct {
	Backends []backendConfigFileEntry `yaml:"s3backends" json:"s3backends"`
	Default string                    `yaml:"default" json:"default"`
}

//TODO: legacyBehavior
func getBackendsConfig(filename string, legacyBehavior bool) (*backendsConfig, error) {
	buf, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return getBackendsConfigFromBytes(buf, legacyBehavior)
}

//TODO: legacyBehavior
func getBackendsConfigFromBytes(inputBytes []byte, legacyBehavior bool) (*backendsConfig, error) {
	c := &backendsConfigFile{}
	err := yaml.Unmarshal(inputBytes, c)
	if err != nil {
		return nil, err
	}

	result := backendsConfig{
		backends: map[string]backendConfigEntry{},
	}

	for _, backendRawCfg := range c.Backends {
		backendCfg := backendConfigEntry{}
		err = backendCfg.fromBackendConfigFileEntry(backendRawCfg)
		if err != nil {
			return nil, fmt.Errorf("invalid config %v resulted in %s", backendRawCfg, err)
		}
		result.backends[backendRawCfg.RegionName] = backendCfg
	}

	defaultBackend := c.Default
	_, defaultExists := result.backends[defaultBackend]
	if !defaultExists {
		return nil, fmt.Errorf("default backend %s does not exist", defaultBackend)
	}
	result.defaultBackend = defaultBackend
	result.invalidRegionToDefaultRegion = legacyBehavior
	
	return &result, err
}

type backendConfigEntry struct {
	credentials aws.Credentials
	endpoint endpoint
}

//A dedicated type for endpoint allows to have the semantics of endpoints of the config.
//When creating these endpoints we do certain checks so by typing them we can assume these
//checks had passed whenever we encounter an endpoint later on
type endpoint string

func buildEndpoint(uri string) (endpoint, error) {
	if !strings.HasPrefix(uri, "https://") && !strings.HasPrefix(uri, "http://") {
		return "", errors.New("endpoint URIs must start with https:// or http://")
	}
	return endpoint(uri), nil
}

//This method is to get rid of the protocol from the endpoint specification
func (e endpoint) GetHost() string {
	uriString := string(e)
	return strings.Split(uriString, "://")[1]
}

//The endpoint base URI is of form protocol://hostname and can be used to identify the backend
//service
func (e endpoint) GetBaseURI() string {
	return string(e)
}

func (bce *backendConfigEntry) fromBackendConfigFileEntry(input backendConfigFileEntry) error {
	endpoint, err := buildEndpoint(input.Endpoint)
	if err != nil {
		return err
	}
	bce.endpoint = endpoint

	awsCredentials, err := input.getCredentials()
	bce.credentials = awsCredentials
	return err
}

type backendsConfig struct {
	backends map[string]backendConfigEntry
	defaultBackend string

	invalidRegionToDefaultRegion bool
}

var errInvalidBackendErr = errors.New("invalid BackendId")

func (cfg* backendsConfig) getBackendConfig(backendId string) (cfgEntry backendConfigEntry, err error) {
	if cfg == nil {
		return cfgEntry, errors.New("backendsConfig not initialised")
	}
	if backendId == "" {
		backendId = cfg.defaultBackend
	}
	backendCfg, ok := cfg.backends[backendId]
	if ok {
		return backendCfg, nil
	} else {
		if cfg.invalidRegionToDefaultRegion && backendId != cfg.defaultBackend{
			return cfg.getBackendConfig(cfg.defaultBackend)
		} else {
			return cfgEntry, errInvalidBackendErr
		}
	}
}

//Get the server credentials for a specific backend identified by its identifier
//At this time we use the region name and we do support the empty string in case the region
//cannot be determined and the default backend should be used.
func (cfg *backendsConfig) GetBackendCredentials(backendId string) (creds aws.Credentials, err error) {
	backendCfg, err := cfg.getBackendConfig(backendId)
	if err != nil {
		return creds, err
	}
	creds = backendCfg.credentials
	return
}

func GetBackendCredentials(cfgFilePath, backendId string) (creds aws.Credentials, err error) {
	cfg, err := getBackendsConfig(cfgFilePath, true)
	if err != nil {
		return aws.Credentials{}, err
	}
	return cfg.GetBackendCredentials(backendId)
}



//Get endpoint for a backend. The endpoint contains the protocol and the hostname
//to arrive at the backend.
func (cfg *backendsConfig) GetBackendEndpoint(backendId string) (interfaces.Endpoint, error) {
	backendCfg, err := cfg.getBackendConfig(backendId)
	if err != nil {
		return nil, err
	}
	return backendCfg.endpoint, nil
}

func (cfg *backendsConfig) GetDefaultBackend() (string) {
	return cfg.defaultBackend
}