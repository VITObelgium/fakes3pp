package s3

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"sigs.k8s.io/yaml"
)

type backendConfigFileEntry struct {
  RegionName string             `yaml:"region" json:"region"`
  Credentials map[string]any `yaml:"credentials" json:"credentials"`
  Endpoint string               `yaml:"endpoint" json:"endpoint"`
  Capabilities []string         `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}


type awsBackendCredentialFile struct {
	AccessKey    string                 `yaml:"aws_access_key_id" json:"aws_access_key_id"`
	SecretKey    string                 `yaml:"aws_secret_access_key" json:"aws_secret_access_key"`
	SessionToken string                 `yaml:"aws_session_token,omitempty" json:"aws_session_token,omitempty"`
}

func buildCredentialErrorf(msg string, a... any) (ccreds aws.Credentials, err error) {
	return aws.Credentials{}, fmt.Errorf(msg, a...)
}

//Try to get a string out of a map that has any values and return empty string if not a valid string
func lookupString(m map[string]any, key string) (string) {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

//The config file could host different types of credentials. Check cases 1 by one
//and fail if there was no valid type of credentials found
func (entry backendConfigFileEntry) getCredentials(relativepath string) (creds aws.Credentials, err error) {
	fileEntry, ok := entry.Credentials["file"]
	if ok {
		filePath, ok := fileEntry.(string)
		if !ok {
			return buildCredentialErrorf("When providing a credential file it must be a string, got %v", fileEntry)
		}
		// We are indeed a file 
		if !path.IsAbs(filePath) {
			filePath = path.Join(relativepath, filePath)
		}
		buf, err := os.ReadFile(filePath)
		if err != nil {
			return buildCredentialErrorf("could not read credentials file %s; %s", filePath, err)
		}

		c := &awsBackendCredentialFile{}
		err = yaml.Unmarshal(buf, c)
		if err != nil {
			return buildCredentialErrorf("error unmarshalling file %s; %s", filePath, err)
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
	inlineEntry, ok := entry.Credentials["inline"]
	if ok {
		//Credentials will be inline
		inlineMap, ok := inlineEntry.(map[string]any)
		if !ok {
			return buildCredentialErrorf("When providing inline credentials a map must be provided. %v", fileEntry)
		}
		accessKey := lookupString(inlineMap, "aws_access_key_id")
		if accessKey == "" {
			return buildCredentialErrorf("Must have a non empty access key")	
		}
		secretKey := lookupString(inlineMap, "aws_secret_access_key")
		if secretKey == "" {
			return buildCredentialErrorf("Must have a non empty secret key")	
		}
		sessionToken := lookupString(inlineMap, "aws_session_token")
		return aws.Credentials{
			AccessKeyID: accessKey,
			SecretAccessKey: secretKey,
			SessionToken: sessionToken,
		}, nil

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
	_, relativepath := utils.GetFilenameAndRelativePath(filename)
	return getBackendsConfigFromBytes(buf, legacyBehavior, relativepath)
}

//Process a backends configuration in bytes. Use the relativepath as a prefix for filepaths
func getBackendsConfigFromBytes(inputBytes []byte, legacyBehavior bool, relativepath string) (*backendsConfig, error) {
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
		err = backendCfg.fromBackendConfigFileEntry(backendRawCfg, relativepath)
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

	//A list of capabilities supported by the backend.
	//Check interfaces/backend-s3-capabilities for a definition of capabilities
	capabilities []interfaces.S3Capability
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

func (bce *backendConfigEntry) fromBackendConfigFileEntry(input backendConfigFileEntry, relativepath string) error {
	endpoint, err := buildEndpoint(input.Endpoint)
	if err != nil {
		return err
	}
	bce.endpoint = endpoint

	awsCredentials, err := input.getCredentials(relativepath)
	bce.credentials = awsCredentials
	bce.capabilities = make([]interfaces.S3Capability, 0)
	for _, capability := range input.Capabilities {
		typedCapability, exists := interfaces.S3CapabilityLookup[capability]
		if !exists {
			return fmt.Errorf("unknown capability: %s in config %v", capability, input)
		}
		bce.capabilities = append(bce.capabilities, typedCapability)
	}
	return err
}

type backendsConfig struct {
	backends map[string]backendConfigEntry
	defaultBackend string

	invalidRegionToDefaultRegion bool
}

var errInvalidBackendErr = errors.New("invalid BackendId")

func (cfg* backendsConfig) HasCapability(backendId string, capability interfaces.S3Capability) bool {
	backendCfg, err := cfg.getBackendConfig(backendId)
	if err == nil {
		return slices.Contains(backendCfg.capabilities, capability)
	} else {
		return false
	}
	
}

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