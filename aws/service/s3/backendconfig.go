package s3

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	s3ifaces "github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/micahhausler/aws-iam-policy/policy"
	"sigs.k8s.io/yaml"
)

// ConditionKey for the AKID of the incoming request
const ConditionKeyRequestAccessKeyId = "fakes3pp:RequestAccessKeyId"

// ---- raw YAML/JSON shapes for the config file ----

type backendConfigFileEntry struct {
	RegionName   string         `yaml:"region" json:"region"`
	Credentials  map[string]any `yaml:"credentials" json:"credentials"`
	Endpoint     string         `yaml:"endpoint" json:"endpoint"`
	Capabilities []string       `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

type awsBackendCredentialFile struct {
	AccessKey    string `yaml:"aws_access_key_id" json:"aws_access_key_id"`                     // #nosec G117 -- intentional deserialization field for AWS-compatible backend credentials
	SecretKey    string `yaml:"aws_secret_access_key" json:"aws_secret_access_key"`             // #nosec G117 -- intentional deserialization field for AWS-compatible backend credentials
	SessionToken string `yaml:"aws_session_token,omitempty" json:"aws_session_token,omitempty"` // #nosec G117 -- intentional deserialization field for AWS-compatible backend credentials
}

// credentialRuleFileEntry is the raw config shape for a single credential rule inside credentials.rules
type credentialRuleFileEntry struct {
	Name   string                    `yaml:"name" json:"name"`
	When   map[string]map[string]any `yaml:"when,omitempty" json:"when,omitempty"`
	File   string                    `yaml:"file,omitempty" json:"file,omitempty"`
	Inline map[string]string         `yaml:"inline,omitempty" json:"inline,omitempty"`
}

func buildCredentialErrorf(msg string, a ...any) (ccreds aws.Credentials, err error) {
	return aws.Credentials{}, fmt.Errorf(msg, a...)
}

// Try to get a string out of a map that has any values and return empty string if not a valid string
func lookupString(m map[string]any, key string) string {
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

// loadCredentialsFromFile reads an AWS credential file and returns the parsed credentials.
func loadCredentialsFromFile(filePath string) (aws.Credentials, error) {
	buf, err := os.ReadFile(filePath) // #nosec G304 -- platform provided files
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("could not read credentials file %s; %s", filePath, err)
	}
	c := &awsBackendCredentialFile{}
	if err = yaml.Unmarshal(buf, c); err != nil {
		return aws.Credentials{}, fmt.Errorf("error unmarshalling file %s; %s", filePath, err)
	}
	if c.AccessKey == "" {
		return aws.Credentials{}, errors.New("invalid credentials file, missing access key")
	}
	if c.SecretKey == "" {
		return aws.Credentials{}, errors.New("invalid credentials file, missing secret key")
	}
	creds := aws.Credentials{
		AccessKeyID:     c.AccessKey,
		SecretAccessKey: c.SecretKey,
	}
	if c.SessionToken != "" {
		creds.SessionToken = c.SessionToken
		creds.CanExpire = true
	}
	return creds, nil
}

// loadCredentialsFromInline reads credentials from an inline map.
func loadCredentialsFromInline(inlineMap map[string]string) (aws.Credentials, error) {
	accessKey := inlineMap["aws_access_key_id"]
	if accessKey == "" {
		return aws.Credentials{}, errors.New("inline credentials missing aws_access_key_id")
	}
	secretKey := inlineMap["aws_secret_access_key"]
	if secretKey == "" {
		return aws.Credentials{}, errors.New("inline credentials missing aws_secret_access_key")
	}
	return aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    inlineMap["aws_session_token"],
	}, nil
}

// loadCredentialsFromInlineAny reads credentials from an inline map[string]any (legacy path).
func loadCredentialsFromInlineAny(inlineMap map[string]any) (aws.Credentials, error) {
	accessKey := lookupString(inlineMap, "aws_access_key_id")
	if accessKey == "" {
		return aws.Credentials{}, errors.New("inline credentials missing aws_access_key_id")
	}
	secretKey := lookupString(inlineMap, "aws_secret_access_key")
	if secretKey == "" {
		return aws.Credentials{}, errors.New("inline credentials missing aws_secret_access_key")
	}
	return aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    lookupString(inlineMap, "aws_session_token"),
	}, nil
}

// ---- credential rule: the in-memory representation of a single rule ----

// credentialRule is a compiled, ready-to-evaluate rule.
// If conditionBlock is nil the rule is the default (no when clause).
type credentialRule struct {
	name           string
	conditionBlock map[string]map[string]*policy.ConditionValue // nil == default rule
	credentials    aws.Credentials
}

// isDefault returns true when this rule has no when clause.
func (r *credentialRule) isDefault() bool {
	return r.conditionBlock == nil
}

// matches evaluates this rule against the provided selection context.
// Default rules (no conditionBlock) always match.
func (r *credentialRule) matches(ctx map[string]*policy.ConditionValue) (bool, error) {
	if r.isDefault() {
		return true, nil
	}
	return iam.EvalConditionBlock(r.conditionBlock, ctx)
}

// convertWhenBlock converts the raw YAML when-block (map[string]map[string]any) to
// the typed policy.ConditionValue form required by the evaluator.
func convertWhenBlock(raw map[string]map[string]any) (map[string]map[string]*policy.ConditionValue, error) {
	result := make(map[string]map[string]*policy.ConditionValue, len(raw))
	for operator, keyValues := range raw {
		inner := make(map[string]*policy.ConditionValue, len(keyValues))
		for condKey, rawVal := range keyValues {
			switch v := rawVal.(type) {
			case string:
				inner[condKey] = policy.NewConditionValueString(true, v)
			case []any:
				strs := make([]string, 0, len(v))
				for _, elem := range v {
					s, ok := elem.(string)
					if !ok {
						return nil, fmt.Errorf("condition key %q under %q: expected string elements, got %T", condKey, operator, elem)
					}
					strs = append(strs, s)
				}
				inner[condKey] = policy.NewConditionValueString(true, strs...)
			default:
				return nil, fmt.Errorf("condition key %q under %q: unsupported value type %T", condKey, operator, rawVal)
			}
		}
		result[operator] = inner
	}
	return result, nil
}

// buildCredentialRule constructs a credentialRule from a raw config entry.
func buildCredentialRule(entry credentialRuleFileEntry, relativepath string) (credentialRule, error) {
	if entry.Name == "" {
		return credentialRule{}, errors.New("credential rule must have a non-empty name")
	}

	// Exactly one credential source must be present
	hasFile := entry.File != ""
	hasInline := len(entry.Inline) > 0
	if hasFile && hasInline {
		return credentialRule{}, fmt.Errorf("rule %q: cannot specify both file and inline credentials", entry.Name)
	}
	if !hasFile && !hasInline {
		return credentialRule{}, fmt.Errorf("rule %q: must specify either file or inline credentials", entry.Name)
	}

	var creds aws.Credentials
	var err error
	if hasFile {
		filePath := entry.File
		if !path.IsAbs(filePath) {
			filePath = path.Join(relativepath, filePath)
		}
		creds, err = loadCredentialsFromFile(filePath)
		if err != nil {
			return credentialRule{}, fmt.Errorf("rule %q: %w", entry.Name, err)
		}
	} else {
		creds, err = loadCredentialsFromInline(entry.Inline)
		if err != nil {
			return credentialRule{}, fmt.Errorf("rule %q: %w", entry.Name, err)
		}
	}

	// Build the condition block (nil == default/always-match)
	var conditionBlock map[string]map[string]*policy.ConditionValue
	if len(entry.When) > 0 {
		conditionBlock, err = convertWhenBlock(entry.When)
		if err != nil {
			return credentialRule{}, fmt.Errorf("rule %q when block: %w", entry.Name, err)
		}
	}

	return credentialRule{
		name:           entry.Name,
		conditionBlock: conditionBlock,
		credentials:    creds,
	}, nil
}

// ---- credential selection context ----

// CredentialSelectionContext holds the request-derived attributes used to evaluate
// credential rules. It is built once per request and reused.
type CredentialSelectionContext struct {
	// RequestAccessKeyID is the AKID the caller used to sign the incoming request.
	RequestAccessKeyID string

	// RequestedRegion is the target backend region derived from the request.
	RequestedRegion string

	// ClaimsSubject is the "sub" claim from the validated session token.
	ClaimsSubject string

	// ClaimsIssuer is the issuer claim (initial issuer when available) from the session token.
	ClaimsIssuer string

	// PrincipalTags are the AWS session principal tags from the session token.
	PrincipalTags map[string][]string
}

// Implement s3ifaces.CredentialSelectionContextProvider so CredentialSelectionContext can
// be used wherever the interface is expected.
func (c CredentialSelectionContext) GetRequestAccessKeyID() string         { return c.RequestAccessKeyID }
func (c CredentialSelectionContext) GetRequestedRegion() string            { return c.RequestedRegion }
func (c CredentialSelectionContext) GetClaimsSubject() string              { return c.ClaimsSubject }
func (c CredentialSelectionContext) GetClaimsIssuer() string               { return c.ClaimsIssuer }
func (c CredentialSelectionContext) GetPrincipalTags() map[string][]string { return c.PrincipalTags }

// compile-time check that CredentialSelectionContext satisfies the interface
var _ s3ifaces.CredentialSelectionContextProvider = CredentialSelectionContext{}

// selectionContextToConditionContext converts any CredentialSelectionContextProvider to the
// condition-key map expected by the IAM evaluator.
func selectionContextToConditionContext(p s3ifaces.CredentialSelectionContextProvider) map[string]*policy.ConditionValue {
	ctx := make(map[string]*policy.ConditionValue)
	if v := p.GetRequestAccessKeyID(); v != "" {
		ctx[ConditionKeyRequestAccessKeyId] = policy.NewConditionValueString(true, v)
	}
	if v := p.GetRequestedRegion(); v != "" {
		ctx["aws:RequestedRegion"] = policy.NewConditionValueString(true, v)
	}
	if v := p.GetClaimsSubject(); v != "" {
		ctx["claims:sub"] = policy.NewConditionValueString(true, v)
	}
	if v := p.GetClaimsIssuer(); v != "" {
		ctx["claims:iss"] = policy.NewConditionValueString(true, v)
	}
	for tagKey, tagValues := range p.GetPrincipalTags() {
		ctx[fmt.Sprintf("aws:PrincipalTag/%s", tagKey)] = policy.NewConditionValueString(true, tagValues...)
	}
	return ctx
}

// ---- backend config entry ----

type backendConfigEntry struct {
	// credentialRules is the ordered list of credential rules (default rule, if present, is last).
	credentialRules []credentialRule

	// credentials is kept for the legacy static path (GetBackendCredentials without request context).
	// It is the credential of the single default rule when the config uses legacy syntax.
	credentials aws.Credentials

	endpoint endpoint

	//A list of capabilities supported by the backend.
	//Check interfaces/backend-s3-capabilities for a definition of capabilities
	capabilities []s3ifaces.S3Capability
}

// ErrNoMatchingCredentialRule is returned when no credential rule matches the selection context.
var ErrNoMatchingCredentialRule = errors.New("no matching credential rule for this request")

// A dedicated type for endpoint allows to have the semantics of endpoints of the config.
// When creating these endpoints we do certain checks so by typing them we can assume these
// checks had passed whenever we encounter an endpoint later on
type endpoint string

func buildEndpoint(uri string) (endpoint, error) {
	if !strings.HasPrefix(uri, "https://") && !strings.HasPrefix(uri, "http://") {
		return "", errors.New("endpoint URIs must start with https:// or http://")
	}
	return endpoint(uri), nil
}

// This method is to get rid of the protocol from the endpoint specification
func (e endpoint) GetHost() string {
	uriString := string(e)
	return strings.Split(uriString, "://")[1]
}

// The endpoint base URI is of form protocol://hostname and can be used to identify the backend
// service
func (e endpoint) GetBaseURI() string {
	return string(e)
}

// getCredentialsRulesFromEntry parses and validates the credential rules for one backend.
// It handles both the legacy single-credential format and the new rules format.
func getCredentialRulesFromEntry(rawCreds map[string]any, relativepath string) ([]credentialRule, error) {
	// --- new rules format ---
	rulesRaw, hasRules := rawCreds["rules"]
	if hasRules {
		// Reject mixing rules with legacy top-level keys
		if _, hasFile := rawCreds["file"]; hasFile {
			return nil, errors.New("cannot mix credentials.rules with credentials.file")
		}
		if _, hasInline := rawCreds["inline"]; hasInline {
			return nil, errors.New("cannot mix credentials.rules with credentials.inline")
		}

		// Re-marshal the rules slice so we can unmarshal into the typed struct
		rulesBytes, err := yaml.Marshal(rulesRaw)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal credentials.rules: %w", err)
		}
		var rawEntries []credentialRuleFileEntry
		if err = yaml.Unmarshal(rulesBytes, &rawEntries); err != nil {
			return nil, fmt.Errorf("cannot parse credentials.rules: %w", err)
		}
		if len(rawEntries) == 0 {
			return nil, errors.New("credentials.rules must have at least one rule")
		}

		// Validate and build rules; separate defaults from conditional rules
		var conditionalRules []credentialRule
		var defaultRules []credentialRule

		for _, entry := range rawEntries {
			rule, err := buildCredentialRule(entry, relativepath)
			if err != nil {
				return nil, err
			}
			if rule.isDefault() {
				defaultRules = append(defaultRules, rule)
			} else {
				conditionalRules = append(conditionalRules, rule)
			}
		}
		if len(defaultRules) > 1 {
			return nil, errors.New("credentials.rules may have at most one default rule (a rule without 'when')")
		}

		// Defaults are always evaluated last
		rules := conditionalRules
		rules = append(rules, defaultRules...)
		return rules, nil
	}

	// --- legacy single-credential format: normalize to one default rule ---
	legacyEntry := backendConfigFileEntry{Credentials: rawCreds}
	creds, err := legacyEntry.getCredentials(relativepath)
	if err != nil {
		return nil, err
	}
	return []credentialRule{
		{
			name:           "_legacy_default",
			conditionBlock: nil, // default
			credentials:    creds,
		},
	}, nil
}

// The config file could host different types of credentials. Check cases 1 by one
// and fail if there was no valid type of credentials found.
// This is the legacy path kept for getCredentialRulesFromEntry.
func (entry backendConfigFileEntry) getCredentials(relativepath string) (creds aws.Credentials, err error) {
	fileEntry, ok := entry.Credentials["file"]
	if ok {
		filePath, ok := fileEntry.(string)
		if !ok {
			return buildCredentialErrorf("When providing a credential file it must be a string, got %v", fileEntry)
		}
		if !path.IsAbs(filePath) {
			filePath = path.Join(relativepath, filePath)
		}
		return loadCredentialsFromFile(filePath)
	}
	inlineEntry, ok := entry.Credentials["inline"]
	if ok {
		inlineMap, ok := inlineEntry.(map[string]any)
		if !ok {
			return buildCredentialErrorf("When providing inline credentials a map must be provided. %v", fileEntry)
		}
		return loadCredentialsFromInlineAny(inlineMap)
	}
	return creds, errors.New("unable to find a valid type of credentials")
}

func (bce *backendConfigEntry) fromBackendConfigFileEntry(input backendConfigFileEntry, relativepath string) error {
	endpointVal, err := buildEndpoint(input.Endpoint)
	if err != nil {
		return err
	}
	bce.endpoint = endpointVal

	bce.credentialRules, err = getCredentialRulesFromEntry(input.Credentials, relativepath)
	if err != nil {
		return err
	}

	// Keep the legacy credentials field populated for static callers (e.g. presign).
	// Use the first default rule's credentials for that purpose.
	for _, rule := range bce.credentialRules {
		if rule.isDefault() {
			bce.credentials = rule.credentials
			break
		}
	}

	bce.capabilities = make([]s3ifaces.S3Capability, 0)
	for _, capability := range input.Capabilities {
		typedCapability, exists := s3ifaces.S3CapabilityLookup[capability]
		if !exists {
			return fmt.Errorf("unknown capability: %s in config %v", capability, input)
		}
		bce.capabilities = append(bce.capabilities, typedCapability)
	}
	return nil
}

type backendsConfig struct {
	backends       map[string]backendConfigEntry
	defaultBackend string

	invalidRegionToDefaultRegion bool
}

type backendsConfigFile struct {
	Backends []backendConfigFileEntry `yaml:"s3backends" json:"s3backends"`
	Default  string                   `yaml:"default" json:"default"`
}

// TODO: legacyBehavior
func getBackendsConfig(filename string, legacyBehavior bool) (*backendsConfig, error) {
	buf, err := os.ReadFile(filename) // #nosec G304 -- platform provided files
	if err != nil {
		return nil, err
	}
	_, relativepath := utils.GetFilenameAndRelativePath(filename)
	return getBackendsConfigFromBytes(buf, legacyBehavior, relativepath)
}

// Process a backends configuration in bytes. Use the relativepath as a prefix for filepaths
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

var errInvalidBackendErr = errors.New("invalid BackendId")

func (cfg *backendsConfig) HasCapability(backendId string, capability s3ifaces.S3Capability) bool {
	backendCfg, err := cfg.getBackendConfig(backendId)
	if err == nil {
		return slices.Contains(backendCfg.capabilities, capability)
	} else {
		return false
	}
}

func (cfg *backendsConfig) getBackendConfig(backendId string) (cfgEntry backendConfigEntry, err error) {
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
		if cfg.invalidRegionToDefaultRegion && backendId != cfg.defaultBackend {
			return cfg.getBackendConfig(cfg.defaultBackend)
		} else {
			return cfgEntry, errInvalidBackendErr
		}
	}
}

// GetBackendCredentials returns the static (default rule) credentials for a backend.
// This is kept for callers that do not have request context (e.g. presign CLI).
func (cfg *backendsConfig) GetBackendCredentials(backendId string) (creds aws.Credentials, err error) {
	backendCfg, err := cfg.getBackendConfig(backendId)
	if err != nil {
		return creds, err
	}
	creds = backendCfg.credentials
	return
}

// SelectBackendCredentials evaluates credential rules for the given backend against the
// provided selection context and returns the first matching rule's credentials.
// Returns ErrNoMatchingCredentialRule (which should be surfaced as AccessDenied) when no
// rule matches and there is no default rule.
func (cfg *backendsConfig) SelectBackendCredentials(backendId string, selCtx s3ifaces.CredentialSelectionContextProvider) (aws.Credentials, string, error) {
	backendCfg, err := cfg.getBackendConfig(backendId)
	if err != nil {
		return aws.Credentials{}, "", err
	}
	condCtx := selectionContextToConditionContext(selCtx)
	for _, rule := range backendCfg.credentialRules {
		matched, err := rule.matches(condCtx)
		if err != nil {
			return aws.Credentials{}, "", fmt.Errorf("error evaluating credential rule %q: %w", rule.name, err)
		}
		if matched {
			return rule.credentials, rule.name, nil
		}
	}
	return aws.Credentials{}, "", ErrNoMatchingCredentialRule
}

// compile-time assertion: *backendsConfig must satisfy s3ifaces.BackendManager
var _ s3ifaces.BackendManager = (*backendsConfig)(nil)

func GetBackendCredentials(cfgFilePath, backendId string) (creds aws.Credentials, err error) {
	cfg, err := getBackendsConfig(cfgFilePath, true)
	if err != nil {
		return aws.Credentials{}, err
	}
	return cfg.GetBackendCredentials(backendId)
}

// Get endpoint for a backend. The endpoint contains the protocol and the hostname
// to arrive at the backend.
func (cfg *backendsConfig) GetBackendEndpoint(backendId string) (s3ifaces.Endpoint, error) {
	backendCfg, err := cfg.getBackendConfig(backendId)
	if err != nil {
		return nil, err
	}
	return backendCfg.endpoint, nil
}

func (cfg *backendsConfig) GetDefaultBackend() string {
	return cfg.defaultBackend
}
