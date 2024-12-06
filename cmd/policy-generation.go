package cmd

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sync"
	"text/template"
)

const PathSeparator = "/"
const policySuffix = ".json.tmpl"


type LocalPolicyRetriever struct{
	rolePolicyPath string
}

func NewLocalPolicyRetriever(stsRolePolicyPath string) *LocalPolicyRetriever {
	return &LocalPolicyRetriever{
		rolePolicyPath: stsRolePolicyPath,
	}
}

func (r *LocalPolicyRetriever) getPolicyPathPrefix() (string) {
	return fmt.Sprintf("%s%s", r.rolePolicyPath, PathSeparator)
}

func (r *LocalPolicyRetriever) getPolicyPath(arn string) (string) {
	safeRoleArn := b32(arn)
	return fmt.Sprintf("%s%s%s", r.getPolicyPathPrefix(), safeRoleArn, policySuffix)
}

func (r LocalPolicyRetriever) retrieveAllIdentifiers() ([]string, error) {
	prefix := r.getPolicyPathPrefix()
	suffix := policySuffix
	matches, err := filepath.Glob(fmt.Sprintf("%s*%s", prefix , suffix))
	if err != nil {
		return nil, err
	}
	cleanedMatches := make([]string, len(matches))
	for i, match := range matches {
		safePolicyName := match[len(prefix):len(match) - len(suffix)]
		cleanedMatches[i], err = b32_decode(safePolicyName)
		if err != nil {
			return nil, err
		} 
	}	
	return cleanedMatches, err
}

func (r *LocalPolicyRetriever) retrievePolicyStr(arn string) (string, error) {
	c, err := readFileFull(r.getPolicyPath(arn))
	if err != nil {
		return "", err
	}
	return string(c), err
}

type PolicyRetriever interface {
	//Retrieve the policy content based out of an identifier which can be an AWS ARN
	retrievePolicyStr(string) (string, error)

	//Get all policy identifiers
	retrieveAllIdentifiers() ([]string, error)
}

type PolicyManager struct {
	retriever PolicyRetriever
	templates map[string]*template.Template
	//Mutex for local template access
	tMux      *sync.RWMutex
}

//Check if a policy manager can get a policy corresponding to an ARN
func (m *PolicyManager) DoesPolicyExist(arn string) bool {

	_, err := m.getPolicyTemplate(arn)
	return err == nil
}

//Check if a policy manager can get a policy corresponding to an ARN
func (m *PolicyManager) PreWarm() error {
	ids, err := m.retriever.retrieveAllIdentifiers()
	if err != nil {
		return err
	}
	for _, policyId := range ids {
		_, err := m.getPolicyTemplate(policyId)
		if err != nil{
			return err
		}
	}
	return nil	
}

//Get template from local cache and nil if it does not exist
func (m *PolicyManager) getPolicyTemplateFromCache(arn string) (tmpl *template.Template) {
	m.tMux.RLock()
	defer m.tMux.RUnlock()
	tmpl, exists := m.templates[arn]
	if !exists {
		return nil
	}
	return tmpl
}

func (m *PolicyManager) getPolicyTemplate(arn string) (tmpl *template.Template, err error) {
	tmpl = m.getPolicyTemplateFromCache(arn)
	if tmpl != nil {
		return
	}
	policy, err := m.retriever.retrievePolicyStr(arn)
	if err != nil {
		return nil, err

	}
	funcMap := template.FuncMap{
		"YYYYmmdd":        YYYYmmdd,
		"Now":             Now,
		"Add1Day":         Add1Day,
		"SHA1":            sha1sum,
		"YYYYmmddSlashed": YYYYmmddSlashed,
	}
	tmpl, err = template.New(arn).Funcs(funcMap).Parse(policy)
	if err == nil {
		m.tMux.Lock()
		defer m.tMux.Unlock()
		m.templates[arn] = tmpl
	} else {
		return nil, err
	}
	return 
}


type PolicySessionClaims struct {
	Subject string
	Issuer string
}


//This is the structure that will be made available during templating and
//thus is available to be used in policies.
type PolicySessionData struct {
	Claims PolicySessionClaims
	Tags AWSSessionTags
	RequestedRegion string
}

func GetPolicySessionDataFromClaims(claims *SessionClaims) *PolicySessionData {
	issuer := claims.IIssuer
	if issuer == "" {
		issuer = claims.Issuer
	}
	return &PolicySessionData{
		Claims: PolicySessionClaims{
			Subject: claims.Subject,
			Issuer: issuer,
		},
		Tags: claims.Tags,
	}
}


func (m *PolicyManager) GetPolicy(arn string, data *PolicySessionData) (string, error) {
	tmpl, err := m.getPolicyTemplate(arn)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func NewPolicyManager(r PolicyRetriever) *PolicyManager{
	return &PolicyManager{
		retriever: r,
		templates: map[string]*template.Template{},
		tMux: &sync.RWMutex{},
	}
}