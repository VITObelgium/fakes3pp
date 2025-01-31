package cmd

import (
	"bytes"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"text/template"

	"github.com/VITObelgium/fakes3pp/aws/service/sts/session"
	"github.com/fsnotify/fsnotify"
)

const PathSeparator = "/"
const policySuffix = ".json.tmpl"


type LocalPolicyRetriever struct{
	rolePolicyPath string
	
	//To communicate cache invalidation.
	pm *PolicyManager

	//To monitor file system changes
	watcher *fsnotify.Watcher
}

var localPolicyRetrievers map[string]*LocalPolicyRetriever = map[string]*LocalPolicyRetriever{}

func NewLocalPolicyRetriever(stsRolePolicyPath string) *LocalPolicyRetriever {
	lp, ok := localPolicyRetrievers[stsRolePolicyPath]
	if ok {
		slog.Warn("Getting lp from cache", "stsRolePolicyPath", stsRolePolicyPath)
		return lp
	}

	var fileDeleted fileCallback = func(fileName string) {
		if lp.pm == nil {
			slog.Warn("There was no Policy Manager for local retriever to handle file deletion", "retriever", lp)
		} else {
			arn, err := lp.getPolicyArn(fileName)
			if err != nil {
				slog.Error("Could not get arn", "filename", fileName)
			}
			slog.Info("Remove policy", "arn", arn)
			lp.pm.deletePolicyCacheEntry(arn)
		}
	}

	var fileUpdated fileCallback = func(fileName string) {
		if lp.pm == nil {
			slog.Warn("There was no Policy Manager for local retriever to handle file update", "retriever", lp)
		} else {
			arn, err := lp.getPolicyArn(fileName)
			if err != nil {
				slog.Error("Could not get arn", "filename", fileName)
			}
			slog.Info("Reload policy", "arn", arn)
			lp.pm.deletePolicyCacheEntry(arn)
			_, err = lp.pm.getPolicyTemplate(arn)
			if err != nil {
				slog.Warn("Could not get policy", "policyArn", arn)
			}
		}
	}

	watcher := createFileWatcherAndStartWatching(fileUpdated, fileDeleted)
	lp =  &LocalPolicyRetriever{
		rolePolicyPath: stsRolePolicyPath,
		watcher: watcher,
	}

	localPolicyRetrievers[stsRolePolicyPath] = lp

	return lp
}

func (r *LocalPolicyRetriever) getPolicyPathPrefix() (string) {
	return fmt.Sprintf("%s%s", r.rolePolicyPath, PathSeparator)
}

func (r *LocalPolicyRetriever) getPolicyPath(arn string) (string) {
	safeRoleArn := b32(arn)
	return fmt.Sprintf("%s%s%s", r.getPolicyPathPrefix(), safeRoleArn, policySuffix)
}

func (r *LocalPolicyRetriever) getPolicyArn(filePath string) (string, error) {
	prefix := r.getPolicyPathPrefix()
	suffix := policySuffix

	if len(suffix) > len(filePath) || len(prefix) > len(filePath) - len(suffix) {
		slog.Warn("Invalid file path for policy", "filepath", filePath)
	}

	safePolicyName := filePath[len(prefix):len(filePath) - len(suffix)]
	policyArn, err := b32_decode(safePolicyName)
	if err != nil {
		return "", err
	}
	return policyArn, nil
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
	filePath := r.getPolicyPath(arn)
	startWatching(r.watcher, filePath) // For cache invalidation
	c, err := readFileFull(filePath)
	if err != nil {
		return "", err
	}
	return string(c), err
}

func (r *LocalPolicyRetriever) registerPolicyManager(pm *PolicyManager) {
	r.pm = pm
}

type PolicyRetriever interface {
	//Retrieve the policy content based out of an identifier which can be an AWS ARN
	retrievePolicyStr(string) (string, error)

	//Get all policy identifiers
	retrieveAllIdentifiers() ([]string, error)

	//Set PolicyManager
	//Each policy retriever can be used by 1 policy Manager when the policy manager gets
	//created with a policy retriever it will register itself using this method this allows
	//The retriever to do calls to the policy manager for example to communicate policy changes
	registerPolicyManager(pm *PolicyManager)
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
	Tags session.AWSSessionTags
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

func (m *PolicyManager) deletePolicyCacheEntry(arn string) {
	m.tMux.Lock()
	defer m.tMux.Unlock()
	_, exists := m.templates[arn]
	if !exists {
		return
	} else {
		delete(m.templates, arn)
	}
}

func NewPolicyManager(r PolicyRetriever) *PolicyManager{
	pm := &PolicyManager{
		retriever: r,
		templates: map[string]*template.Template{},
		tMux: &sync.RWMutex{},
	}
	r.registerPolicyManager(pm)
	return pm
}

//A callback function that takes a filepath to action a change to a file.
type fileCallback func(string) ()


//Start a watcher to keep an eye on files
//
//This will start watching later on 
func createFileWatcherAndStartWatching(fileChanged, fileDeleted fileCallback) (*fsnotify.Watcher) {
	//See https://github.com/fsnotify/fsnotify
	watcher, err := fsnotify.NewWatcher()
    if err != nil {
        slog.Error("Could not create new watcher", "error", err)
    }

    // Start listening for events.
    go func() {
        for {
            select {
            case event, ok := <-watcher.Events:
                if !ok {
                    return
                }
				slog.Debug("Config watcher event", "event", event)
                if event.Has(fsnotify.Write) {
                    slog.Debug("Write notification", "event", event)
					fileChanged(event.Name)
                }
				if event.Has(fsnotify.Remove) {
					slog.Debug("Deletion notification", "event", event)
					fileDeleted(event.Name)
					// See https://ahmet.im/blog/kubernetes-inotify/
					restartWatching(watcher, event.Name)
				}
            case err, ok := <-watcher.Errors:
                if !ok {
                    return
                }
                slog.Warn("error with file watcher", "error", err)
            }
        }
    }()
	return watcher
}

func startWatching(watcher *fsnotify.Watcher, fileName string) {
    err := watcher.Add(fileName)
    if err != nil {
        slog.Error("Could not add watcher", "filename", fileName, "error", err)
    } else {
		slog.Debug("Started watching file", "filename", fileName)
	}
}

func restartWatching(watcher *fsnotify.Watcher, fileName string) {
	err := watcher.Remove(fileName)
    if err != nil {
        slog.Debug("Wanted to stop watching file but watcher was gone", "filename", fileName)
    } else {
		slog.Debug("Stopped watching file", "filename", fileName)
	}
	startWatching(watcher, fileName)
}