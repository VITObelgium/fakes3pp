package server

import (
	"crypto/tls"
	"log/slog"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// tlsCertificateReloader holds the current TLS certificate/key pair and keeps
// them fresh by watching the source files with fsnotify.  The initial load is
// strict: any error causes newTLSCertificateReloader to return an error.
// Subsequent reloads on file changes are tolerant: a parse failure logs a
// warning and the previous valid certificate is kept in service.
type tlsCertificateReloader struct {
	certFile string
	keyFile  string

	mu   sync.RWMutex
	cert *tls.Certificate

	watcher *fsnotify.Watcher
}

// newTLSCertificateReloader creates a reloader, performs the initial
// certificate load (returning an error if it fails), and starts the
// background fsnotify watcher goroutine.
func newTLSCertificateReloader(certFile, keyFile string) (*tlsCertificateReloader, error) {
	r := &tlsCertificateReloader{
		certFile: certFile,
		keyFile:  keyFile,
	}

	//First we setup watches for files.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	r.watcher = watcher

	if err = watcher.Add(certFile); err != nil {
		_ = watcher.Close()
		return nil, err
	}
	if err = watcher.Add(keyFile); err != nil {
		_ = watcher.Close()
		return nil, err
	}

	go r.watchLoop()

	//Then we load them so if they change we should not have a race condition between loading and watching.
	if err := r.loadLocked(); err != nil {
		return nil, err
	}

	return r, nil
}

// loadLocked reads both files from disk and atomically swaps the stored
// certificate.  It is safe to call concurrently; the write lock is acquired
// only after the (potentially slow) file I/O.
func (r *tlsCertificateReloader) loadLocked() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cert = &cert
	return nil
}

// watchLoop is the background goroutine that reacts to fsnotify events.
func (r *tlsCertificateReloader) watchLoop() {
	for {
		select {
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			slog.Debug("TLS certificate watcher event", "event", event)
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				slog.Info("TLS certificate file changed, reloading", "file", event.Name)
				if err := r.loadLocked(); err != nil {
					slog.Warn("Failed to reload TLS certificate, keeping previous cert",
						"file", event.Name, "error", err)
				} else {
					slog.Info("TLS certificate reloaded successfully")
				}
			}
			if event.Has(fsnotify.Remove) {
				slog.Warn("TLS certificate file removed, waiting for it to reappear",
					"file", event.Name)
				// Kubernetes secret rotation replaces via remove+create; re-arm
				// the watch so we catch the new file when it arrives.
				r.rearmWatch(event.Name)
			}
		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("TLS certificate watcher error", "error", err)
		}
	}
}

// rearmWatch removes a stale watch entry (ignoring errors) and adds it back
// only if the file already exists again.
func (r *tlsCertificateReloader) rearmWatch(fileName string) {
	_ = r.watcher.Remove(fileName)
	if _, err := os.Stat(fileName); err == nil {
		if addErr := r.watcher.Add(fileName); addErr != nil {
			slog.Error("Could not re-arm TLS certificate watcher", "file", fileName,
				"error", addErr)
		}
	}
}

// GetCertificate implements tls.Config.GetCertificate.  It returns the
// currently loaded certificate under a read lock so it is safe to call from
// multiple goroutines while a reload is in progress.
func (r *tlsCertificateReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// Close stops the underlying fsnotify watcher.  It should be called when the
// server is shutting down.
func (r *tlsCertificateReloader) Close() {
	if err := r.watcher.Close(); err != nil {
		slog.Warn("Error closing TLS certificate watcher", "error", err)
	}
}
