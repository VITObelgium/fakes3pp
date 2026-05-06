package server

// Option B certificate strategy: all test certificates are generated
// programmatically using crypto/x509 so the tests have zero dependency on
// checked-in key material and can create as many distinct cert/key pairs as
// they need at runtime.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSelfSignedCert creates a throwaway ECDSA P-256 cert/key pair and
// returns their PEM-encoded bytes.  It is intentionally minimal – validity,
// SANs, etc. are set just enough for tls.LoadX509KeyPair to accept them.
// Each call produces a distinct certificate because the serial number is drawn
// from a cryptographically random 64-bit range.
func generateSelfSignedCert(t testing.TB) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// writeCertFiles writes cert and key PEM bytes to temporary files and returns
// their paths.  The files are cleaned up automatically when the test ends.
func writeCertFiles(t testing.TB, certPEM, keyPEM []byte) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// certSerial extracts the serial number from a *tls.Certificate for easy
// comparison in assertions.
func certSerial(t testing.TB, cert *tls.Certificate) *big.Int {
	t.Helper()
	if len(cert.Certificate) == 0 {
		t.Fatal("tls.Certificate has no raw DER data")
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return x509Cert.SerialNumber
}

// TestTLSReloaderInitialLoad verifies that a reloader created with valid files
// immediately serves the loaded certificate.
func TestTLSReloaderInitialLoad(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	certFile, keyFile := writeCertFiles(t, certPEM, keyPEM)

	r, err := newTLSCertificateReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newTLSCertificateReloader: %v", err)
	}
	defer r.Close()

	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil cert")
	}
}

// TestTLSReloaderFailsOnBadInitialCert verifies that newTLSCertificateReloader
// returns an error immediately when the initial cert/key files are invalid,
// rather than starting with a nil certificate.
func TestTLSReloaderFailsOnBadInitialCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, []byte("not a cert"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := newTLSCertificateReloader(certFile, keyFile)
	if err == nil {
		t.Fatal("expected error for invalid cert/key, got nil")
	}
}

// TestTLSReloaderReloadOnFileChange writes a second certificate to disk after
// the reloader has started and verifies that GetCertificate eventually returns
// the new certificate (identified by a different serial number).
func TestTLSReloaderReloadOnFileChange(t *testing.T) {
	certPEM1, keyPEM1 := generateSelfSignedCert(t)
	certFile, keyFile := writeCertFiles(t, certPEM1, keyPEM1)

	r, err := newTLSCertificateReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newTLSCertificateReloader: %v", err)
	}
	defer r.Close()

	cert1, _ := r.GetCertificate(nil)
	serial1 := certSerial(t, cert1)

	// Generate a second, distinct cert with a different serial number.
	certPEM2, keyPEM2 := generateSelfSignedCert(t)
	// Write key first, then cert – both events will be delivered but a single
	// reload is sufficient.
	if err := os.WriteFile(keyFile, keyPEM2, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, certPEM2, 0600); err != nil {
		t.Fatal(err)
	}

	// Poll until the reloader picks up the new certificate (or timeout).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cert2, _ := r.GetCertificate(nil)
		if certSerial(t, cert2).Cmp(serial1) != 0 {
			return // success – cert was reloaded
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for certificate reload after file change")
}

// TestTLSReloaderKeepsLastGoodCertOnInvalidReplacement writes garbage bytes
// over the cert file and verifies that the reloader keeps the previous valid
// certificate rather than replacing it with nil.
func TestTLSReloaderKeepsLastGoodCertOnInvalidReplacement(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	certFile, keyFile := writeCertFiles(t, certPEM, keyPEM)

	r, err := newTLSCertificateReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newTLSCertificateReloader: %v", err)
	}
	defer r.Close()

	cert1, _ := r.GetCertificate(nil)
	serial1 := certSerial(t, cert1)

	// Overwrite cert with invalid data.
	if err := os.WriteFile(certFile, []byte("not a cert"), 0600); err != nil {
		t.Fatal(err)
	}

	// Give the watcher goroutine time to process the event and attempt a reload.
	time.Sleep(300 * time.Millisecond)

	cert2, err2 := r.GetCertificate(nil)
	if err2 != nil {
		t.Fatalf("GetCertificate after bad write: %v", err2)
	}
	if cert2 == nil {
		t.Fatal("GetCertificate returned nil after bad write")
	}
	serial2 := certSerial(t, cert2)
	if serial2.Cmp(serial1) != 0 {
		t.Fatalf("certificate changed after invalid replacement: was serial %v, now %v",
			serial1, serial2)
	}
	_ = keyFile // keyFile remains valid; only cert was corrupted
}
