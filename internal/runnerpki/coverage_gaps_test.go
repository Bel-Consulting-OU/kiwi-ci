package runnerpki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failingReader struct {
	budget int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.budget <= 0 {
		return 0, errors.New("entropy exhausted")
	}
	if len(p) > r.budget {
		p = p[:r.budget]
	}
	for i := range p {
		p[i] = byte(i * 7)
	}
	r.budget -= len(p)
	return len(p), nil
}

func withFailingRand(t *testing.T, budget int) {
	t.Helper()
	old := randomReader()
	injected := io.Reader(&failingReader{budget: budget})
	randReader.Store(&injected)
	t.Cleanup(func() {
		restore := old
		randReader.Store(&restore)
	})
}

func rsaCA(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "rsa ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestLoadCARejectsMalformedMaterial(t *testing.T) {
	ca, err := NewCA("ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := caCertPEM(t, ca)
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	badCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	badKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	_, leafPEM, _ := signRunner(t, ca, "leaf")
	rsaKey, rsaCAPEM := rsaCA(t)
	rsaKeyDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaKeyDER})

	cases := []struct {
		name     string
		cert     []byte
		key      []byte
		contains string
	}{
		{"cert not pem", []byte("junk"), keyPEM, "invalid CA certificate PEM"},
		{"cert wrong block", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ca.Cert.Raw}), keyPEM, "invalid CA certificate PEM"},
		{"cert undecodable", badCertPEM, keyPEM, "parse CA certificate"},
		{"cert not ca", leafPEM, keyPEM, "not a CA"},
		{"key not pem", caPEM, []byte("junk"), "invalid CA private key PEM"},
		{"key undecodable", caPEM, badKeyPEM, "parse CA private key"},
		{"key not ed25519", caPEM, rsaKeyPEM, "not Ed25519"},
		{"cert not ed25519", rsaCAPEM, keyPEM, "public key is not Ed25519"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadCA(c.cert, c.key)
			if err == nil || !strings.Contains(err.Error(), c.contains) {
				t.Fatalf("LoadCA error = %v, want %q", err, c.contains)
			}
		})
	}
}

func TestLoadOrCreateCAErrorBranches(t *testing.T) {
	testutil.UnixChmod(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, caCertFile), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err == nil || !strings.Contains(err.Error(), "load runner CA") {
		t.Fatalf("corrupt existing CA = %v", err)
	}

	certDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(certDir, caCertFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(certDir); err == nil {
		t.Fatal("unreadable cert path must error")
	}

	keyDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(keyDir, caKeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(keyDir); err == nil {
		t.Fatal("unreadable key path must error")
	}

	// Write-phase and durability-step failures are covered by
	// TestRunnerCAAtomicDurabilitySeams, which injects a failing step through
	// the fsutil hooks (the private non-fsync writer this branch used to
	// probe with a directory at "<file>.tmp" is gone).

	if os.Geteuid() != 0 {
		ro := t.TempDir()
		if err := os.Chmod(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(ro, 0o700)
		if _, err := LoadOrCreateCA(filepath.Join(ro, "sub")); err == nil {
			t.Fatal("MkdirAll under a read-only parent must error")
		}
	}
}

func TestNewCAEntropyFailures(t *testing.T) {
	withFailingRand(t, 31)
	if _, err := NewCA("ca", time.Hour); err == nil {
		t.Fatal("key generation failure must propagate")
	}
	if _, _, err := GenerateKeyAndCSR("runner"); err == nil {
		t.Fatal("enrollment key generation failure must propagate")
	}
	withFailingRand(t, 0)
	if _, err := LoadOrCreateCA(t.TempDir()); err == nil {
		t.Fatal("LoadOrCreateCA must propagate CA generation failure")
	}
	withFailingRand(t, 32)
	if _, err := NewCA("ca", time.Hour); err == nil {
		t.Fatal("serial generation failure must propagate")
	}
}

func TestNewCADefaultTTL(t *testing.T) {
	ca, err := NewCA("ca", 0)
	if err != nil {
		t.Fatal(err)
	}
	if remaining := time.Until(ca.Cert.NotAfter); remaining < 300*24*time.Hour {
		t.Fatalf("default TTL too short: %v", remaining)
	}
}

func TestSignRunnerCSRInputValidation(t *testing.T) {
	var nilCA *CA
	if _, err := nilCA.SignRunnerCSR(nil, "r", 0, nil); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("nil CA = %v", err)
	}
	ca, err := NewCA("ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM, err := GenerateKeyAndCSR("r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.SignRunnerCSR(csrPEM, "", time.Hour, nil); err == nil || !strings.Contains(err.Error(), "runner id is required") {
		t.Fatalf("empty runner id = %v", err)
	}
	if _, err := ca.SignRunnerCSR([]byte("junk"), "r", time.Hour, nil); err == nil || !strings.Contains(err.Error(), "invalid CSR PEM") {
		t.Fatalf("junk CSR = %v", err)
	}
	badCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("not a csr")})
	if _, err := ca.SignRunnerCSR(badCSR, "r", time.Hour, nil); err == nil || !strings.Contains(err.Error(), "parse CSR") {
		t.Fatalf("undecodable CSR = %v", err)
	}
	if _, err := ca.SignRunnerCSR(csrPEM, "r", time.Hour, []string{"relative/path"}); err == nil || !strings.Contains(err.Error(), "invalid extra SAN URI") {
		t.Fatalf("non-absolute extra SAN = %v", err)
	}
	certPEM, err := ca.SignRunnerCSR(csrPEM, "r", 0, []string{"spiffe://kiwi/extra"})
	if err != nil {
		t.Fatalf("valid extra SAN: %v", err)
	}
	cert := parseCert(t, certPEM)
	if len(cert.URIs) != 2 || cert.URIs[1].String() != "spiffe://kiwi/extra" {
		t.Fatalf("extra SANs = %v", cert.URIs)
	}
	if remaining := time.Until(cert.NotAfter); remaining < 300*24*time.Hour {
		t.Fatalf("zero ttl did not default to a year: %v", remaining)
	}

	withFailingRand(t, 0)
	if _, err := ca.SignRunnerCSR(csrPEM, "r", time.Hour, nil); err == nil || !strings.Contains(err.Error(), "generate certificate serial") {
		t.Fatalf("serial failure = %v", err)
	}
}

func TestSignRunnerCSRMismatchedCAKey(t *testing.T) {
	ca1, err := NewCA("one", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := NewCA("two", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM, err := GenerateKeyAndCSR("r")
	if err != nil {
		t.Fatal(err)
	}
	mismatch := &CA{Cert: ca1.Cert, Key: ca2.Key}
	if _, err := mismatch.SignRunnerCSR(csrPEM, "r", time.Hour, nil); err == nil || !strings.Contains(err.Error(), "sign CSR") {
		t.Fatalf("mismatched CA key = %v", err)
	}
}

func TestVerifyPeerBranches(t *testing.T) {
	ca, err := NewCA("ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, leaf := signRunner(t, ca, "runner-1")
	roots := Pool(caCertPEM(t, ca))
	if _, err := ca.VerifyPeer(leaf, nil); err == nil || !strings.Contains(err.Error(), "no trust roots") {
		t.Fatalf("nil roots = %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	serverOnly := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, serverOnly, ca.Cert, priv.Public(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.VerifyPeer(serverCert, roots); err == nil || !strings.Contains(err.Error(), "client authentication") {
		t.Fatalf("server-only EKU = %v", err)
	}

	unknownCA, err := NewCA("other", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.VerifyPeer(leaf, Pool(caCertPEM(t, unknownCA))); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("untrusted chain = %v", err)
	}
}

func TestRunnerIDFromCertFallbacks(t *testing.T) {
	if got := RunnerIDFromCert(nil); got != "" {
		t.Fatalf("nil cert = %q", got)
	}
	now := time.Now().UTC()
	uriCert := &x509.Certificate{
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(time.Hour),
	}
	uri, err := url.Parse("spiffe://kiwi/runner/uri-runner")
	if err != nil {
		t.Fatal(err)
	}
	uriCert.URIs = []*url.URL{uri}
	if got := RunnerIDFromCert(uriCert); got != "uri-runner" {
		t.Fatalf("URI fallback = %q", got)
	}
	other, err := url.Parse("spiffe://other/runner/nope")
	if err != nil {
		t.Fatal(err)
	}
	uriCert.URIs = []*url.URL{other}
	if got := RunnerIDFromCert(uriCert); got != "" {
		t.Fatalf("foreign spiffe URI = %q", got)
	}
}

func TestParseCertPEMAndValidity(t *testing.T) {
	if _, err := ParseCertPEM([]byte("junk")); err == nil {
		t.Fatal("junk PEM must fail")
	}
	if _, err := ParseCertPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})); err == nil {
		t.Fatal("non-certificate PEM block must fail")
	}
	if _, err := ParseCertPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})); err == nil {
		t.Fatal("undecodable certificate must fail")
	}
	if CertValidFor([]byte("junk"), time.Hour) {
		t.Fatal("unparsable PEM must not be valid")
	}

	ca, err := NewCA("ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !CertValidFor(caCertPEM(t, ca), time.Minute) {
		t.Fatal("fresh CA certificate must be valid")
	}
	if CertValidFor(caCertPEM(t, ca), 2*time.Hour) {
		t.Fatal("certificate must not be valid beyond its lifetime")
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	future := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "future"},
		NotBefore:    now.Add(time.Hour),
		NotAfter:     now.Add(2 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, future, future, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if CertValidFor(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), time.Minute) {
		t.Fatal("not-yet-valid certificate must not be valid")
	}
}

func TestGenerateKeyAndCSRInvalidUTF8ID(t *testing.T) {
	if _, _, err := GenerateKeyAndCSR("bad\xff"); err == nil {
		t.Fatal("invalid UTF-8 runner id must fail CSR generation")
	}
}

func TestTLSServerConfigClientAuthModes(t *testing.T) {
	certPEM, keyPEM := selfSignedServerCert(t)

	cfg, err := TLSServerConfig(certPEM, keyPEM, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("no CA without requirement = %v", cfg.ClientAuth)
	}

	ca, err := NewCA("ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = TLSServerConfig(certPEM, keyPEM, ca, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("optional client certs = %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("client CA pool must be populated")
	}

	nilCertCA := &CA{}
	if _, err := TLSServerConfig(certPEM, keyPEM, nilCertCA, true); err == nil {
		t.Fatal("CA without a certificate must be treated as missing")
	}
}
