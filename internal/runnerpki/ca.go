// Package runnerpki implements the runner public-key infrastructure: a
// self-signed Ed25519 certificate authority that signs runner client
// certificates from CSRs and verifies peer certificates for mTLS identity
// binding between runners and the control plane.
package runnerpki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"
	// RunnerURIPrefix is the SPIFFE-style URI prefix embedded in every runner
	// certificate: spiffe://kiwi/runner/<runnerID>.
	RunnerURIPrefix = "spiffe://kiwi/runner/"
)

// CA is an Ed25519 certificate authority for runner certificates.
type CA struct {
	Cert *x509.Certificate
	Key  ed25519.PrivateKey
}

// NewCA creates a self-signed Ed25519 CA with the given common name and
// validity period. A non-positive ttl defaults to one year.
func NewCA(commonName string, ttl time.Duration) (*CA, error) {
	if ttl <= 0 {
		ttl = 24 * 365 * time.Hour
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randInt()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: priv}, nil
}

// LoadCA parses a CA certificate and its Ed25519 PKCS8 private key from
// PEM and verifies that the loaded key actually signs for the loaded
// certificate (an Ed25519 sign/verify round trip over the certificate
// bytes). A mismatched pair is a startup error: a CA whose key does not
// correspond to its certificate could never sign verifiable leaves.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid CA private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA private key is not Ed25519")
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("CA certificate public key is not Ed25519")
	}
	// The loaded private key must sign for the loaded certificate: this
	// detects half-restored key material (e.g. a backup mixing two CAs).
	sig := ed25519.Sign(key, cert.Raw)
	if !ed25519.Verify(pub, cert.Raw, sig) {
		return nil, fmt.Errorf("CA private key does not match the certificate")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// LoadOrCreateCA loads ca.crt/ca.key (PEM, PKCS8 private key) from dir,
// generating and persisting a fresh CA on first use.
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		ca, err := LoadCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("load runner CA: %w", err)
		}
		return ca, nil
	}
	if certErr != nil && !os.IsNotExist(certErr) {
		return nil, certErr
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return nil, keyErr
	}
	ca, err := NewCA("kiwi runner CA", 0)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	if err := writeFileAtomic(certPath, certOut, 0o644); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return nil, err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeFileAtomic(keyPath, keyOut, 0o600); err != nil {
		return nil, err
	}
	return ca, nil
}

// SignRunnerCSR signs a runner certificate request, issuing a client-only
// certificate whose identity is synthesized by the SERVER: CN=runnerID and
// the spiffe://kiwi/runner/<runnerID> URI SAN. The CSR is used solely as a
// proof-of-possession vehicle for the runner's public key — its own
// subject, SANs, email/DNS/IP entries and other requester-controlled
// identity fields are discarded entirely. Each leaf gets a fresh random
// 128-bit serial (crypto/rand, no process-local counters), and the
// extended key usage is ClientAuth only: the certificate cannot
// authenticate a server.
func (c *CA) SignRunnerCSR(csrPEM []byte, runnerID string, ttl time.Duration, extraSans []string) ([]byte, error) {
	if c == nil || c.Cert == nil {
		return nil, fmt.Errorf("runner CA not configured")
	}
	if runnerID == "" {
		return nil, fmt.Errorf("runner id is required")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}
	// Server-synthesized identity: the requester's CSR identity fields
	// (CN, SANs, ...) never reach the certificate.
	uris := []*url.URL{{Scheme: "spiffe", Host: "kiwi", Path: "/runner/" + runnerID}}
	for _, s := range extraSans {
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" {
			return nil, fmt.Errorf("invalid extra SAN URI %q", s)
		}
		uris = append(uris, u)
	}
	if ttl <= 0 {
		ttl = 24 * 365 * time.Hour
	}
	serial, err := randInt()
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: runnerID},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, csr.PublicKey, c.Key)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// VerifyPeer checks that a peer certificate is a valid runner client
// certificate chaining to roots and extracts the runner ID it identifies
// (common name, falling back to the spiffe://kiwi/runner/<id> URI).
func (c *CA) VerifyPeer(peer *x509.Certificate, roots *x509.CertPool) (string, error) {
	if peer == nil {
		return "", fmt.Errorf("no peer certificate")
	}
	if roots == nil {
		return "", fmt.Errorf("no trust roots")
	}
	if len(peer.ExtKeyUsage) > 0 && !hasEKU(peer.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return "", fmt.Errorf("peer certificate is not valid for client authentication")
	}
	if _, err := peer.Verify(x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		return "", fmt.Errorf("peer certificate verification failed: %w", err)
	}
	return RunnerIDFromCert(peer), nil
}

// RunnerIDFromCert extracts the runner ID from a certificate's common name
// or spiffe://kiwi/runner/<id> URI.
func RunnerIDFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cn := cert.Subject.CommonName; cn != "" {
		return cn
	}
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" && u.Host == "kiwi" && strings.HasPrefix(u.Path, "/runner/") {
			return strings.TrimPrefix(u.Path, "/runner/")
		}
	}
	return ""
}

func hasEKU(list []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func randInt() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return n, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
