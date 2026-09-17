package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// Signing-key separation: the control plane holds four distinct persisted
// trust roots that must never share key material or storage files:
//
//   - the OIDC signing key (oidc.go: oidc-keyring.json),
//   - the artifact provenance key (provenance.key/provenance.pub, loaded
//     through provenance.LoadOrCreateProvenanceKey),
//   - the cache manifest signing key (cache-signing.key/cache-signing.pem),
//   - the web session HMAC secret (web-session.key).
//
// Artifact provenance uploads sign with the provenance key only; the OIDC
// key is never used for attestation material, so rotating or publishing
// the OIDC JWKS cannot affect the provenance trust root.

const (
	cacheSigningKeyFile = "cache-signing.key"
	cacheSigningPubFile = "cache-signing.pem"
	webSessionKeyFile   = "web-session.key"
)

// cacheSigner is the cache manifest Ed25519 signing key with its key id.
type cacheSigner struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	KID     string
}

// provenanceSigner is the artifact provenance Ed25519 signing key with its
// key id (the id is derived from the public key hash, distinct from the
// random OIDC KIDs).
type provenanceSigner struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	KID     string
}

func newEphemeralEd25519() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(randReader)
	if err != nil {
		panic("kiwi server: failed to generate Ed25519 key: " + err.Error())
	}
	return pub, priv
}

// kidForPublicKey derives the stable key id from a public key hash.
func kidForPublicKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// loadProvenanceKey loads the persisted provenance key from dataDir or
// generates and persists a fresh pair on first use. A non-persistent
// server (empty dataDir) gets an ephemeral pair that is still distinct
// from every other signing root.
func (s *Server) loadProvenanceKey(dataDir string) error {
	if dataDir != "" {
		pub, priv, err := provenance.LoadOrCreateProvenanceKey(dataDir)
		if err != nil {
			return fmt.Errorf("provenance key: %w", err)
		}
		s.provenance = &provenanceSigner{Private: priv, Public: pub, KID: kidForPublicKey(pub)}
		return nil
	}
	pub, priv := newEphemeralEd25519()
	s.provenance = &provenanceSigner{Private: priv, Public: pub, KID: kidForPublicKey(pub)}
	return nil
}

// ensureProvenanceKey installs an ephemeral provenance key when none has
// been loaded (bare &Server{} construction in tests).
func (s *Server) ensureProvenanceKey() *provenanceSigner {
	if s.provenance == nil {
		pub, priv := newEphemeralEd25519()
		s.provenance = &provenanceSigner{Private: priv, Public: pub, KID: kidForPublicKey(pub)}
	}
	return s.provenance
}

func encodeEd25519PrivatePEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func encodeEd25519PublicPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// loadCacheSigner loads the persisted cache manifest signing key from
// dataDir or generates and persists a fresh pair on first use. Ephemeral
// servers get a process-local pair.
func (s *Server) loadCacheSigner(dataDir string) error {
	if dataDir == "" {
		pub, priv := newEphemeralEd25519()
		s.cacheSigner = &cacheSigner{Private: priv, Public: pub, KID: kidForPublicKey(pub)}
		return nil
	}
	keyPath := filepath.Join(dataDir, cacheSigningKeyFile)
	pubPath := filepath.Join(dataDir, cacheSigningPubFile)
	keyPEM, keyErr := os.ReadFile(keyPath)
	pubPEM, pubErr := os.ReadFile(pubPath)
	if keyErr == nil && pubErr == nil {
		priv, err := parseEd25519PrivatePEM(keyPEM)
		if err != nil {
			return fmt.Errorf("cache signing key: %w", err)
		}
		pub, err := parseEd25519PublicPEM(pubPEM)
		if err != nil {
			return fmt.Errorf("cache signing public key: %w", err)
		}
		if !pub.Equal(priv.Public().(ed25519.PublicKey)) {
			return fmt.Errorf("cache signing key pair in %s does not match", dataDir)
		}
		s.cacheSigner = &cacheSigner{Private: priv, Public: pub, KID: kidForPublicKey(pub)}
		return nil
	}
	if keyErr == nil || pubErr == nil {
		return fmt.Errorf("incomplete cache signing key pair in %s", dataDir)
	}
	pub, priv := newEphemeralEd25519()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	keyOut, err := encodeEd25519PrivatePEM(priv)
	if err != nil {
		return err
	}
	pubOut, err := encodeEd25519PublicPEM(pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, pubOut, 0o644); err != nil {
		return err
	}
	s.cacheSigner = &cacheSigner{Private: priv, Public: pub, KID: kidForPublicKey(pub)}
	return nil
}

func (s *Server) ensureCacheSigner() *cacheSigner {
	if s.cacheSigner == nil {
		pub, priv := newEphemeralEd25519()
		s.cacheSigner = &cacheSigner{Private: priv, Public: pub, KID: kidForPublicKey(pub)}
	}
	return s.cacheSigner
}

// loadWebSessionSecret loads the persisted web session HMAC secret from
// dataDir, falling back to the KIWI_WEB_SESSION_SECRET environment variable
// and finally generating and persisting a fresh key on first use. It runs
// at NewPersistent time so restarts keep existing sessions valid.
func (s *Server) loadWebSessionSecret(dataDir string) error {
	path := ""
	if dataDir != "" {
		path = filepath.Join(dataDir, webSessionKeyFile)
		if b, err := os.ReadFile(path); err == nil {
			raw, derr := hex.DecodeString(strings.TrimSpace(string(b)))
			if derr == nil && len(raw) == 32 {
				s.WebSessionSecret = raw
				return nil
			}
			if derr == nil {
				return fmt.Errorf("web session secret in %s has invalid size", path)
			}
			return fmt.Errorf("web session secret in %s is not hex: %w", path, derr)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if raw := strings.TrimSpace(os.Getenv("KIWI_WEB_SESSION_SECRET")); raw != "" {
		if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
			s.WebSessionSecret = b
			return nil
		}
	}
	b := make([]byte, 32)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return err
	}
	s.WebSessionSecret = b
	if path != "" {
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return err
		}
		return writeFileAtomic(path, []byte(hex.EncodeToString(b)), 0o600)
	}
	return nil
}

func parseEd25519PrivatePEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return priv, nil
}

func parseEd25519PublicPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid public key PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return pub, nil
}

// writeFileAtomic writes data to path via a temp file and rename so a crash
// mid-write can never leave a truncated key file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

// marshalJSONFile is a small shared helper for atomic JSON persistence of
// server-owned state files (schedules, CRL, test history).
func marshalJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o600)
}

// readFileIfExists returns the file contents or nil when the file does not
// exist.
func readFileIfExists(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func joinDataDir(dir, name string) string { return filepath.Join(dir, name) }
