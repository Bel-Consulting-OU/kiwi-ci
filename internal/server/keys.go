package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
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
//
// The first-use write is a startup gate: a pre-rename failure leaves the
// previous (here: absent) file intact and a post-rename directory-fsync
// failure leaves the new secret visible but not certified durable
// (fsutil.Renamed). Either way the error propagates and construction fails
// closed — no server is ever built on a session secret it might not be able
// to reuse after a crash — and a later start loads the visible file, so the
// published-uncertain case converges instead of forking the secret.
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
		return fsutil.AtomicWriteFile(path, []byte(hex.EncodeToString(b)), 0o600)
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

// marshalJSONFile is the shared durable JSON persistence helper for
// server-owned security state files (the runner CRL mirror, enrollment
// grants, secret receipts, test history). It delegates to
// fsutil.AtomicWriteFile, whose real sequence is: a UNIQUE temp file in the
// destination directory (os.CreateTemp), write, chmod 0600, checked file
// fsync, checked close, rename over the destination, and a parent-directory
// fsync.
//
// The returned error is a typed *fsutil.AtomicWriteError, and its phase is
// what decides how a caller may react:
//
//   - create/write/chmod/file-sync/close/rename failures happen BEFORE the
//     rename, so the new bytes were definitely not published: the temp file
//     is removed, the previous file at path is bit-for-bit intact (it was
//     never touched), and the caller keeps its existing rollback behavior.
//   - the parent-directory fsync runs AFTER the rename, so its failure means
//     the new bytes ARE visible at path with uncertified crash durability
//     (fsutil.ErrPublishedUncertain, fsutil.Renamed(err) == true). A caller
//     must not read that as "the previous file is intact": for a
//     security-monotonic mutation it must retain the published (more
//     restrictive) state and leave readiness degraded
//     (noteFilePersistResult) until a later successful persist reconciles.
//
// The unique temp name keeps concurrent writers from clobbering each other.
func marshalJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(path, append(b, '\n'), 0o600)
}

// degradedReadiness is the composite degraded signal consumed by /readiness
// and the lease gate. It is armed by the fs snapshot's own persist outcome
// (snapshot) OR by any directory that holds a published-but-uncertified
// security-state file (dirs). Load reports the OR, so the historical
// stateDegraded.Load() call sites keep working while the two causes can be
// cleared independently: a successful snapshot persist clears only snapshot,
// and a successful security-state persist clears only its own directory.
type degradedReadiness struct {
	snapshot atomic.Bool
	dirs     persistDirSet
}

func (d *degradedReadiness) Load() bool {
	return d.snapshot.Load() || d.dirs.any()
}

func (d *degradedReadiness) Store(v bool) { d.snapshot.Store(v) }

// persistDirSet tracks the canonical parent directories in which a durable
// security-state file was published but its crash durability could not be
// certified. A directory fsync flushes only that directory's metadata, so
// uncertainty is cleared only by a successful persist/fsync in the SAME
// directory; a successful write elsewhere must not heal it.
type persistDirSet struct {
	mu sync.Mutex
	m  map[string]struct{}
}

// arm marks dir uncertain and reports whether it was newly armed.
func (d *persistDirSet) arm(dir string) (newly bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = map[string]struct{}{}
	}
	if _, ok := d.m[dir]; ok {
		return false
	}
	d.m[dir] = struct{}{}
	return true
}

// clear drops dir's uncertainty (a successful persist/fsync in that dir).
func (d *persistDirSet) clear(dir string) {
	d.mu.Lock()
	delete(d.m, dir)
	d.mu.Unlock()
}

func (d *persistDirSet) any() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.m) > 0
}

// list returns the uncertain directories sorted, for deterministic
// reporting.
func (d *persistDirSet) list() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.m) == 0 {
		return nil
	}
	out := make([]string, 0, len(d.m))
	for dir := range d.m {
		out = append(out, dir)
	}
	sort.Strings(out)
	return out
}

// noteFilePersistResult folds the outcome of one durable security-state file
// write into the PER-DIRECTORY uncertainty set (not the snapshot's own
// stateDegraded bit): a directory fsync only flushes the metadata of its own
// directory, so a successful write in an unrelated directory must not clear
// the uncertainty left by a different one.
//
//   - success clears uncertainty for filepath.Dir(path): the state in THAT
//     directory has been re-persisted, so an earlier published-but-uncertified
//     write there is reconciled;
//   - a published-but-uncertified failure (fsutil.Renamed) arms uncertainty
//     for filepath.Dir(path): the new bytes are visible at the destination
//     while their crash durability is unproven, so /readiness must fail
//     closed until a successful persist/fsync in that same directory;
//   - a pre-rename failure leaves the set untouched: nothing observable
//     changed on disk, and the caller keeps its existing rollback behavior.
//
// When path is empty the directory is recovered from a typed
// *fsutil.AtomicWriteError's Path, so a caller that only has the error still
// attributes the uncertainty correctly; an error with no attributable
// directory (a pure in-memory or DB failure) is ignored. The fixed
// /readiness body is preserved: the uncertain directories are reported to
// the structured log, never on the unauthenticated probe.
func (s *Server) noteFilePersistResult(path string, err error) {
	dir := canonicalPersistDir(path)
	if dir == "" {
		var awe *fsutil.AtomicWriteError
		if errors.As(err, &awe) {
			dir = canonicalPersistDir(awe.Path)
		}
	}
	if dir == "" {
		return
	}
	if err == nil {
		s.stateDegraded.dirs.clear(dir)
		return
	}
	if !fsutil.Renamed(err) {
		return
	}
	if s.stateDegraded.dirs.arm(dir) {
		s.logError("state persistence uncertainty armed for directory; readiness degraded until a same-directory persist succeeds", "dir", dir, "error", err.Error())
	}
}

// canonicalPersistDir normalizes the parent directory of a durable-state file
// path so two spellings of the same directory share one uncertainty slot.
func canonicalPersistDir(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Clean(filepath.Dir(path))
}

// uncertainPersistDirs returns the canonical directories holding at least one
// published-but-uncertified security-state file, sorted for deterministic
// reporting.
func (s *Server) uncertainPersistDirs() []string {
	return s.stateDegraded.dirs.list()
}

// persistenceDegraded reports whether /readiness must fail closed: either the
// fs snapshot itself is not durable or some security-state file was published
// without certified crash durability in its directory.
func (s *Server) persistenceDegraded() bool {
	return s.stateDegraded.Load()
}

// oidcPersistPath returns the filesystem path the OIDC ring is (or would be)
// persisted to, for per-directory uncertainty attribution: the signer's own
// ring path in file mode, the FS cluster store's ring path when the signer
// persists through one, and empty for a DB-backed or in-memory ring (nothing
// directory-scoped to track).
func (s *Server) oidcPersistPath(signer *oidcSigner) string {
	if signer != nil {
		if signer.ringPath != "" {
			return signer.ringPath
		}
		if fs, ok := signer.cluster.(*FSClusterKeyStore); ok {
			if p, err := fs.path(clusterKindOIDC); err == nil {
				return p
			}
		}
	}
	if fs, ok := s.ClusterKeys.(*FSClusterKeyStore); ok {
		if p, err := fs.path(clusterKindOIDC); err == nil {
			return p
		}
	}
	return ""
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
