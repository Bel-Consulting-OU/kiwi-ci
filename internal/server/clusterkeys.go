package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// Cluster key kinds: every signing/encryption material the control plane
// holds can be shared across replicas through a ClusterKeyStore so an HA
// deployment's replicas verify each other's tokens and signatures.
const (
	clusterKindLease        = "lease"
	clusterKindOIDC         = "oidc"
	clusterKindProvenance   = "provenance"
	clusterKindCacheSigning = "cache-signing"
	clusterKindWebSession   = "web-session"
	clusterKindRunnerCA     = "runner-ca"
)

// ClusterKeyStore loads a shared key material by kind, creating and
// persisting it on first use. Implementations must be safe for concurrent
// use and must return the same bytes for the same kind across all replicas
// of the control plane.
type ClusterKeyStore interface {
	LoadOrCreate(kind string) ([]byte, error)
}

// ClusterKeyWriter optionally persists updates to a key material (OIDC key
// rotation). Stores that do not implement it cannot rotate the OIDC ring
// durably; the rotation is logged and the in-memory signer still rotates.
type ClusterKeyWriter interface {
	Store(kind string, data []byte) error
}

// ClusterKeyLookup optionally reports whether a kind already exists without
// creating it. The runner CA loader uses it to keep the legacy behavior of
// not materializing a CA unless one is configured.
type ClusterKeyLookup interface {
	Lookup(kind string) ([]byte, bool, error)
}

// FSClusterKeyStore persists one file per kind under Dir with mode 0600.
// File names and formats match the legacy data-dir layout so an existing
// deployment's keys keep working unchanged:
//
//	lease         lease.key             hex(32 raw bytes)
//	oidc          oidc-keyring.json     the OIDC key ring JSON
//	provenance    provenance.key        PKCS8 PEM (provenance.pub sidecar)
//	cache-signing cache-signing.key     PKCS8 PEM (cache-signing.pem sidecar)
//	web-session   web-session.key       hex(32 raw bytes)
//	runner-ca     ca.crt + ca.key       cert PEM + key PEM concatenated
type FSClusterKeyStore struct {
	Dir string
}

// StaticClusterKeyStore is an in-memory ClusterKeyStore for tests and
// single-process deployments: LoadOrCreate returns the stored bytes or
// creates them with New (defaulting to the server's creators).
type StaticClusterKeyStore struct {
	mu   sync.Mutex
	Keys map[string][]byte
	New  func(kind string) ([]byte, error)
}

var (
	_ ClusterKeyStore  = (*FSClusterKeyStore)(nil)
	_ ClusterKeyWriter = (*FSClusterKeyStore)(nil)
	_ ClusterKeyLookup = (*FSClusterKeyStore)(nil)
	_ ClusterKeyStore  = (*StaticClusterKeyStore)(nil)
	_ ClusterKeyWriter = (*StaticClusterKeyStore)(nil)
	_ ClusterKeyLookup = (*StaticClusterKeyStore)(nil)
)

// ---------------------------------------------------------------------------
// key material creators (shared by both store implementations)
// ---------------------------------------------------------------------------

// createClusterKey returns fresh material for kind in its canonical wire
// format. The server-side loaders parse these bytes.
func createClusterKey(kind string) ([]byte, error) {
	switch kind {
	case clusterKindLease:
		return newLeaseKey()
	case clusterKindOIDC:
		signer := newOIDCSigner()
		rf := oidcKeyRingJSON{
			Active: oidcActiveKeyFile{
				KID:       signer.KID,
				Pub:       base64.RawStdEncoding.EncodeToString(signer.Public),
				Priv:      base64.RawStdEncoding.EncodeToString(signer.Private),
				NotBefore: signer.NotBefore.UTC().Format(time.RFC3339Nano),
			},
		}
		return json.MarshalIndent(rf, "", "  ")
	case clusterKindProvenance, clusterKindCacheSigning:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return encodeEd25519PrivatePEM(priv)
	case clusterKindWebSession:
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		return b, nil
	case clusterKindRunnerCA:
		ca, err := runnerpki.NewCA("kiwi runner CA", 0)
		if err != nil {
			return nil, err
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
		keyDER, err := encodeEd25519PrivatePEM(ca.Key)
		if err != nil {
			return nil, err
		}
		return append(append([]byte{}, certPEM...), keyDER...), nil
	default:
		return nil, fmt.Errorf("cluster keys: unknown key kind %q", kind)
	}
}

// createWebSessionKey honors the KIWI_WEB_SESSION_SECRET env override before
// generating, matching the legacy loader's precedence.
func createWebSessionKey() ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv("KIWI_WEB_SESSION_SECRET")); raw != "" {
		if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ---------------------------------------------------------------------------
// FSClusterKeyStore
// ---------------------------------------------------------------------------

func (s *FSClusterKeyStore) path(kind string) (string, error) {
	if s.Dir == "" {
		return "", errors.New("cluster keys: empty filesystem store directory")
	}
	switch kind {
	case clusterKindLease:
		return filepath.Join(s.Dir, "lease.key"), nil
	case clusterKindOIDC:
		return filepath.Join(s.Dir, oidcKeyRingFile), nil
	case clusterKindProvenance:
		return filepath.Join(s.Dir, "provenance.key"), nil
	case clusterKindCacheSigning:
		return filepath.Join(s.Dir, cacheSigningKeyFile), nil
	case clusterKindWebSession:
		return filepath.Join(s.Dir, webSessionKeyFile), nil
	case clusterKindRunnerCA:
		return filepath.Join(s.Dir, "ca.crt"), nil
	default:
		return "", fmt.Errorf("cluster keys: unknown key kind %q", kind)
	}
}

func (s *FSClusterKeyStore) LoadOrCreate(kind string) ([]byte, error) {
	if existing, ok, err := s.Lookup(kind); err != nil {
		return nil, err
	} else if ok {
		return existing, nil
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	if kind == clusterKindRunnerCA {
		// The runner CA loader materializes cert+key through its own
		// create-if-absent flow; the persisted files are the source of
		// truth and are read back below.
		if _, err := runnerpki.LoadOrCreateCA(s.Dir); err != nil {
			return nil, err
		}
		certPEM, cerr := os.ReadFile(filepath.Join(s.Dir, "ca.crt"))
		if cerr != nil {
			return nil, cerr
		}
		keyPEM, cerr := os.ReadFile(filepath.Join(s.Dir, "ca.key"))
		if cerr != nil {
			return nil, cerr
		}
		return append(append([]byte{}, certPEM...), keyPEM...), nil
	}
	var created []byte
	var err error
	switch kind {
	case clusterKindWebSession:
		created, err = createWebSessionKey()
	default:
		created, err = createClusterKey(kind)
	}
	if err != nil {
		return nil, err
	}
	// Atomic create-if-absent: the hard link is the CAS primitive. Only the
	// creator whose link won returns its freshly generated material; every
	// concurrent creator whose link hit EEXIST re-reads the winning file,
	// so freshly generated material is NEVER returned when the file
	// already exists.
	enc, err := s.encodedBytes(kind, created)
	if err != nil {
		return nil, err
	}
	path, err := s.path(kind)
	if err != nil {
		return nil, err
	}
	if err := createFileCAS(path, enc); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		existing, ok, lerr := s.Lookup(kind)
		if lerr != nil {
			return nil, lerr
		}
		if !ok {
			return nil, fmt.Errorf("cluster keys: %s was created concurrently but cannot be read", kind)
		}
		return existing, nil
	}
	// Sidecar publications for key-pair kinds are best effort after the
	// CAS link: the key file is authoritative and a missing public sidecar
	// is tolerated by Lookup.
	if kind == clusterKindProvenance || kind == clusterKindCacheSigning {
		priv, perr := parseEd25519PrivatePEM(created)
		if perr != nil {
			return nil, perr
		}
		pub, perr := encodeEd25519PublicPEM(priv.Public().(ed25519.PublicKey))
		if perr != nil {
			return nil, perr
		}
		pubPath := filepath.Join(s.Dir, "provenance.pub")
		if kind == clusterKindCacheSigning {
			pubPath = filepath.Join(s.Dir, cacheSigningPubFile)
		}
		if perr := writeFileAtomic(pubPath, pub, 0o644); perr != nil {
			return nil, perr
		}
	}
	return created, nil
}

// encodedBytes renders the canonical on-disk encoding for one kind without
// touching the filesystem (hex for raw 32-byte material, identity for the
// self-describing formats).
func (s *FSClusterKeyStore) encodedBytes(kind string, data []byte) ([]byte, error) {
	switch kind {
	case clusterKindLease, clusterKindWebSession:
		return []byte(hex.EncodeToString(data)), nil
	case clusterKindOIDC, clusterKindProvenance, clusterKindCacheSigning:
		return data, nil
	default:
		return nil, fmt.Errorf("cluster keys: unknown key kind %q", kind)
	}
}

// createFileCAS publishes data at path with create-if-absent semantics: the
// bytes are written to a unique temp file, fsynced, and hard-linked into
// place. A link racing an existing file fails with os.ErrExist. On Windows
// (where hard links can be unsupported on some filesystems) the O_CREATE|
// O_EXCL fallback is used instead.
func createFileCAS(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".cas-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	if err := os.Link(tmpName, path); err != nil {
		if os.IsExist(err) {
			return os.ErrExist
		}
		return err
	}
	return nil
}

// Lookup reports the stored bytes for kind without creating anything.
func (s *FSClusterKeyStore) Lookup(kind string) ([]byte, bool, error) {
	switch kind {
	case clusterKindLease, clusterKindWebSession:
		p, err := s.path(kind)
		if err != nil {
			return nil, false, err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, false, nil
			}
			return nil, false, err
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != 32 {
			return nil, false, fmt.Errorf("cluster keys: invalid %s in %s", kind, p)
		}
		return raw, true, nil
	case clusterKindOIDC:
		p := filepath.Join(s.Dir, oidcKeyRingFile)
		b, err := os.ReadFile(p)
		if err == nil {
			return b, true, nil
		}
		if !os.IsNotExist(err) {
			return nil, false, err
		}
		// Migrate the legacy single-key file so existing deployments keep
		// their OIDC trust root. The migrated ring is persisted immediately
		// so the legacy file is never consulted again.
		legacy, lerr := legacyOIDCRingBytes(s.Dir)
		if lerr != nil {
			if os.IsNotExist(lerr) {
				return nil, false, nil
			}
			return nil, false, lerr
		}
		if werr := writeFileAtomic(p, legacy, 0o600); werr != nil {
			return nil, false, werr
		}
		return legacy, true, nil
	case clusterKindProvenance, clusterKindCacheSigning:
		p, err := s.path(kind)
		if err != nil {
			return nil, false, err
		}
		keyPEM, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, false, nil
			}
			return nil, false, err
		}
		priv, perr := parseEd25519PrivatePEM(keyPEM)
		if perr != nil {
			return nil, false, perr
		}
		// Validate the public sidecar when present (matching the legacy
		// loader's pair check) so a torn write is caught at startup.
		var pubPath string
		switch kind {
		case clusterKindProvenance:
			pubPath = filepath.Join(s.Dir, "provenance.pub")
		case clusterKindCacheSigning:
			pubPath = filepath.Join(s.Dir, cacheSigningPubFile)
		}
		if pubPEM, perr := os.ReadFile(pubPath); perr == nil {
			pub, perr := parseEd25519PublicPEM(pubPEM)
			if perr != nil || !pub.Equal(priv.Public().(ed25519.PublicKey)) {
				return nil, false, fmt.Errorf("cluster keys: %s key pair does not match", kind)
			}
		}
		return keyPEM, true, nil
	case clusterKindRunnerCA:
		certPEM, certErr := os.ReadFile(filepath.Join(s.Dir, "ca.crt"))
		keyPEM, keyErr := os.ReadFile(filepath.Join(s.Dir, "ca.key"))
		if certErr != nil || keyErr != nil {
			return nil, false, nil
		}
		return append(append([]byte{}, certPEM...), keyPEM...), true, nil
	default:
		return nil, false, fmt.Errorf("cluster keys: unknown key kind %q", kind)
	}
}

func (s *FSClusterKeyStore) Store(kind string, data []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	switch kind {
	case clusterKindLease, clusterKindWebSession:
		p, err := s.path(kind)
		if err != nil {
			return err
		}
		return writeFileAtomic(p, []byte(hex.EncodeToString(data)), 0o600)
	case clusterKindOIDC:
		return writeFileAtomic(filepath.Join(s.Dir, oidcKeyRingFile), data, 0o600)
	case clusterKindProvenance:
		if err := writeFileAtomic(filepath.Join(s.Dir, "provenance.key"), data, 0o600); err != nil {
			return err
		}
		priv, err := parseEd25519PrivatePEM(data)
		if err != nil {
			return err
		}
		pub, err := encodeEd25519PublicPEM(priv.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		return writeFileAtomic(filepath.Join(s.Dir, "provenance.pub"), pub, 0o644)
	case clusterKindCacheSigning:
		if err := writeFileAtomic(filepath.Join(s.Dir, cacheSigningKeyFile), data, 0o600); err != nil {
			return err
		}
		priv, err := parseEd25519PrivatePEM(data)
		if err != nil {
			return err
		}
		pub, err := encodeEd25519PublicPEM(priv.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		return writeFileAtomic(filepath.Join(s.Dir, cacheSigningPubFile), pub, 0o644)
	case clusterKindRunnerCA:
		certPEM, keyPEM, err := splitRunnerCAPEMs(data)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(filepath.Join(s.Dir, "ca.crt"), certPEM, 0o644); err != nil {
			return err
		}
		return writeFileAtomic(filepath.Join(s.Dir, "ca.key"), keyPEM, 0o600)
	default:
		return fmt.Errorf("cluster keys: unknown key kind %q", kind)
	}
}

// ---------------------------------------------------------------------------
// StaticClusterKeyStore
// ---------------------------------------------------------------------------

// LoadOrCreate returns the stored bytes for kind, creating them when
// absent. Creation is race-free: the map is re-checked under the lock after
// the (potentially expensive) key generation, and the STORED value is
// always returned — a concurrent creator's material wins when the call lost
// the race, so freshly generated material is never returned when the store
// already holds a value.
func (s *StaticClusterKeyStore) LoadOrCreate(kind string) ([]byte, error) {
	s.mu.Lock()
	if s.Keys != nil {
		if b, ok := s.Keys[kind]; ok {
			out := append([]byte(nil), b...)
			s.mu.Unlock()
			return out, nil
		}
	}
	s.mu.Unlock()
	newFn := s.New
	if newFn == nil {
		newFn = func(kind string) ([]byte, error) {
			if kind == clusterKindWebSession {
				return createWebSessionKey()
			}
			return createClusterKey(kind)
		}
	}
	b, err := newFn(kind)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Keys != nil {
		if existing, ok := s.Keys[kind]; ok {
			// Lost the race to a concurrent creator: the stored material
			// is authoritative.
			return append([]byte(nil), existing...), nil
		}
	}
	if s.Keys == nil {
		s.Keys = map[string][]byte{}
	}
	s.Keys[kind] = append([]byte(nil), b...)
	return append([]byte(nil), b...), nil
}

func (s *StaticClusterKeyStore) Lookup(kind string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Keys == nil {
		return nil, false, nil
	}
	b, ok := s.Keys[kind]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), b...), true, nil
}

func (s *StaticClusterKeyStore) Store(kind string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Keys == nil {
		s.Keys = map[string][]byte{}
	}
	s.Keys[kind] = append([]byte(nil), data...)
	return nil
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// legacyOIDCRingBytes migrates the legacy oidc-ed25519.key single-key file
// into the ring format. It returns an *os.PathError when the file is absent.
func legacyOIDCRingBytes(dir string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, oidcLegacyKeyFile))
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid OIDC signing key size")
	}
	priv := ed25519.PrivateKey(raw)
	pub := priv.Public().(ed25519.PublicKey)
	signer := signerFromKeys(pub, priv)
	rf := oidcKeyRingJSON{
		Active: oidcActiveKeyFile{
			KID:       signer.KID,
			Pub:       base64.RawStdEncoding.EncodeToString(pub),
			Priv:      base64.RawStdEncoding.EncodeToString(priv),
			NotBefore: signer.NotBefore.UTC().Format(time.RFC3339Nano),
		},
	}
	return json.MarshalIndent(rf, "", "  ")
}

// splitRunnerCAPEMs splits a concatenated certPEM+keyPEM blob back into its
// two PEM documents.
func splitRunnerCAPEMs(data []byte) (certPEM, keyPEM []byte, err error) {
	i := indexOfPEMBoundary(data, "CERTIFICATE")
	if i < 0 {
		return nil, nil, fmt.Errorf("cluster keys: runner CA blob missing certificate")
	}
	j := indexOfPEMBoundary(data, "PRIVATE KEY")
	if j < 0 {
		return nil, nil, fmt.Errorf("cluster keys: runner CA blob missing private key")
	}
	if j < i {
		return nil, nil, fmt.Errorf("cluster keys: runner CA blob malformed")
	}
	return data[i:j], data[j:], nil
}

// indexOfPEMBoundary returns the byte offset of the PEM start line of the
// given block type.
func indexOfPEMBoundary(data []byte, blockType string) int {
	needle := "-----BEGIN " + blockType + "-----"
	idx := strings.Index(string(data), needle)
	if idx < 0 {
		return -1
	}
	return idx
}

// keyFingerprintRaw derives the stable key id for one raw/public key
// material: hex(sha256(material)) truncated to 16 bytes.
func keyFingerprintRaw(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// ---------------------------------------------------------------------------
// server-side cluster loaders
// ---------------------------------------------------------------------------

func (s *Server) loadLeaseKeyCluster(store ClusterKeyStore) error {
	b, err := store.LoadOrCreate(clusterKindLease)
	if err != nil {
		return fmt.Errorf("cluster lease key: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("cluster lease key: invalid size %d", len(b))
	}
	s.leaseKey = append([]byte(nil), b...)
	return nil
}

func (s *Server) loadOIDCSignerCluster(store ClusterKeyStore) (*oidcSigner, error) {
	b, err := store.LoadOrCreate(clusterKindOIDC)
	if err != nil {
		return nil, fmt.Errorf("cluster oidc key ring: %w", err)
	}
	signer, err := oidcSignerFromRing(b)
	if err != nil {
		return nil, err
	}
	signer.cluster = store
	sum := sha256.Sum256(b)
	signer.ringDigest = hex.EncodeToString(sum[:])
	return signer, nil
}

func (s *Server) loadProvenanceCluster(store ClusterKeyStore) error {
	b, err := store.LoadOrCreate(clusterKindProvenance)
	if err != nil {
		return fmt.Errorf("cluster provenance key: %w", err)
	}
	priv, err := parseEd25519PrivatePEM(b)
	if err != nil {
		return fmt.Errorf("cluster provenance key: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	s.provenance = &provenanceSigner{Private: priv, Public: pub, KID: kidForPublicKey(pub)}
	return nil
}

func (s *Server) loadCacheSignerCluster(store ClusterKeyStore) error {
	b, err := store.LoadOrCreate(clusterKindCacheSigning)
	if err != nil {
		return fmt.Errorf("cluster cache signing key: %w", err)
	}
	priv, err := parseEd25519PrivatePEM(b)
	if err != nil {
		return fmt.Errorf("cluster cache signing key: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	s.cacheSigner = &cacheSigner{Private: priv, Public: pub, KID: kidForPublicKey(pub)}
	return nil
}

func (s *Server) loadWebSessionCluster(store ClusterKeyStore) error {
	b, err := store.LoadOrCreate(clusterKindWebSession)
	if err != nil {
		return fmt.Errorf("cluster web session secret: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("cluster web session secret: invalid size %d", len(b))
	}
	s.WebSessionSecret = append([]byte(nil), b...)
	return nil
}

// loadRunnerCACluster installs the shared runner CA when the store has one.
// Like the legacy loader, an absent CA leaves mTLS disabled rather than
// materializing a CA the operator never configured.
func (s *Server) loadRunnerCACluster(store ClusterKeyStore) error {
	if lookup, ok := store.(ClusterKeyLookup); ok {
		b, found, err := lookup.Lookup(clusterKindRunnerCA)
		if err != nil {
			return fmt.Errorf("cluster runner CA: %w", err)
		}
		if !found {
			return nil
		}
		return s.setRunnerCAFromBlob(b)
	}
	b, err := store.LoadOrCreate(clusterKindRunnerCA)
	if err != nil {
		return fmt.Errorf("cluster runner CA: %w", err)
	}
	return s.setRunnerCAFromBlob(b)
}

// setRunnerCAFromBlob parses a concatenated cert+key PEM blob into the
// server's runner CA.
func (s *Server) setRunnerCAFromBlob(b []byte) error {
	certPEM, keyPEM, err := splitRunnerCAPEMs(b)
	if err != nil {
		return fmt.Errorf("cluster runner CA: %w", err)
	}
	ca, err := runnerpki.LoadCA(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("load runner CA: %w", err)
	}
	s.RunnerCA = ca
	return nil
}

// KeyFingerprints returns the stable key id (hex sha256 truncated to 16
// bytes of the public/raw material) for every loaded key material, keyed by
// the cluster kind name. It is the cluster identity digest: replicas that
// share a cluster key store report identical fingerprints.
func (s *Server) KeyFingerprints() map[string]string {
	out := map[string]string{}
	if len(s.leaseKey) > 0 {
		out[clusterKindLease] = keyFingerprintRaw(s.leaseKey)
	}
	s.mu.Lock()
	oidc := s.oidc
	s.mu.Unlock()
	if oidc != nil {
		out[clusterKindOIDC] = keyFingerprintRaw(oidc.Public)
	}
	if s.provenance != nil {
		out[clusterKindProvenance] = keyFingerprintRaw(s.provenance.Public)
	}
	if s.cacheSigner != nil {
		out[clusterKindCacheSigning] = keyFingerprintRaw(s.cacheSigner.Public)
	}
	if len(s.WebSessionSecret) > 0 {
		out[clusterKindWebSession] = keyFingerprintRaw(s.WebSessionSecret)
	}
	if s.RunnerCA != nil && s.RunnerCA.Cert != nil {
		out[clusterKindRunnerCA] = keyFingerprintRaw(s.RunnerCA.Cert.Raw)
	}
	return out
}

// ValidateHAReady reports whether the control plane may serve as part of an
// HA deployment. A server with a database but no cluster key store would
// generate per-replica signing material, so replicas could not verify each
// other's lease tokens, OIDC tokens, provenance or cache signatures.
func (s *Server) ValidateHAReady() error {
	if s.DB != nil && s.ClusterKeys == nil {
		return errors.New("HA deployments require a cluster key store")
	}
	return nil
}
