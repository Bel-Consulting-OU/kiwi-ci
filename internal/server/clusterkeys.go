package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
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

	// runnerCAObjectFile is the single atomic object holding the runner CA
	// (cert PEM + "\x00" + key PEM); ca.crt/ca.key are derived sidecars.
	runnerCAObjectFile = "runner-ca.pem"
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

// ClusterKeyInstaller optionally installs caller-provided key material with
// atomic create-if-absent semantics: the STORED material always wins when
// the kind already exists, and created reports whether this call's bytes
// were installed. It is what lets an explicit runner CA be installed into
// the shared cluster store and compared against what every replica already
// trusts (see Server.SetRunnerCA): material that disagrees with the stored
// bytes fails startup instead of silently replacing the shared trust root.
// Stores that do not implement it can still serve read-only material through
// Lookup; the runner-CA install path refuses them rather than falling back to
// node-local files.
type ClusterKeyInstaller interface {
	InstallOrLoad(kind string, data []byte) (stored []byte, created bool, err error)
}

// ClusterKeyRotationFencer optionally provides the cross-replica fence that
// serializes key-material rotation. It is what makes rotation safe in HA: a
// local mutex only serializes goroutines inside one replica, while two
// replicas can both observe an expired active key, generate different
// replacements, and both issue tokens under a ring the other then overwrites.
// A fenced rotation reloads the shared ring AFTER taking the fence and
// re-checks whether rotation is still due, so the loser of a concurrent
// rotation observes the winner's published key instead of rotating again.
//
// The DB-backed store implements this with a PostgreSQL advisory lock; the
// fence is held only across reload/re-check/rotate/persist and is
// hard-bounded on release.
type ClusterKeyRotationFencer interface {
	WithClusterKeyRotationFence(ctx context.Context, kind string, fn func() error) error
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
//	runner-ca     runner-ca.pem         ONE atomic object: cert PEM + "\x00"
//	                                    + key PEM; ca.crt (0644) and ca.key
//	                                    (0600) are derived sidecars published
//	                                    from the object
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
	_ ClusterKeyStore     = (*FSClusterKeyStore)(nil)
	_ ClusterKeyWriter    = (*FSClusterKeyStore)(nil)
	_ ClusterKeyLookup    = (*FSClusterKeyStore)(nil)
	_ ClusterKeyInstaller = (*FSClusterKeyStore)(nil)
	_ ClusterKeyStore     = (*StaticClusterKeyStore)(nil)
	_ ClusterKeyWriter    = (*StaticClusterKeyStore)(nil)
	_ ClusterKeyLookup    = (*StaticClusterKeyStore)(nil)
	_ ClusterKeyInstaller = (*StaticClusterKeyStore)(nil)
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
		_, priv, err := ed25519.GenerateKey(randReader)
		if err != nil {
			return nil, err
		}
		return encodeEd25519PrivatePEM(priv)
	case clusterKindWebSession:
		b := make([]byte, 32)
		if _, err := io.ReadFull(randReader, b); err != nil {
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
		// The runner CA is ONE atomic cluster-key object: certificate PEM,
		// a NUL separator, private key PEM. Loaders split on the NUL; the
		// PEM-boundary split is kept only for pre-existing objects.
		obj := make([]byte, 0, len(certPEM)+1+len(keyDER))
		obj = append(obj, certPEM...)
		obj = append(obj, 0)
		obj = append(obj, keyDER...)
		return obj, nil
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
	if _, err := io.ReadFull(randReader, b); err != nil {
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
		return filepath.Join(s.Dir, runnerCAObjectFile), nil
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
		// The runner CA is one atomic object: create-if-absent, then
		// publish the ca.crt/ca.key sidecars from it. The object file is
		// authoritative; a concurrent creator's material wins via the CAS
		// link and is read back.
		created, err := createClusterKey(kind)
		if err != nil {
			return nil, err
		}
		path, err := s.path(kind)
		if err != nil {
			return nil, err
		}
		if err := createFileCAS(path, created); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return nil, err
			}
			existing, ok, lerr := s.Lookup(kind)
			if lerr != nil {
				return nil, lerr
			}
			if !ok {
				return nil, fmt.Errorf("cluster keys: runner-ca was created concurrently but cannot be read")
			}
			return existing, nil
		}
		if err := s.publishRunnerCASidecars(created); err != nil {
			return nil, err
		}
		return created, nil
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
		if perr := fsutil.AtomicWriteFile(pubPath, pub, 0o644); perr != nil {
			return nil, perr
		}
	}
	return created, nil
}

// InstallOrLoad installs data for kind when the store holds nothing yet and
// returns the stored bytes; created reports whether this call's bytes were
// installed. An existing value always wins (the hard-link CAS plus a
// read-back), so the call is an atomic compare-or-install against the shared
// trust root. The runner-CA object also publishes its ca.crt/ca.key sidecars,
// mirroring LoadOrCreate, and key-pair kinds publish their public sidecar.
func (s *FSClusterKeyStore) InstallOrLoad(kind string, data []byte) ([]byte, bool, error) {
	if len(data) == 0 {
		return nil, false, errors.New("cluster keys: empty key material")
	}
	if existing, ok, err := s.Lookup(kind); err != nil {
		return nil, false, err
	} else if ok {
		return existing, false, nil
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, false, err
	}
	encoded, err := s.encodedBytes(kind, data)
	if err != nil {
		return nil, false, err
	}
	path, err := s.path(kind)
	if err != nil {
		return nil, false, err
	}
	if err := createFileCAS(path, encoded); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, false, err
		}
		// A concurrent installer won: the stored bytes are authoritative.
		existing, ok, lerr := s.Lookup(kind)
		if lerr != nil {
			return nil, false, lerr
		}
		if !ok {
			return nil, false, fmt.Errorf("cluster keys: %s was installed concurrently but cannot be read", kind)
		}
		return existing, false, nil
	}
	if kind == clusterKindRunnerCA {
		if err := s.publishRunnerCASidecars(data); err != nil {
			return nil, false, err
		}
	}
	if kind == clusterKindProvenance || kind == clusterKindCacheSigning {
		priv, perr := parseEd25519PrivatePEM(data)
		if perr != nil {
			return nil, false, perr
		}
		pubPEM, perr := encodeEd25519PublicPEM(priv.Public().(ed25519.PublicKey))
		if perr != nil {
			return nil, false, perr
		}
		pubPath := filepath.Join(s.Dir, "provenance.pub")
		if kind == clusterKindCacheSigning {
			pubPath = filepath.Join(s.Dir, cacheSigningPubFile)
		}
		if perr := fsutil.AtomicWriteFile(pubPath, pubPEM, 0o644); perr != nil {
			return nil, false, perr
		}
	}
	return data, true, nil
}

// encodedBytes renders the canonical on-disk encoding for one kind without
// touching the filesystem (hex for raw 32-byte material, identity for the
// self-describing formats including the runner-CA object).
func (s *FSClusterKeyStore) encodedBytes(kind string, data []byte) ([]byte, error) {
	switch kind {
	case clusterKindLease, clusterKindWebSession:
		return []byte(hex.EncodeToString(data)), nil
	case clusterKindOIDC, clusterKindProvenance, clusterKindCacheSigning, clusterKindRunnerCA:
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
		if werr := fsutil.AtomicWriteFile(p, legacy, 0o600); werr != nil {
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
		obj, err := os.ReadFile(filepath.Join(s.Dir, runnerCAObjectFile))
		if err == nil {
			if _, _, serr := splitRunnerCAPEMs(obj); serr != nil {
				return nil, false, serr
			}
			return obj, true, nil
		}
		if !os.IsNotExist(err) {
			return nil, false, err
		}
		// Migrate the legacy split files (ca.crt + ca.key) into the single
		// atomic object once; from then on the object is authoritative.
		certPEM, certErr := os.ReadFile(filepath.Join(s.Dir, "ca.crt"))
		keyPEM, keyErr := os.ReadFile(filepath.Join(s.Dir, "ca.key"))
		if certErr != nil || keyErr != nil {
			return nil, false, nil
		}
		migrated := make([]byte, 0, len(certPEM)+1+len(keyPEM))
		migrated = append(migrated, certPEM...)
		migrated = append(migrated, 0)
		migrated = append(migrated, keyPEM...)
		if werr := createFileCAS(filepath.Join(s.Dir, runnerCAObjectFile), migrated); werr != nil && !errors.Is(werr, os.ErrExist) {
			return nil, false, werr
		}
		return migrated, true, nil
	default:
		return nil, false, fmt.Errorf("cluster keys: unknown key kind %q", kind)
	}
}

// Store persists key material for kind with overwrite semantics (the OIDC
// ring rotation and an explicit runner-CA replacement are the callers).
//
// Failures are typed (*fsutil.AtomicWriteError) and phase-aware, because the
// store holds no in-memory authority to roll back:
//
//   - a pre-rename failure means the material was definitely not published:
//     the previous file at the kind's path is bit-for-bit intact (or absent),
//     the temp file is removed, and the caller may keep serving the previous
//     material as if the write had never been attempted.
//   - a post-rename directory-fsync failure (fsutil.Renamed) means the NEW
//     material IS visible at the kind's path with uncertified crash
//     durability. The caller must not treat the new material as "not
//     installed" and must not overwrite it back to the previous value:
//     fsutil.Renamed is the signal to retain the published material (it is
//     what every read of the store now returns) and — on a server path that
//     owns readiness — to leave the degraded marker armed until a later
//     successful persist reconciles.
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
		return fsutil.AtomicWriteFile(p, []byte(hex.EncodeToString(data)), 0o600)
	case clusterKindOIDC:
		return fsutil.AtomicWriteFile(filepath.Join(s.Dir, oidcKeyRingFile), data, 0o600)
	case clusterKindProvenance:
		if err := fsutil.AtomicWriteFile(filepath.Join(s.Dir, "provenance.key"), data, 0o600); err != nil {
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
		return fsutil.AtomicWriteFile(filepath.Join(s.Dir, "provenance.pub"), pub, 0o644)
	case clusterKindCacheSigning:
		if err := fsutil.AtomicWriteFile(filepath.Join(s.Dir, cacheSigningKeyFile), data, 0o600); err != nil {
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
		return fsutil.AtomicWriteFile(filepath.Join(s.Dir, cacheSigningPubFile), pub, 0o644)
	case clusterKindRunnerCA:
		if err := createFileCAS(filepath.Join(s.Dir, runnerCAObjectFile), data); err != nil {
			if errors.Is(err, os.ErrExist) {
				// The object already exists: overwrite semantics need the
				// explicit Store path, which the CAS link cannot provide.
				if werr := fsutil.AtomicWriteFile(filepath.Join(s.Dir, runnerCAObjectFile), data, 0o600); werr != nil {
					return werr
				}
			} else {
				return err
			}
		}
		return s.publishRunnerCASidecars(data)
	default:
		return fmt.Errorf("cluster keys: unknown key kind %q", kind)
	}
}

// publishRunnerCASidecars writes the ca.crt (0644) and ca.key (0600)
// sidecars derived from the single runner-ca object so legacy consumers
// (data-dir readers, operator tooling) keep working. Both sidecars are
// written atomically from the same object.
//
// The object file is the authoritative copy: a sidecar failure (either
// phase) never invalidates it, and a post-rename failure
// (fsutil.Renamed) leaves that sidecar already visible. The error still
// propagates so the caller fails closed — a half-published legacy pair is
// never reported as a successful install — and a retry re-derives both
// sidecars from the object, which converges because the object did not move.
func (s *FSClusterKeyStore) publishRunnerCASidecars(obj []byte) error {
	certPEM, keyPEM, err := splitRunnerCAPEMs(obj)
	if err != nil {
		return err
	}
	if err := fsutil.AtomicWriteFile(filepath.Join(s.Dir, "ca.crt"), certPEM, 0o644); err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(filepath.Join(s.Dir, "ca.key"), keyPEM, 0o600)
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

// InstallOrLoad installs data for kind when absent (create-if-absent under
// the store mutex) and returns the stored bytes; created reports whether the
// caller's bytes were installed. An existing value always wins, so
// concurrent installers converge on one trust root.
func (s *StaticClusterKeyStore) InstallOrLoad(kind string, data []byte) ([]byte, bool, error) {
	if len(data) == 0 {
		return nil, false, errors.New("cluster keys: empty key material")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Keys == nil {
		s.Keys = map[string][]byte{}
	}
	if existing, ok := s.Keys[kind]; ok {
		return append([]byte(nil), existing...), false, nil
	}
	s.Keys[kind] = append([]byte(nil), data...)
	return append([]byte(nil), data...), true, nil
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

// splitRunnerCAPEMs splits a runner CA cluster object into its certificate
// and private key PEM documents. The canonical object format separates the
// two PEM documents with a single NUL byte; objects written before that
// format concatenated the PEMs directly, so the PEM-boundary split is kept
// as a fallback.
func splitRunnerCAPEMs(data []byte) (certPEM, keyPEM []byte, err error) {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		certPEM = data[:i]
		keyPEM = data[i+1:]
		if len(bytes.TrimSpace(certPEM)) == 0 || len(bytes.TrimSpace(keyPEM)) == 0 {
			return nil, nil, fmt.Errorf("cluster keys: runner CA blob is empty on one side of the separator")
		}
		return certPEM, keyPEM, nil
	}
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
	ca, err := s.parseRunnerCABlob(b)
	if err != nil {
		return err
	}
	s.RunnerCA = ca
	return nil
}

// UseClusterKeyStore replaces the server's cluster key store and loads every
// signing material through it. The app wiring calls it for the DB-backed
// store after the SQL store is connected; construction-time callers go
// through NewPersistentWithCluster instead. Like that constructor, an absent
// runner CA stays absent (it is never materialized by the loader).
func (s *Server) UseClusterKeyStore(store ClusterKeyStore) error {
	if store == nil {
		return errors.New("cluster keys: nil store")
	}
	s.ClusterKeys = store
	if signer, err := s.loadOIDCSignerCluster(store); err != nil {
		return err
	} else {
		s.oidc = signer
	}
	if err := s.loadLeaseKeyCluster(store); err != nil {
		return err
	}
	if err := s.loadRunnerCACluster(store); err != nil {
		return err
	}
	if err := s.loadProvenanceCluster(store); err != nil {
		return err
	}
	if err := s.loadCacheSignerCluster(store); err != nil {
		return err
	}
	return s.loadWebSessionCluster(store)
}

// parseRunnerCABlob parses a runner CA cluster object (cert PEM + NUL + key
// PEM, or the legacy concatenated PEMs) into a CA.
func (s *Server) parseRunnerCABlob(b []byte) (*runnerpki.CA, error) {
	certPEM, keyPEM, err := splitRunnerCAPEMs(b)
	if err != nil {
		return nil, fmt.Errorf("cluster runner CA: %w", err)
	}
	ca, err := runnerpki.LoadCA(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load runner CA: %w", err)
	}
	return ca, nil
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
// other's lease tokens, OIDC tokens, provenance or cache signatures. The
// implicit NewPersistent store rooted at the node-local data dir is NOT
// proof of a shared key store: separate replicas with separate data dirs
// would each pass while holding different keys, so HA/DB mode requires a
// deliberately configured shared provider (the DB-backed cluster key store,
// or an explicit --cluster-key-dir on shared storage that is not the data
// dir itself). When runner CA material is loaded, it must additionally
// resolve identically through the cluster store: the shared object must
// parse to a CA whose certificate fingerprint equals the loaded CA's, so a
// replica cannot hold a divergent runner CA.
func (s *Server) ValidateHAReady() error {
	if s.DB != nil && s.ClusterKeys == nil {
		return errors.New("HA deployments require a cluster key store")
	}
	if s.DB != nil {
		if fs, ok := s.ClusterKeys.(*FSClusterKeyStore); ok && clusterKeyDirIsNodeLocal(fs.Dir, s.dataDir) {
			return fmt.Errorf("HA deployments require a shared cluster key store: the cluster key directory %q is the node-local data dir, so replicas would hold different keys; configure --cluster-key-dir on shared storage or use the database-backed cluster key store", fs.Dir)
		}
	}
	if s.RunnerCA != nil && s.ClusterKeys != nil {
		var shared []byte
		var err error
		if lookup, ok := s.ClusterKeys.(ClusterKeyLookup); ok {
			shared, _, err = lookup.Lookup(clusterKindRunnerCA)
		} else {
			shared, err = s.ClusterKeys.LoadOrCreate(clusterKindRunnerCA)
		}
		if err != nil {
			return fmt.Errorf("HA validation: resolve shared runner CA: %w", err)
		}
		if len(shared) == 0 {
			return fmt.Errorf("HA validation: runner CA is loaded but the cluster key store has no shared runner CA material")
		}
		sharedCA, perr := s.parseRunnerCABlob(shared)
		if perr != nil {
			return fmt.Errorf("HA validation: shared runner CA: %w", perr)
		}
		if !bytes.Equal(sharedCA.Cert.Raw, s.RunnerCA.Cert.Raw) {
			return fmt.Errorf("HA validation: runner CA fingerprint mismatch between the loaded CA and the cluster key store")
		}
	}
	return nil
}

// clusterKeyDirIsNodeLocal reports whether dir is the server's own data
// directory (or a filesystem alias of it): that store is node-local by
// construction, not a deliberately configured shared provider.
func clusterKeyDirIsNodeLocal(dir, dataDir string) bool {
	if dir == "" || dataDir == "" {
		return dir == dataDir
	}
	if filepath.Clean(dir) == filepath.Clean(dataDir) {
		return true
	}
	di, derr := os.Stat(dir)
	dd, dderr := os.Stat(dataDir)
	return derr == nil && dderr == nil && os.SameFile(di, dd)
}
