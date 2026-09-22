package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const (
	oidcKeyRingFile   = "oidc-keyring.json"
	oidcLegacyKeyFile = "oidc-ed25519.key"
)

// oidcActiveKeyMaxAge is how long an active OIDC signing key may be used
// before the next token issuance rotates it. Tests shorten it to force a
// rotation.
var oidcActiveKeyMaxAge = 30 * 24 * time.Hour

// oidcPreviousKeyRetireAfter is how long a rotated-out signing key remains
// advertised in the JWKS so tokens it signed stay verifiable.
var oidcPreviousKeyRetireAfter = 72 * time.Hour

// clusterKeyRotationFenceTimeout bounds how long a due rotation waits for the
// cross-replica fence. Contention beyond this keeps the CURRENT published key
// active instead of rotating without the fence: a token signed under an
// unpublished key is unverifiable, which is strictly worse than a slightly
// stale signing key. It is a var only so tests can shrink the bound.
var clusterKeyRotationFenceTimeout = 10 * time.Second

// oidcPreviousKey is a rotated-out signing key kept in the JWKS until
// RetireAfter. Only the public half is retained.
type oidcPreviousKey struct {
	KID         string
	Public      ed25519.PublicKey
	NotBefore   time.Time
	RetireAfter time.Time
}

// oidcSigner is the active OIDC signing key plus the rotation ring. Once
// published it is immutable: rotation builds a fresh signer and swaps it in
// under s.mu, moving the previous active key into Previous.
type oidcSigner struct {
	Private   ed25519.PrivateKey
	Public    ed25519.PublicKey
	KID       string
	NotBefore time.Time
	Previous  []oidcPreviousKey
	ringPath  string
	// ringMod/ringSize track the identity of the file-backed ring so a
	// replica can detect a peer's rotation with a cheap stat.
	ringMod  time.Time
	ringSize int64
	// ringDigest is the sha256 hex of the persisted ring bytes in cluster
	// mode; replicas reload when the stored digest changes.
	ringDigest string
	// cluster, when non-nil, is the shared key store the ring persists
	// through (HA deployments); ringPath stays empty in that mode.
	cluster ClusterKeyStore
}

// oidcKeyRingJSON is the on-disk key ring format written to
// <dataDir>/oidc-keyring.json with mode 0600.
type oidcKeyRingJSON struct {
	Active   oidcActiveKeyFile     `json:"active"`
	Previous []oidcPreviousKeyFile `json:"previous"`
}

type oidcActiveKeyFile struct {
	KID       string `json:"kid"`
	Pub       string `json:"pub"`
	Priv      string `json:"priv"`
	NotBefore string `json:"not_before"`
}

type oidcPreviousKeyFile struct {
	KID         string `json:"kid"`
	Pub         string `json:"pub"`
	NotBefore   string `json:"not_before"`
	RetireAfter string `json:"retire_after"`
}

func newOIDCKID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newOIDCSigner() *oidcSigner {
	pub, priv, err := ed25519.GenerateKey(randReader)
	if err != nil {
		panic("kiwi server: failed to generate OIDC signing key: " + err.Error())
	}
	kid, err := newOIDCKID()
	if err != nil {
		panic("kiwi server: failed to generate OIDC key id: " + err.Error())
	}
	return &oidcSigner{Private: priv, Public: pub, KID: kid, NotBefore: time.Now().UTC()}
}

// signerFromKeys derives the key id from the public key hash. It is used when
// migrating the legacy single-key file so existing verifiers keep the kid
// they pinned.
func signerFromKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey) *oidcSigner {
	sum := sha256.Sum256(pub)
	return &oidcSigner{Private: priv, Public: pub, KID: base64.RawURLEncoding.EncodeToString(sum[:12]), NotBefore: time.Now().UTC()}
}

func parseOIDCTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, v)
}

func oidcSignerFromRing(b []byte) (*oidcSigner, error) {
	var rf oidcKeyRingJSON
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("invalid OIDC key ring: %w", err)
	}
	raw, err := base64.RawStdEncoding.DecodeString(rf.Active.Priv)
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC active private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid OIDC signing key size")
	}
	priv := ed25519.PrivateKey(raw)
	pub := priv.Public().(ed25519.PublicKey)
	if rf.Active.Pub != "" {
		want, err := base64.RawStdEncoding.DecodeString(rf.Active.Pub)
		if err != nil {
			return nil, fmt.Errorf("invalid OIDC active public key: %w", err)
		}
		if subtle.ConstantTimeCompare(want, pub) != 1 {
			return nil, fmt.Errorf("OIDC key ring public key does not match private key")
		}
	}
	kid := rf.Active.KID
	if kid == "" {
		kid = signerFromKeys(pub, priv).KID
	}
	nb, err := parseOIDCTime(rf.Active.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC active not_before: %w", err)
	}
	s := &oidcSigner{Private: priv, Public: pub, KID: kid, NotBefore: nb}
	for _, pf := range rf.Previous {
		pp, err := base64.RawStdEncoding.DecodeString(pf.Pub)
		if err != nil {
			return nil, fmt.Errorf("invalid OIDC previous public key: %w", err)
		}
		if len(pp) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid OIDC previous public key size")
		}
		pnb, err := parseOIDCTime(pf.NotBefore)
		if err != nil {
			return nil, fmt.Errorf("invalid OIDC previous not_before: %w", err)
		}
		ret, err := parseOIDCTime(pf.RetireAfter)
		if err != nil {
			return nil, fmt.Errorf("invalid OIDC previous retire_after: %w", err)
		}
		s.Previous = append(s.Previous, oidcPreviousKey{KID: pf.KID, Public: ed25519.PublicKey(pp), NotBefore: pnb, RetireAfter: ret})
	}
	return s, nil
}

func persistOIDCKeyRing(s *oidcSigner) error {
	rf := oidcKeyRingJSON{
		Active: oidcActiveKeyFile{
			KID:       s.KID,
			Pub:       base64.RawStdEncoding.EncodeToString(s.Public),
			Priv:      base64.RawStdEncoding.EncodeToString(s.Private),
			NotBefore: s.NotBefore.UTC().Format(time.RFC3339Nano),
		},
	}
	for _, p := range s.Previous {
		rf.Previous = append(rf.Previous, oidcPreviousKeyFile{
			KID:         p.KID,
			Pub:         base64.RawStdEncoding.EncodeToString(p.Public),
			NotBefore:   p.NotBefore.UTC().Format(time.RFC3339Nano),
			RetireAfter: p.RetireAfter.UTC().Format(time.RFC3339Nano),
		})
	}
	b, err := jsonMarshalIndent(rf, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if s.cluster != nil {
		writer, ok := s.cluster.(ClusterKeyWriter)
		if !ok {
			return fmt.Errorf("oidc key ring: cluster key store does not support writes")
		}
		if err := writer.Store(clusterKindOIDC, b); err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		s.ringDigest = hex.EncodeToString(sum[:])
		return nil
	}
	if s.ringPath == "" {
		return nil
	}
	tmp := s.ringPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.ringPath); err != nil {
		return err
	}
	if info, err := os.Stat(s.ringPath); err == nil {
		s.ringMod = info.ModTime()
		s.ringSize = info.Size()
	}
	return nil
}

func loadOIDCSigner(root string) (*oidcSigner, error) {
	ringPath := filepath.Join(root, oidcKeyRingFile)
	if b, err := os.ReadFile(ringPath); err == nil {
		s, er := oidcSignerFromRing(b)
		if er != nil {
			return nil, er
		}
		s.ringPath = ringPath
		if info, serr := os.Stat(ringPath); serr == nil {
			s.ringMod = info.ModTime()
			s.ringSize = info.Size()
		}
		return s, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	legacy := filepath.Join(root, oidcLegacyKeyFile)
	if b, err := os.ReadFile(legacy); err == nil {
		raw, er := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if er != nil {
			return nil, er
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid OIDC signing key size")
		}
		priv := ed25519.PrivateKey(raw)
		pub := priv.Public().(ed25519.PublicKey)
		s := signerFromKeys(pub, priv)
		s.ringPath = ringPath
		if er := persistOIDCKeyRing(s); er != nil {
			return nil, er
		}
		return s, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	s := newOIDCSigner()
	s.ringPath = ringPath
	if err := persistOIDCKeyRing(s); err != nil {
		return nil, err
	}
	return s, nil
}

// rotateOIDCKeyLocked moves the active signing key into the retired-previous
// ring (advertised for oidcPreviousKeyRetireAfter more) and installs a fresh
// active key. The new ring is persisted BEFORE activation: an interrupted
// write leaves the old ring active everywhere, never a ring only this
// replica can verify. The caller must hold s.mu. It is internal to this
// file.
//
// The persist outcome is phase-aware because the shared key store returns
// typed fsutil errors:
//
//   - a definitely-not-published failure (fsutil.Renamed false: create,
//     write, chmod, file fsync, close or rename failed) leaves the previous
//     ring bit-for-bit intact in the store, so the old ring stays active and
//     readiness is untouched;
//   - a published-but-uncertain failure (fsutil.Renamed: only the parent
//     directory fsync failed, after the rename) means the store's reads now
//     return the NEW ring. Rolling back to the old ring would make this
//     replica disagree with every peer and with the next read, so the new
//     ring is retained in memory and the shared degraded marker is armed
//     until a later successful persist reconciles it.
func (s *Server) rotateOIDCKeyLocked(now time.Time) {
	if s.oidc == nil {
		s.oidc = newOIDCSigner()
		return
	}
	next := newOIDCSigner()
	next.NotBefore = now
	next.ringPath = s.oidc.ringPath
	next.cluster = s.oidc.cluster
	next.ringMod = s.oidc.ringMod
	next.ringSize = s.oidc.ringSize
	next.ringDigest = s.oidc.ringDigest
	next.Previous = make([]oidcPreviousKey, 0, len(s.oidc.Previous)+1)
	for _, p := range s.oidc.Previous {
		if p.RetireAfter.After(now) {
			next.Previous = append(next.Previous, p)
		}
	}
	next.Previous = append(next.Previous, oidcPreviousKey{
		KID:         s.oidc.KID,
		Public:      s.oidc.Public,
		NotBefore:   s.oidc.NotBefore,
		RetireAfter: now.Add(oidcPreviousKeyRetireAfter),
	})
	if err := persistOIDCKeyRing(next); err != nil {
		if fsutil.Renamed(err) {
			// The rename succeeded: the new ring is what the shared store now
			// serves. Retain it in memory and leave readiness degraded until a
			// successful persist proves durability.
			s.oidc = next
			s.noteFilePersistResult(s.oidcPersistPath(next), err)
			s.logError("oidc: key rotation published but not durably certified; retaining new ring and arming degraded readiness", "error", err.Error())
			return
		}
		s.logError("oidc: key rotation not persisted; keeping current ring active", "error", err.Error())
		return
	}
	s.oidc = next
	// A successful persist reconciles any earlier published-but-uncertain
	// rotation IN THE SAME DIRECTORY; uncertainty for another directory (for
	// example a separate --cluster-key-dir) is deliberately left armed.
	s.noteFilePersistResult(s.oidcPersistPath(next), nil)
}

// clusterKeyRotationFencer returns the cross-replica rotation fence for the
// OIDC ring, or nil when none is available (dev/in-memory mode). The cluster
// store is preferred because it owns the ring; the DB store is the fallback
// so a shared --cluster-key-dir deployment still fences through PostgreSQL.
func (s *Server) clusterKeyRotationFencer() ClusterKeyRotationFencer {
	if f, ok := s.ClusterKeys.(ClusterKeyRotationFencer); ok {
		return f
	}
	if s.DB != nil {
		if f, ok := s.DB.(ClusterKeyRotationFencer); ok {
			return f
		}
	}
	return nil
}

// ensureOIDCSigner returns the signer issueOIDC must sign under, rotating the
// active key first when it is due. The shared ring is refreshed before the
// check so a rotation published by another replica is adopted immediately.
//
// The refresh loads and parses ring material OUTSIDE s.mu (see
// refreshOIDCRing): a key store is remote I/O, and holding the global server
// mutex across it would let one public JWKS request stall every control-plane
// operation. Only the pointer comparison and swap take s.mu, for a few
// instructions.
//
// When a cross-replica fence is available the due-rotation path is: acquire
// the fence, refresh the shared ring AGAIN (still outside s.mu, under its own
// bounded context so an expired fence deadline cannot skip the read), re-check
// whether rotation is still due, then rotate and persist exactly once. The
// loser of a concurrent rotation therefore observes the winner's published
// key and does not overwrite it, and no replica ever activates a replacement
// before it is published. The re-read is mandatory: if it cannot POSITIVELY
// confirm the published ring (store error, parse failure, expiry) the
// rotation is skipped and the current published key stays active, because
// rebuilding from this replica's possibly stale signer could drop a peer's
// freshly published key from the shared ring and JWKS. When the fence cannot
// be acquired within clusterKeyRotationFenceTimeout the current (published)
// key stays active: issuing under an unpublished key would produce tokens no
// peer can verify. Without any fence (dev mode) the local mutex serializes
// rotation.
func (s *Server) ensureOIDCSigner(ctx context.Context, now time.Time) *oidcSigner {
	// >= (not >): coarse-clock platforms can report an exactly-zero age for
	// a freshly created key, and a max age of 0 must mean "rotate now".
	s.refreshOIDCRing(ctx)
	s.mu.Lock()
	signer := s.oidc
	due := signer == nil || now.Sub(signer.NotBefore) >= oidcActiveKeyMaxAge
	s.mu.Unlock()
	if !due {
		return signer
	}
	if fencer := s.clusterKeyRotationFencer(); fencer != nil {
		fctx, cancel := context.WithTimeout(ctx, clusterKeyRotationFenceTimeout)
		err := fencer.WithClusterKeyRotationFence(fctx, clusterKindOIDC, func() error {
			// Refresh INSIDE the fence — the winner may have published while
			// this replica waited — but OUTSIDE s.mu: the re-read is key-store
			// I/O like any other. The re-check then runs under the short lock
			// against whatever the refresh published.
			//
			// The in-fence re-read runs under its OWN bounded context,
			// independent of the fence deadline: the fence may have been
			// acquired only because the waiting goroutine could not be
			// interrupted at the deadline (a mutex-like fence), or the
			// deadline may have been consumed by slow acquisition, and an
			// expired fence context must never masquerade as "the published
			// ring is still the one this replica holds". Releasing the fence
			// is itself context-independent and hard-bounded, so a longer
			// in-fence read cannot wedge the next rotator.
			rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), clusterKeyRotationFenceTimeout)
			_, confirmed := s.refreshOIDCRingConfirmed(rctx)
			rcancel()
			// ONLY a positively confirmed read of the published ring may be
			// followed by a rotation. An unconfirmed refresh means this
			// replica cannot see what is published; rotating from its own
			// (possibly stale) signer could overwrite a peer's freshly
			// published active key and orphan tokens signed under it, so the
			// rotation is skipped and the current signer stays active.
			if !confirmed {
				s.logError("oidc: rotation skipped; shared key ring could not be confirmed")
				return nil
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.oidc == nil || now.Sub(s.oidc.NotBefore) >= oidcActiveKeyMaxAge {
				s.rotateOIDCKeyLocked(now)
			}
			return nil
		})
		cancel()
		if err != nil {
			s.logError("oidc: rotation fence unavailable; keeping current published key", "error", err.Error())
		}
	} else {
		s.mu.Lock()
		if s.oidc == nil || now.Sub(s.oidc.NotBefore) >= oidcActiveKeyMaxAge {
			s.rotateOIDCKeyLocked(now)
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.oidc
}

// contextClusterKeyLookup is the optional context-aware form of
// ClusterKeyLookup. The base interface carries no context; a store that can
// honor the caller's request context (a JWKS request, or a rotation fence
// deadline) should implement this and the refresh uses it directly, so an
// abandoned request aborts the key-store read instead of waiting for the
// store's own timeout. Stores without it are still called OUTSIDE s.mu and
// give up at the caller's context (see lookupOIDCRingBytes).
type contextClusterKeyLookup interface {
	LookupContext(ctx context.Context, kind string) ([]byte, bool, error)
}

// lookupOIDCRingBytes loads the shared OIDC ring bytes without holding s.mu.
// A context-aware store is called directly; otherwise the store's bounded,
// context-less Lookup runs in its own goroutine and this call gives up when
// the caller's context ends, returning ctx.Err(). Giving up is safe: the
// caller keeps the signer it already published, and the abandoned lookup's
// result only affects a future refresh.
func (s *Server) lookupOIDCRingBytes(ctx context.Context, cluster ClusterKeyStore) ([]byte, bool, error) {
	if cl, ok := cluster.(contextClusterKeyLookup); ok {
		return cl.LookupContext(ctx, clusterKindOIDC)
	}
	lookup, ok := cluster.(ClusterKeyLookup)
	if !ok {
		return nil, false, nil
	}
	type lookupResult struct {
		b     []byte
		found bool
		err   error
	}
	done := make(chan lookupResult, 1)
	go func() {
		b, found, err := lookup.Lookup(clusterKindOIDC)
		done <- lookupResult{b: b, found: found, err: err}
	}()
	select {
	case r := <-done:
		return r.b, r.found, r.err
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}

// installReloadedSigner publishes a freshly parsed signer under a SHORT s.mu
// critical section. observed is the signer the caller based its read on: if
// the published pointer changed in the meantime (another refresh, or a
// rotation that persisted a newer ring) the newer published signer wins and
// the parsed one is dropped, so a stale read can never roll the cluster back
// to an older ring.
func (s *Server) installReloadedSigner(observed, loaded *oidcSigner) *oidcSigner {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.oidc != observed {
		return s.oidc
	}
	s.oidc = loaded
	return loaded
}

// refreshOIDCRing converges the in-memory signer with the persisted ring when
// it changed since it was loaded — another replica rotated it. See
// refreshOIDCRingConfirmed; this form discards the confirmation flag for
// read-only callers (the JWKS handler) that may serve whatever is published.
func (s *Server) refreshOIDCRing(ctx context.Context) *oidcSigner {
	signer, _ := s.refreshOIDCRingConfirmed(ctx)
	return signer
}

// refreshOIDCRingConfirmed is refreshOIDCRing plus whether the currently
// PUBLISHED ring was positively read. All key-store I/O and parsing happen
// OUTSIDE s.mu; only the compare-and-swap takes the lock briefly. File mode
// compares the ring file's mtime/size; cluster mode compares the stored
// bytes' digest. A changed ring that fails to parse keeps the current signer
// active (fail closed), and a context that ends during the load returns the
// current signer unchanged.
//
// confirmed=false means the shared ring could not be read, parsed or found:
// the returned signer is then just this replica's current one, and callers
// that MUTATE the shared ring (rotation) must not proceed on it — they would
// be rebuilding the ring from local state that may predate a peer's
// publication. A ring with no shared backing at all (dev/in-memory mode) has
// nothing to confirm and is always confirmed.
func (s *Server) refreshOIDCRingConfirmed(ctx context.Context) (*oidcSigner, bool) {
	s.mu.Lock()
	current := s.oidc
	s.mu.Unlock()
	if current == nil || (current.cluster == nil && current.ringPath == "") {
		return current, true
	}
	if current.cluster != nil {
		b, found, err := s.lookupOIDCRingBytes(ctx, current.cluster)
		if err != nil {
			if ctx.Err() == nil {
				s.logError("oidc: ring reload lookup failed", "error", err.Error())
			}
			return s.currentOIDCSigner(), false
		}
		if !found {
			return s.currentOIDCSigner(), false
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		if digest == current.ringDigest {
			return current, true
		}
		signer, err := oidcSignerFromRing(b)
		if err != nil {
			s.logError("oidc: ring reload parse failed", "error", err.Error())
			return s.currentOIDCSigner(), false
		}
		signer.cluster = current.cluster
		signer.ringDigest = digest
		return s.installReloadedSigner(current, signer), true
	}
	info, err := os.Stat(current.ringPath)
	if err != nil {
		return s.currentOIDCSigner(), false
	}
	if info.ModTime().Equal(current.ringMod) && info.Size() == current.ringSize {
		return current, true
	}
	b, err := os.ReadFile(current.ringPath)
	if err != nil {
		return s.currentOIDCSigner(), false
	}
	signer, err := oidcSignerFromRing(b)
	if err != nil {
		s.logError("oidc: ring reload parse failed", "error", err.Error())
		return s.currentOIDCSigner(), false
	}
	signer.ringPath = current.ringPath
	signer.ringMod = info.ModTime()
	signer.ringSize = info.Size()
	return s.installReloadedSigner(current, signer), true
}

// currentOIDCSigner reads the published signer under a short lock. Used when a
// refresh could not load anything: the caller must serve what is published,
// never the signer its (possibly stale) read was based on.
func (s *Server) currentOIDCSigner() *oidcSigner {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.oidc
}

// oidcIssuer validates and returns the OIDC issuer identifier through the
// SAME parsed-URL validator config validation uses
// (config.ValidateExternalURL), so a value that passed startup can never be
// rejected here later with a 503. The value must be an absolute HTTPS URL;
// plaintext HTTP is tolerated only for a genuine loopback host (local
// development), never for a lookalike hostname like "localhost.evil.example"
// or "127.0.0.1.attacker.test". Userinfo, queries and fragments are rejected
// because an OIDC issuer identifier must be a bare origin(+path) URL.
//
// Production plaintext cannot reach this path: config.Validate refuses an
// http:// external_url in production mode before the server starts, and the
// server itself carries no mode to re-check.
func (s *Server) oidcIssuer() (string, error) {
	if strings.TrimRight(s.ExternalURL, "/") == "" {
		return "", fmt.Errorf("KIWI_EXTERNAL_URL/--external-url is required for OIDC")
	}
	v, err := config.ValidateExternalURL(s.ExternalURL, "")
	if err != nil {
		return "", fmt.Errorf("OIDC issuer: %w", err)
	}
	return v, nil
}

func (s *Server) oidcConfiguration(w http.ResponseWriter, r *http.Request) {
	iss, err := s.oidcIssuer()
	if err != nil {
		s.serverError(w, r, http.StatusServiceUnavailable, err, "OIDC unavailable")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, 200, map[string]any{"issuer": iss, "jwks_uri": iss + "/api/v1/oidc/jwks", "id_token_signing_alg_values_supported": []string{"EdDSA"}, "subject_types_supported": []string{"public"}, "response_types_supported": []string{"id_token"}})
}

func oidcJWK(kid string, pub ed25519.PublicKey) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func (s *Server) oidcJWKS(w http.ResponseWriter, r *http.Request) {
	// Refresh the shared ring BEFORE serving: a replica that has not issued a
	// token since a peer rotated would otherwise keep publishing a JWKS
	// without the peer's active key, and tokens signed under that key would
	// fail verification at every consumer of this endpoint. The refresh does
	// its key-store I/O outside s.mu (bounded by this request's context), so
	// this public endpoint can never pin the control plane on a slow store:
	// on a stall it serves the last published key set.
	signer := s.refreshOIDCRing(r.Context())
	if signer == nil {
		http.Error(w, "OIDC unavailable", http.StatusServiceUnavailable)
		return
	}
	now := time.Now().UTC()
	keys := make([]any, 0, 1+len(signer.Previous))
	keys = append(keys, oidcJWK(signer.KID, signer.Public))
	for _, p := range signer.Previous {
		if p.RetireAfter.After(now) {
			keys = append(keys, oidcJWK(p.KID, p.Public))
		}
	}
	body, err := jsonMarshal(map[string]any{"keys": keys})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) issueOIDC(w http.ResponseWriter, r *http.Request) {
	iss, err := s.oidcIssuer()
	if err != nil {
		s.serverError(w, r, http.StatusServiceUnavailable, err, "OIDC unavailable")
		return
	}
	jobID := r.PathValue("id")
	var in struct {
		Audience string `json:"audience"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Audience) == "" || len(in.Audience) > 512 {
		http.Error(w, "audience is required", http.StatusBadRequest)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	now := time.Now().UTC()
	// DB mode: the store is the source of truth for the lease/audience
	// checks; the in-memory maps are only the dev-mode mirror.
	var j model.Job
	var run model.Run
	if s.DB != nil {
		var err error
		j, err = s.DB.GetJob(r.Context(), jobID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.internalError(w, r, err, "")
			return
		}
		run, err = s.DB.GetRun(r.Context(), j.RunID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.internalError(w, r, err, "")
			return
		}
	} else {
		s.mu.Lock()
		ok := false
		j, ok = s.jobs[jobID]
		run = s.runs[j.RunID]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
	}
	if !j.OIDCAllowed {
		http.Error(w, "job does not have permissions.id_token", http.StatusForbidden)
		return
	}
	// Defense in depth: admission already denies OIDC for untrusted jobs.
	if !j.Trusted {
		http.Error(w, "untrusted jobs may not issue id_tokens", http.StatusForbidden)
		return
	}
	// Per-job audience allowlist compiled from capabilities at enqueue time;
	// nil means any audience.
	if j.OIDCAudiences != nil && !containsString(j.OIDCAudiences, in.Audience) {
		http.Error(w, "audience not allowed for this job", http.StatusForbidden)
		return
	}
	if j.Status != model.StatusRunning || j.LeaseExpiresAt == nil || !j.LeaseExpiresAt.After(now) {
		http.Error(w, "job lease is not active", http.StatusConflict)
		return
	}
	if len(j.LeaseTokenHash) == 0 || subtle.ConstantTimeCompare(hashLeaseToken(s.leaseKey, token), j.LeaseTokenHash) != 1 {
		http.Error(w, "invalid job token", http.StatusUnauthorized)
		return
	}
	// AUTHENTICATION BEFORE SIGNER WORK. The endpoint is public at the auth
	// layer (the lease token is the credential), so nothing above this point
	// may touch the signing key or its shared key store: the signer is
	// resolved — and a due rotation may do key-store I/O — only after the
	// job, audience and lease checks have all passed. Unauthenticated traffic
	// therefore performs zero key-store reads.
	signer := s.ensureOIDCSigner(r.Context(), now)
	if signer == nil {
		s.serverError(w, r, http.StatusServiceUnavailable, fmt.Errorf("OIDC signer unavailable"), "OIDC unavailable")
		return
	}
	// The subject and the repository_id claim use the canonical repository
	// identity; the repository claim stays the human-readable full name.
	repoID := repoIDForRun(run)
	sub := "repo:" + repoID + ":ref:" + run.Ref + ":job:" + j.Key
	jti, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	claims := map[string]any{"iss": iss, "sub": sub, "aud": in.Audience, "iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": jti, "repository": run.RepoFullName, "repository_id": repoID, "ref": run.Ref, "sha": run.SHA, "event": run.Event, "run_id": run.ID, "job_id": j.ID, "job": j.Key, "environment": j.Environment, "trusted": j.Trusted}
	jwt, err := s.signJWT(signer, claims)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	// The audit trail records the issuance before the token is returned; a
	// persistence failure fails the issuance closed (no log-and-continue).
	if err := s.auditOIDCIssuance(r, j.LeaseRunnerID, j.RunID, j.ID, signer.KID, j.Key, in.Audience); err != nil {
		http.Error(w, "OIDC issuance audit failed", http.StatusInternalServerError)
		return
	}
	s.metricAdd("kiwi_oidc_issues_total", 1, nil)
	writeJSON(w, 200, map[string]any{"value": jwt, "expires_at": now.Add(5 * time.Minute)})
}

// auditOIDCIssuance appends the oidc.issued audit event (kid, audience —
// never the token) and returns any persistence error so issuance can fail
// closed. A server without a store (pure in-memory dev mode) has no audit
// sink and reports success.
func (s *Server) auditOIDCIssuance(r *http.Request, actor, runID, jobID, kid, job, audience string) error {
	if s.store == nil && s.DB == nil {
		return nil
	}
	id, err := newID()
	if err != nil {
		return err
	}
	e := model.AuditEvent{
		ID: id, Action: "oidc.issued", Actor: actor, RunID: runID, JobID: jobID,
		Message:   "OIDC id_token issued",
		Metadata:  map[string]string{"job": job, "audience": audience, "kid": kid},
		CreatedAt: time.Now().UTC(),
	}
	if s.DB != nil {
		return s.DB.AppendAudit(r.Context(), e)
	}
	return s.store.AppendAudit(e)
}

func (s *Server) signJWT(signer *oidcSigner, claims map[string]any) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("OIDC signer unavailable")
	}
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": signer.KID}
	h, _ := jsonMarshal(header)
	c, err := jsonMarshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString
	input := enc(h) + "." + enc(c)
	sig := ed25519.Sign(signer.Private, []byte(input))
	return input + "." + enc(sig), nil
}

func containsString(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}
