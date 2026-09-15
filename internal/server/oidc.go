package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newOIDCSigner() *oidcSigner {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
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
	b, err := json.MarshalIndent(rf, "", "  ")
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
		s.logError("oidc: key rotation not persisted; keeping current ring active", "error", err.Error())
		return
	}
	s.oidc = next
}

// reloadOIDCRingLocked replaces the in-memory signer when the persisted
// ring changed since it was loaded — another replica rotated it. The caller
// must hold s.mu. File mode compares the ring file's mtime/size; cluster
// mode compares the stored bytes' digest. A changed ring that fails to
// parse keeps the current signer active (fail closed).
func (s *Server) reloadOIDCRingLocked() {
	if s.oidc == nil {
		return
	}
	if s.oidc.cluster != nil {
		lookup, ok := s.oidc.cluster.(ClusterKeyLookup)
		if !ok {
			return
		}
		b, found, err := lookup.Lookup(clusterKindOIDC)
		if err != nil {
			s.logError("oidc: ring reload lookup failed", "error", err.Error())
			return
		}
		if !found {
			return
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		if s.oidc.ringDigest == digest {
			return
		}
		signer, err := oidcSignerFromRing(b)
		if err != nil {
			s.logError("oidc: ring reload parse failed", "error", err.Error())
			return
		}
		signer.cluster = s.oidc.cluster
		signer.ringDigest = digest
		s.oidc = signer
		return
	}
	if s.oidc.ringPath == "" {
		return
	}
	info, err := os.Stat(s.oidc.ringPath)
	if err != nil {
		return
	}
	if info.ModTime().Equal(s.oidc.ringMod) && info.Size() == s.oidc.ringSize {
		return
	}
	b, err := os.ReadFile(s.oidc.ringPath)
	if err != nil {
		return
	}
	signer, err := oidcSignerFromRing(b)
	if err != nil {
		s.logError("oidc: ring reload parse failed", "error", err.Error())
		return
	}
	signer.ringPath = s.oidc.ringPath
	signer.ringMod = info.ModTime()
	signer.ringSize = info.Size()
	s.oidc = signer
}

func (s *Server) oidcIssuer() (string, error) {
	v := strings.TrimRight(s.ExternalURL, "/")
	if v == "" {
		return "", fmt.Errorf("KIWI_EXTERNAL_URL/--external-url is required for OIDC")
	}
	if !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://127.0.0.1") && !strings.HasPrefix(v, "http://localhost") {
		return "", fmt.Errorf("OIDC issuer must use HTTPS")
	}
	return v, nil
}

func (s *Server) oidcConfiguration(w http.ResponseWriter, r *http.Request) {
	iss, err := s.oidcIssuer()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, 200, map[string]any{"issuer": iss, "jwks_uri": iss + "/api/v1/oidc/jwks", "id_token_signing_alg_values_supported": []string{"EdDSA"}, "subject_types_supported": []string{"public"}, "response_types_supported": []string{"id_token"}})
}

func oidcJWK(kid string, pub ed25519.PublicKey) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func (s *Server) oidcJWKS(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	signer := s.oidc
	s.mu.Unlock()
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
	body, err := json.Marshal(map[string]any{"keys": keys})
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
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
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
	s.mu.Lock()
	s.reloadOIDCRingLocked()
	if s.oidc == nil || now.Sub(s.oidc.NotBefore) > oidcActiveKeyMaxAge {
		s.rotateOIDCKeyLocked(now)
	}
	signer := s.oidc
	s.mu.Unlock()
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
			http.Error(w, err.Error(), 500)
			return
		}
		run, err = s.DB.GetRun(r.Context(), j.RunID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
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
	sub := "repo:" + run.RepoFullName + ":ref:" + run.Ref + ":job:" + j.Key
	jti, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	claims := map[string]any{"iss": iss, "sub": sub, "aud": in.Audience, "iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": jti, "repository": run.RepoFullName, "ref": run.Ref, "sha": run.SHA, "event": run.Event, "run_id": run.ID, "job_id": j.ID, "job": j.Key, "environment": j.Environment, "trusted": j.Trusted}
	jwt, err := s.signJWT(signer, claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	h, _ := json.Marshal(header)
	c, err := json.Marshal(claims)
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
