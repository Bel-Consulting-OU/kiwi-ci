package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
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
	if s.ringPath == "" {
		return nil
	}
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
	tmp := s.ringPath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.ringPath); err != nil {
		return err
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
// active key. The caller must hold s.mu. It is internal to this file.
func (s *Server) rotateOIDCKeyLocked(now time.Time) {
	if s.oidc == nil {
		s.oidc = newOIDCSigner()
		return
	}
	next := newOIDCSigner()
	next.NotBefore = now
	next.ringPath = s.oidc.ringPath
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
	s.oidc = next
	if err := persistOIDCKeyRing(next); err != nil {
		s.logError("oidc: key rotation not persisted", "error", err.Error())
	}
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
		http.Error(w, err.Error(), 503)
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
		http.Error(w, "OIDC unavailable", 503)
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
		http.Error(w, "internal server error", 500)
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
		http.Error(w, err.Error(), 503)
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
		http.Error(w, "audience is required", 400)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	now := time.Now().UTC()
	s.mu.Lock()
	if s.oidc == nil || now.Sub(s.oidc.NotBefore) > oidcActiveKeyMaxAge {
		s.rotateOIDCKeyLocked(now)
	}
	signer := s.oidc
	j, ok := s.jobs[jobID]
	run := s.runs[j.RunID]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !j.OIDCAllowed {
		http.Error(w, "job does not have permissions.id_token", 403)
		return
	}
	// Defense in depth: admission already denies OIDC for untrusted jobs.
	if !j.Trusted {
		http.Error(w, "untrusted jobs may not issue id_tokens", 403)
		return
	}
	// Per-job audience allowlist compiled from capabilities at enqueue time;
	// nil means any audience.
	if j.OIDCAudiences != nil && !containsString(j.OIDCAudiences, in.Audience) {
		http.Error(w, "audience not allowed for this job", 403)
		return
	}
	if j.Status != model.StatusRunning || j.LeaseExpiresAt == nil || !j.LeaseExpiresAt.After(now) {
		http.Error(w, "job lease is not active", 409)
		return
	}
	if len(j.LeaseTokenHash) == 0 || subtle.ConstantTimeCompare(hashLeaseToken(s.leaseKey, token), j.LeaseTokenHash) != 1 {
		http.Error(w, "invalid job token", 401)
		return
	}
	sub := "repo:" + run.RepoFullName + ":ref:" + run.Ref + ":job:" + j.Key
	jti, err := newID()
	if err != nil {
		http.Error(w, "internal server error", 500)
		return
	}
	claims := map[string]any{"iss": iss, "sub": sub, "aud": in.Audience, "iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": jti, "repository": run.RepoFullName, "ref": run.Ref, "sha": run.SHA, "event": run.Event, "run_id": run.ID, "job_id": j.ID, "job": j.Key, "environment": j.Environment, "trusted": j.Trusted}
	jwt, err := s.signJWT(signer, claims)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.auditLocked("oidc.issued", j.LeaseRunnerID, j.RunID, j.ID, "OIDC id_token issued", map[string]string{"job": j.Key, "audience": in.Audience, "kid": signer.KID})
	s.metricAdd("kiwi_oidc_issues_total", 1, nil)
	writeJSON(w, 200, map[string]any{"value": jwt, "expires_at": now.Add(5 * time.Minute)})
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
