package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

type oidcSigner struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	KID     string
}

func newOIDCSigner() *oidcSigner {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return signerFromKeys(pub, priv)
}
func signerFromKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey) *oidcSigner {
	sum := sha256.Sum256(pub)
	return &oidcSigner{Private: priv, Public: pub, KID: base64.RawURLEncoding.EncodeToString(sum[:12])}
}
func loadOIDCSigner(root string) (*oidcSigner, error) {
	path := filepath.Join(root, "oidc-ed25519.key")
	b, err := os.ReadFile(path)
	if err == nil {
		raw, er := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if er != nil {
			return nil, er
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid OIDC signing key size")
		}
		priv := ed25519.PrivateKey(raw)
		pub := priv.Public().(ed25519.PublicKey)
		return signerFromKeys(pub, priv), nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	s := newOIDCSigner()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(base64.RawStdEncoding.EncodeToString(s.Private)), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return s, nil
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
	writeJSON(w, 200, map[string]any{"issuer": iss, "jwks_uri": iss + "/api/v1/oidc/jwks", "id_token_signing_alg_values_supported": []string{"EdDSA"}, "subject_types_supported": []string{"public"}, "response_types_supported": []string{"id_token"}})
}
func (s *Server) oidcJWKS(w http.ResponseWriter, _ *http.Request) {
	if s.oidc == nil {
		http.Error(w, "OIDC unavailable", 503)
		return
	}
	writeJSON(w, 200, map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": s.oidc.KID, "x": base64.RawURLEncoding.EncodeToString(s.oidc.Public)}}})
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
	jwt, err := s.signJWT(claims)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]any{"value": jwt, "expires_at": now.Add(5 * time.Minute)})
}
func (s *Server) signJWT(claims map[string]any) (string, error) {
	if s.oidc == nil {
		return "", fmt.Errorf("OIDC signer unavailable")
	}
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": s.oidc.KID}
	h, _ := json.Marshal(header)
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString
	input := enc(h) + "." + enc(c)
	sig := ed25519.Sign(s.oidc.Private, []byte(input))
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
