package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// TestVerifyFlagsPlumbedToVerifyWith serves an artifact plus a signed
// provenance envelope and verifies it with the pinned --trusted-key and the
// new constraint flags, then asserts constraint mismatches are rejected.
func TestVerifyFlagsPlumbedToVerifyWith(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("artifact-bytes")
	sum := sha256.Sum256(content)
	artifactSHA := hex.EncodeToString(sum[:])
	started := time.Now().UTC().Add(-time.Minute)

	st := provenance.ArtifactStatement(provenance.ArtifactInput{
		Name: "art-1", SHA256: artifactSHA, RunID: "run-1", JobID: "job-1",
		JobKey: "build", Repository: "acme/app", Ref: "refs/heads/main",
		Commit: "abc123", Runner: "runner-1", Started: started, Finished: started.Add(time.Second),
	})
	st.Builder = provenance.BuilderPlaceholder
	st.Issuer = "https://ci.acme.example"
	env, err := provenance.Sign(st, "kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "trusted.pub")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/artifacts/art-1":
			w.Header().Set("X-Kiwi-Content-SHA256", artifactSHA)
			_, _ = w.Write(content)
		case "/api/v1/artifacts/art-1/provenance":
			_, _ = w.Write(envBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// Pinned key + matching constraints: success.
	err = VerifyArtifact([]string{"--server", ts.URL, "--trusted-key", keyPath,
		"--repository", "acme/app", "--commit", "abc123", "--ref", "refs/heads/main",
		"--job", "build", "--builder", "https://kiwi-ci.dev/runner/runner-1", "--issuer", "https://ci.acme.example", "art-1"})
	if err != nil {
		t.Fatalf("verify with pinned key: %v", err)
	}

	// Constraint mismatch must be reported.
	err = VerifyArtifact([]string{"--server", ts.URL, "--trusted-key", keyPath, "--issuer", "https://evil.example", "art-1"})
	if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("issuer constraint not enforced: %v", err)
	}

	// A wrong pinned key must fail signature verification.
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := x509.MarshalPKIXPublicKey(wrongPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(t.TempDir(), "wrong.pub")
	if err := os.WriteFile(wrongPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wrongDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	err = VerifyArtifact([]string{"--server", ts.URL, "--trusted-key", wrongPath, "art-1"})
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("wrong pinned key accepted: %v", err)
	}
}

// TestVerifyJWKSResolverPath keeps the pre-existing JWKS discovery path
// working alongside the new pinned-key mode.
func TestVerifyJWKSResolverPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("jwks-artifact")
	sum := sha256.Sum256(content)
	artifactSHA := hex.EncodeToString(sum[:])
	started := time.Now().UTC().Add(-time.Minute)
	st := provenance.ArtifactStatement(provenance.ArtifactInput{
		Name: "art-2", SHA256: artifactSHA, RunID: "run-2", JobID: "job-2",
		JobKey: "build", Repository: "acme/app", Ref: "main", Commit: "abc",
		Runner: "runner-2", Started: started, Finished: started.Add(time.Second),
	})
	env, err := provenance.Sign(st, "kid-jwks", priv)
	if err != nil {
		t.Fatal(err)
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]any{{
		"kid": "kid-jwks", "x": base64.RawURLEncoding.EncodeToString(pub),
	}}}
	jwksBytes, _ := json.Marshal(jwks)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/artifacts/art-2":
			w.Header().Set("X-Kiwi-Content-SHA256", artifactSHA)
			_, _ = w.Write(content)
		case "/api/v1/artifacts/art-2/provenance":
			_, _ = w.Write(envBytes)
		case "/api/v1/oidc/jwks":
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	if err := VerifyArtifact([]string{"--server", ts.URL, "art-2"}); err != nil {
		t.Fatalf("verify via JWKS: %v", err)
	}
}
