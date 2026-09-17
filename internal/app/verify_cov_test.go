package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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

func TestVerifyArtifactArgumentErrors(t *testing.T) {
	if err := VerifyArtifact([]string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := VerifyArtifact(nil); err == nil {
		t.Fatal("missing artifact ID accepted")
	}
	if err := VerifyArtifact([]string{"a", "b"}); err == nil {
		t.Fatal("extra arguments accepted")
	}
	if err := VerifyArtifact([]string{"--server", "http://[::1", "art"}); err == nil {
		t.Fatal("malformed server URL accepted")
	}
	if err := VerifyArtifact([]string{"--server", "http://127.0.0.1:1", "art"}); err == nil {
		t.Fatal("unreachable server accepted")
	}
}

func TestVerifyArtifactHTTPErrors(t *testing.T) {
	// The artifact endpoint rejects the request.
	notFound := jsonServer(t, http.StatusNotFound, "no such artifact")
	if err := VerifyArtifact([]string{"--server", notFound.URL, "art"}); err == nil {
		t.Fatal("404 artifact accepted")
	}
	// The artifact body is shorter than its declared length: io.Copy fails.
	shortBody := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1024")
		_, _ = w.Write([]byte("short"))
	})
	if err := VerifyArtifact([]string{"--server", shortBody.URL, "art"}); err == nil {
		t.Fatal("truncated artifact body accepted")
	}
	// The advertised digest does not match the downloaded bytes.
	digestMismatch := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Kiwi-Content-SHA256", strings.Repeat("0", 64))
		_, _ = w.Write([]byte("artifact"))
	})
	err := VerifyArtifact([]string{"--server", digestMismatch.URL, "art"})
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("digest mismatch = %v", err)
	}
	// The provenance endpoint fails after a successful artifact download.
	provFail := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/provenance") {
			http.Error(w, "no provenance", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("artifact"))
	})
	if err := VerifyArtifact([]string{"--server", provFail.URL, "art"}); err == nil {
		t.Fatal("provenance failure accepted")
	}
	// The JWKS endpoint fails.
	jwksFail := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/provenance") {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/jwks") {
			http.Error(w, "no jwks", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("artifact"))
	})
	if err := VerifyArtifact([]string{"--server", jwksFail.URL, "art"}); err == nil {
		t.Fatal("jwks failure accepted")
	}
}

func TestVerifyArtifactJWKSInvalidKeysAndSubjectMismatch(t *testing.T) {
	content := []byte("subject-artifact")
	sum := sha256.Sum256(content)
	artifactSHA := hex.EncodeToString(sum[:])
	started := time.Now().UTC().Add(-time.Minute)
	// The statement describes DIFFERENT bytes: signature verification
	// succeeds (the envelope is valid) but the subject binding fails.
	st := provenance.ArtifactStatement(provenance.ArtifactInput{
		Name: "art", SHA256: strings.Repeat("a", 64), RunID: "r", JobID: "j",
		JobKey: "build", Repository: "acme/app", Ref: "main", Commit: "c",
		Runner: "runner", Started: started, Finished: started.Add(time.Second),
	})
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := provenance.Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	envBytes, _ := json.Marshal(env)
	jwks := map[string]any{"keys": []map[string]any{
		{"kid": "bad-b64", "x": "!!!"},
		{"kid": "short", "x": "AAAA"},
	}}
	jwksBytes, _ := json.Marshal(jwks)
	srv := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/provenance"):
			_, _ = w.Write(envBytes)
		case strings.HasSuffix(r.URL.Path, "/jwks"):
			_, _ = w.Write(jwksBytes)
		default:
			_, _ = w.Write(content)
		}
	})
	err = VerifyArtifact([]string{"--server", srv.URL, "art"})
	if err == nil {
		t.Fatal("subject mismatch accepted")
	}
	_ = artifactSHA
}

func TestVerifyArtifactJWKSRoundTripMismatch(t *testing.T) {
	// JWKS resolves, signature verifies, but the signed subject names other
	// bytes: the binding check rejects the artifact.
	content := []byte("bound-artifact")
	st := provenance.ArtifactStatement(provenance.ArtifactInput{
		Name: "art", SHA256: strings.Repeat("b", 64), RunID: "r", JobID: "j",
		JobKey: "build", Repository: "acme/app", Ref: "main", Commit: "c",
		Runner: "runner", Started: time.Now().UTC(), Finished: time.Now().UTC(),
	})
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := provenance.Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	envBytes, _ := json.Marshal(env)
	jwksBytes, _ := json.Marshal(map[string]any{"keys": []map[string]any{
		{"kid": "kid", "x": base64RawURL(pub)},
	}})
	srv := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/provenance"):
			_, _ = w.Write(envBytes)
		case strings.HasSuffix(r.URL.Path, "/jwks"):
			_, _ = w.Write(jwksBytes)
		default:
			_, _ = w.Write(content)
		}
	})
	err = VerifyArtifact([]string{"--server", srv.URL, "--token", "tok", "art"})
	if err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("subject binding = %v", err)
	}
}

func TestLoadTrustedPublicKeyErrors(t *testing.T) {
	if _, err := loadTrustedPublicKey(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("missing key file accepted")
	}
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrustedPublicKey(junk); err == nil {
		t.Fatal("junk PEM accepted")
	}
	wrongType := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(wrongType, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrustedPublicKey(wrongType); err == nil {
		t.Fatal("non-PUBLIC-KEY PEM accepted")
	}
	brokenDER := filepath.Join(t.TempDir(), "broken.pem")
	if err := os.WriteFile(brokenDER, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrustedPublicKey(brokenDER); err == nil {
		t.Fatal("unparseable PKIX key accepted")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPath := filepath.Join(t.TempDir(), "rsa.pem")
	if err := os.WriteFile(rsaPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTrustedPublicKey(rsaPath); err == nil {
		t.Fatal("RSA key accepted as Ed25519")
	}
}

func TestVerifyArtifactTrustedKeyLoadFailure(t *testing.T) {
	srv := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("artifact"))
	})
	if err := VerifyArtifact([]string{"--server", srv.URL, "--trusted-key", filepath.Join(t.TempDir(), "missing.pem"), "art"}); err == nil {
		t.Fatal("missing trusted key accepted")
	}
}

func TestFetchBytesAndFetchJSONErrors(t *testing.T) {
	failing := jsonServer(t, http.StatusBadGateway, "upstream")
	if _, err := fetchBytes(&http.Client{Timeout: time.Second}, failing.URL, "tok"); err == nil {
		t.Fatal("fetchBytes 502 accepted")
	}
	if err := fetchJSON(&http.Client{Timeout: time.Second}, failing.URL, "tok", &struct{}{}); err == nil {
		t.Fatal("fetchJSON 502 accepted")
	}
	if err := fetchJSON(&http.Client{Timeout: time.Second}, failing.URL, "tok", nil); err == nil {
		t.Fatal("fetchJSON 502 accepted with nil out")
	}
	if _, err := fetchBytes(&http.Client{Timeout: time.Second}, "http://[::1", ""); err == nil {
		t.Fatal("fetchBytes malformed URL accepted")
	}
	if err := fetchJSON(&http.Client{Timeout: time.Second}, "http://[::1", "", &struct{}{}); err == nil {
		t.Fatal("fetchJSON malformed URL accepted")
	}
	brokenJSON := jsonServer(t, http.StatusOK, `{`)
	if err := fetchJSON(&http.Client{Timeout: time.Second}, brokenJSON.URL, "", &struct{}{}); err == nil {
		t.Fatal("fetchJSON malformed body accepted")
	}
	unreachable := &http.Client{Timeout: time.Second}
	if _, err := fetchBytes(unreachable, "http://127.0.0.1:1", ""); err == nil {
		t.Fatal("fetchBytes unreachable accepted")
	}
	if err := fetchJSON(unreachable, "http://127.0.0.1:1", "", &struct{}{}); err == nil {
		t.Fatal("fetchJSON unreachable accepted")
	}
	ts := jsonServer(t, http.StatusOK, `{"ok":true}`)
	if _, err := fetchBytes(&http.Client{Timeout: time.Second}, ts.URL, "tok"); err != nil {
		t.Fatalf("fetchBytes success: %v", err)
	}
	var out map[string]bool
	if err := fetchJSON(&http.Client{Timeout: time.Second}, ts.URL, "tok", &out); err != nil || !out["ok"] {
		t.Fatalf("fetchJSON success: %v %v", out, err)
	}
}

func base64RawURL(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		sb.WriteByte(alphabet[chunk[0]>>2])
		sb.WriteByte(alphabet[(chunk[0]&0x3)<<4|chunk[1]>>4])
		if n > 1 {
			sb.WriteByte(alphabet[(chunk[1]&0xf)<<2|chunk[2]>>6])
		}
		if n > 2 {
			sb.WriteByte(alphabet[chunk[2]&0x3f])
		}
	}
	return sb.String()
}

var _ = httptest.NewServer
var _ = context.Background
