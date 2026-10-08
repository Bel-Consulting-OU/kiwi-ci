package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

func attestationVerifyFixture(t *testing.T) ([]byte, ed25519.PublicKey, string) {
	t.Helper()
	start := time.Unix(1700000000, 0).UTC()
	finish := start.Add(time.Minute)
	st, err := provenance.ExecutionAttestationStatement(provenance.ExecutionAttestationInput{
		RunID: "run-1", JobID: "job-1", JobKey: "build", Generation: 3,
		Status: "success", StartedAt: &start, FinishedAt: &finish, RunnerIdentity: "runner-1",
		CapsuleDigest:          strings.Repeat("a", 64),
		ExecutionCapsuleDigest: strings.Repeat("b", 64),
		ObservedRuntime:        &model.ObservedRuntime{OS: "linux", Arch: "amd64"},
		Artifacts: []provenance.ExecutionAttestationArtifact{
			{Name: "bin", SHA256: strings.Repeat("1", 64), Size: 3, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := provenance.Sign(st, "kid-att", priv)
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
	return envBytes, pub, keyPath
}

// TestVerifyExecutionAttestationModes covers the attestation verify mode:
// server fetch, file mode, matching/mismatching constraints, tampering and
// internal inconsistency all exit non-zero on failure.
func TestVerifyExecutionAttestationModes(t *testing.T) {
	envBytes, _, keyPath := attestationVerifyFixture(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/jobs/job-1/attestation":
			if got := r.URL.Query().Get("generation"); got != "" && got != "3" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(envBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	base := []string{"--server", ts.URL, "--trusted-key", keyPath, "--attestation", "job-1"}
	if err := VerifyArtifact(base); err != nil {
		t.Fatalf("valid attestation: %v", err)
	}
	if err := VerifyArtifact(append(append([]string{}, base...), "--generation", "3")); err != nil {
		t.Fatalf("explicit generation: %v", err)
	}
	if err := VerifyArtifact([]string{"--server", ts.URL, "--trusted-key", keyPath, "--attestation", "job-1", "--generation", "9"}); err == nil {
		t.Fatal("missing generation accepted")
	}

	// Constraints: matching passes, each mismatch fails.
	if err := VerifyArtifact(append(append([]string{}, base...), "--attempt", "job-1:3", "--capsule-digest", strings.Repeat("a", 64), "--execution-capsule-digest", strings.Repeat("b", 64))); err != nil {
		t.Fatalf("matching constraints: %v", err)
	}
	for name, extra := range map[string][]string{
		"attempt":                  {"--attempt", "job-1:4"},
		"capsule-digest":           {"--capsule-digest", strings.Repeat("f", 64)},
		"execution-capsule-digest": {"--execution-capsule-digest", strings.Repeat("f", 64)},
	} {
		if err := VerifyArtifact(append(append([]string{}, base...), extra...)); err == nil {
			t.Fatalf("%s mismatch accepted", name)
		}
	}

	// File mode.
	attPath := filepath.Join(t.TempDir(), "attestation.json")
	if err := os.WriteFile(attPath, envBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact([]string{"--trusted-key", keyPath, "--attestation-file", attPath}); err != nil {
		t.Fatalf("file mode: %v", err)
	}

	// A payload byte tamper fails the signature.
	var env provenance.Envelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)/2] ^= 0x01
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	tampered, _ := json.Marshal(env)
	tamperedPath := filepath.Join(t.TempDir(), "tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact([]string{"--trusted-key", keyPath, "--attestation-file", tamperedPath}); err == nil {
		t.Fatal("tampered attestation verified")
	}

	// A validly signed statement whose block does not bind its subject is
	// rejected by the internal consistency check even though the signature
	// verifies.
	st, err := provenance.ExecutionAttestationStatement(provenance.ExecutionAttestationInput{
		RunID: "run-1", JobID: "job-1", Generation: 3, Status: "success",
	})
	if err != nil {
		t.Fatal(err)
	}
	inconsistent := *st.Attestation
	inconsistent.Status = "failure"
	st.Attestation = &inconsistent
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badEnv, err := provenance.Sign(st, "kid-att", priv)
	if err != nil {
		t.Fatal(err)
	}
	badBytes, _ := json.Marshal(badEnv)
	badPath := filepath.Join(t.TempDir(), "inconsistent.json")
	if err := os.WriteFile(badPath, badBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	// Sign with a key the resolver trusts: regenerate the pinned key from the
	// same private key so only consistency (not the signature) is at fault.
	der, _ := x509.MarshalPKIXPublicKey(priv.Public())
	badKeyPath := filepath.Join(t.TempDir(), "bad.pub")
	if err := os.WriteFile(badKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	err = VerifyArtifact([]string{"--trusted-key", badKeyPath, "--attestation-file", badPath})
	if err == nil || !strings.Contains(err.Error(), "evidence block") {
		t.Fatalf("inconsistent attestation = %v, want a block-binding error", err)
	}
}

// TestVerifyExecutionAttestationJWKS keeps the JWKS discovery path working
// for attestation mode.
func TestVerifyExecutionAttestationJWKS(t *testing.T) {
	envBytes, pub, _ := attestationVerifyFixture(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/jobs/job-1/attestation":
			_, _ = w.Write(envBytes)
		case "/api/v1/oidc/jwks":
			body, _ := json.Marshal(map[string]any{"keys": []map[string]any{{"kid": "kid-att", "x": base64RawURL(pub)}}})
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	if err := VerifyArtifact([]string{"--server", ts.URL, "--attestation", "job-1", "--attempt", "job-1:3"}); err != nil {
		t.Fatalf("JWKS attestation verify: %v", err)
	}
}

// TestVerifyAttestationUsageErrors pins the argument contract: mutually
// exclusive modes and stray positional arguments are rejected.
func TestVerifyAttestationUsageErrors(t *testing.T) {
	if err := VerifyArtifact([]string{"--attestation", "j", "--attestation-file", "f"}); err == nil {
		t.Fatal("conflicting modes accepted")
	}
	if err := VerifyArtifact([]string{"--attestation", "j", "extra"}); err == nil {
		t.Fatal("positional argument with attestation mode accepted")
	}
	if err := VerifyArtifact([]string{"--attestation", "j", "--generation", "-1"}); err == nil {
		t.Fatal("negative generation accepted")
	}
}
