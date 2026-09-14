package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/supplychain"
)

const sbomPipeline = `version: 1
jobs:
  build:
    runtime: container
    artifacts:
      - name: bin
        paths:
          - out/
        sbom: spdx-json
    steps:
      - run: echo hi
`

const sigstorePipeline = `version: 1
jobs:
  build:
    runtime: container
    artifacts:
      - name: bin
        paths:
          - out/
        sigstore:
          required: true
          issuer: https://token.actions.githubusercontent.com
          identity: my-identity
    steps:
      - run: echo hi
`

const validSPDX = `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","name":"bin","dataLicense":"CC0-1.0","documentNamespace":"https://kiwi-ci.dev/sbom/x","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: kiwi-ci"]},"packages":[{"SPDXID":"SPDXRef-Package-bin","name":"bin","downloadLocation":"NOASSERTION","filesAnalyzed":true}],"files":[]}`

// buildSigstoreBundle crafts a Sigstore bundle attesting digest with the
// expected issuer/identity claims, embedded key verification material.
func buildSigstoreBundle(t *testing.T, digest string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := supplychain.SignArtifact(priv, "key-1", digest, "o/r", "refs/heads/main", supplychain.SignOptions{
		Issuer:   "https://token.actions.githubusercontent.com",
		Identity: "my-identity",
	})
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(env, &envelope); err != nil {
		t.Fatal(err)
	}
	bundle := map[string]any{
		"mediaType": supplychain.SigstoreBundleMediaType,
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{
				"rawBytes":   base64.StdEncoding.EncodeToString(pub),
				"keyDetails": "PKIX_ED25519",
			},
			"logEntries": []any{},
		},
		"dsseEnvelope": envelope,
	}
	b, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// seedLeasedArtifactJob injects a leased, running job whose pipeline text
// carries sbom/sigstore declarations. The strict pipeline schema does not
// admit those keys yet (pipeline phase), so the job is seeded directly and
// the server's lenient attestation extraction is exercised.
func seedLeasedArtifactJob(t *testing.T, s *Server, pipelineText string) (runnerID, jobID string, hdrs map[string]string) {
	t.Helper()
	runnerID = "runner-seeded"
	jobID, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	rawToken := "seed-lease-token"
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	s.mu.Lock()
	s.runners[runnerID] = model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}
	s.runs["run-seed"] = model.Run{ID: "run-seed", Repo: "https://example.com/o/r.git", RepoFullName: "o/r", Ref: "refs/heads/main", SHA: "abc", CreatedAt: now, Status: model.StatusRunning}
	s.jobs[jobID] = model.Job{ID: jobID, RunID: "run-seed", Key: "build", BaseKey: "build", Pipeline: pipelineText, Status: model.StatusRunning, LeaseRunnerID: runnerID, LeaseTokenHash: hashLeaseToken(s.leaseKey, rawToken), LeaseGeneration: 1, LeaseExpiresAt: &exp, StartedAt: &now, CreatedAt: now}
	s.mu.Unlock()
	hdrs = map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      rawToken,
		"X-Kiwi-Lease-Generation": "1",
	}
	return runnerID, jobID, hdrs
}

func TestSBOMRequiredMissingRejectsArtifact(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sbomPipeline)
	path := "/api/v1/jobs/" + jobID + "/artifacts/bin"
	w := doJSONHeaders(t, s, http.MethodPut, path, "token", "payload", hdrs)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing sbom = %d, want 422: %s", w.Code, w.Body.String())
	}
}

func TestSBOMInvalidFormatRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sbomPipeline)
	path := "/api/v1/jobs/" + jobID + "/artifacts/bin.sbom"
	// Not JSON at all.
	if w := doJSONHeaders(t, s, http.MethodPut, path, "token", "not-json", hdrs); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid sbom json = %d, want 422: %s", w.Code, w.Body.String())
	}
	// Valid JSON but the wrong format (cyclonedx when spdx declared).
	if w := doJSONHeaders(t, s, http.MethodPut, path, "token", `{"bomFormat":"CycloneDX","specVersion":"1.5"}`, hdrs); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong sbom format = %d, want 422: %s", w.Code, w.Body.String())
	}
}

func TestSBOMAndSigstoreGateHappyPath(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sigstorePipeline)
	jobPath := "/api/v1/jobs/" + jobID + "/artifacts/"

	// The artifact payload is gated on the sigstore bundle.
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin", "token", "signed-bytes", hdrs); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing sigstore = %d, want 422: %s", w.Code, w.Body.String())
	}
	// A bundle whose claims do not match the artifact digest is rejected.
	bundle := buildSigstoreBundle(t, digestOf([]byte("other")))
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin.sigstore", "token", string(bundle), hdrs); w.Code != http.StatusCreated {
		t.Fatalf("sigstore upload = %d: %s", w.Code, w.Body.String())
	}
	// The gate then rejects the artifact whose digest differs from the
	// stored bundle.
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin", "token", "signed-bytes", hdrs); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("digest-mismatched artifact = %d, want 422: %s", w.Code, w.Body.String())
	}
}

func TestSigstoreRequiredMissingIs422(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sigstorePipeline)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "payload", hdrs)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("sigstore required missing = %d, want 422: %s", w.Code, w.Body.String())
	}
}

func TestSBOMHappyPathRecordsSBOM(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sbomPipeline)
	jobPath := "/api/v1/jobs/" + jobID + "/artifacts/"
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin.sbom", "token", validSPDX, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("sbom upload = %d: %s", w.Code, w.Body.String())
	}
	w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin", "token", "payload", hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.SBOMSHA256 == "" {
		t.Fatal("sbom attestation not recorded on the artifact record")
	}
}
