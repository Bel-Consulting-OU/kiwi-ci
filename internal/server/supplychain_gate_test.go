package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/supplychain"
)

const sbomPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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

const sigstoreOptionalPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        paths:
          - out/
        sigstore:
          issuer: https://token.actions.githubusercontent.com
          identity: my-identity
    steps:
      - run: echo hi
`

const validSPDX = `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","name":"bin","dataLicense":"CC0-1.0","documentNamespace":"https://kiwi-ci.dev/sbom/x","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: kiwi-ci"]},"packages":[{"SPDXID":"SPDXRef-Package-bin","name":"bin","downloadLocation":"NOASSERTION","filesAnalyzed":true}],"files":[]}`

// buildSigstoreBundle crafts a Sigstore bundle attesting digest with the
// expected issuer/identity claims, embedded key verification material. The
// generated verification public key is returned so tests can pin it as the
// server's trust root.
func buildSigstoreBundle(t *testing.T, digest string) ([]byte, ed25519.PublicKey) {
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
	return b, pub
}

// pinSigstoreRoot pins the given verification key under keyID as the
// server's Sigstore trust root.
func pinSigstoreRoot(s *Server, keyID string, pub ed25519.PublicKey) {
	s.SetSigstoreTrustRoot(map[string]ed25519.PublicKey{keyID: pub}, nil, "")
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

	bundle, pub := buildSigstoreBundle(t, digestOf([]byte("other")))
	pinSigstoreRoot(s, "key-1", pub)

	// The artifact payload is gated on the sigstore bundle.
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin", "token", "signed-bytes", hdrs); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing sigstore = %d, want 422: %s", w.Code, w.Body.String())
	}
	// A bundle attesting a different digest is stored (verification
	// happens against the payload at gate time).
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
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinSigstoreRoot(s, "key-1", pub)
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sigstorePipeline)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "payload", hdrs)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("sigstore required missing = %d, want 422: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "required sigstore bundle missing") {
		t.Fatalf("unexpected rejection reason: %s", w.Body.String())
	}
}

func TestSigstoreUploadWithoutTrustRootRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// No trust root configured: the upload must fail closed.
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sigstorePipeline)
	bundle, _ := buildSigstoreBundle(t, digestOf([]byte("payload")))
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin.sigstore", "token", string(bundle), hdrs)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("sigstore upload without trust root = %d, want 422: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "trust root") {
		t.Fatalf("unexpected rejection reason: %s", w.Body.String())
	}
}

func TestSigstoreRequiredArtifactWithoutTrustRootRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sigstorePipeline)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "payload", hdrs)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("sigstore required without trust root = %d, want 422: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "trust root") {
		t.Fatalf("unexpected rejection reason: %s", w.Body.String())
	}
}

func TestSigstoreUploadPinnedKeyMatchAccepted(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sigstoreOptionalPipeline)
	jobPath := "/api/v1/jobs/" + jobID + "/artifacts/"
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin", "token", "signed-bytes", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	bundle, pub := buildSigstoreBundle(t, digestOf([]byte("signed-bytes")))
	pinSigstoreRoot(s, "key-1", pub)
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin.sigstore", "token", string(bundle), hdrs); w.Code != http.StatusCreated {
		t.Fatalf("pinned-key sigstore upload = %d: %s", w.Code, w.Body.String())
	}
}

func TestSigstoreUploadPinnedKeyMismatchRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pinned, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sigstoreOptionalPipeline)
	jobPath := "/api/v1/jobs/" + jobID + "/artifacts/"
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin", "token", "signed-bytes", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	// The bundle is signed by a key that is not pinned.
	bundle, _ := buildSigstoreBundle(t, digestOf([]byte("signed-bytes")))
	pinSigstoreRoot(s, "pinned-key", pinned)
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin.sigstore", "token", string(bundle), hdrs); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unpinned-key sigstore upload = %d, want 422: %s", w.Code, w.Body.String())
	}
}

// blockingBody yields its data and then blocks forever, so a handler that
// keeps reading past its size limit hangs instead of returning.
type blockingBody struct {
	data  []byte
	read  int
	block chan struct{}
}

func (b *blockingBody) Read(p []byte) (int, error) {
	if b.read >= len(b.data) {
		<-b.block
		return 0, io.EOF
	}
	n := copy(p, b.data[b.read:])
	b.read += n
	return n, nil
}

func (b *blockingBody) Close() error {
	select {
	case <-b.block:
	default:
		close(b.block)
	}
	return nil
}

func TestSigstoreUploadOversizeRejectedWithoutReadingBody(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinSigstoreRoot(s, "key-1", pub)
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sigstorePipeline)
	body := &blockingBody{data: make([]byte, maxSigstoreBytes+64), block: make(chan struct{})}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin.sigstore", body)
	req.Header.Set("Authorization", "Bearer token")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.Handler().ServeHTTP(w, req)
		close(done)
	}()
	select {
	case <-done:
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("oversized sigstore bundle = %d, want 422: %s", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return: the body was being read past the size limit")
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

// bumpMemoryLeaseGeneration moves a memory-mode job onto a NEW lease
// generation with a fresh token (the retry-generation boundary) and returns
// the lease headers that generation's runner presents.
func bumpMemoryLeaseGeneration(t *testing.T, s *Server, jobID, runnerID, token string, generation int64) map[string]string {
	t.Helper()
	exp := time.Now().UTC().Add(time.Hour)
	s.mu.Lock()
	j := s.jobs[jobID]
	j.LeaseGeneration = generation
	j.LeaseTokenHash = hashLeaseToken(s.leaseKey, token)
	j.LeaseExpiresAt = &exp
	s.jobs[jobID] = j
	s.mu.Unlock()
	return map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": strconv.FormatInt(generation, 10),
	}
}

// TestFSSidecarImmutableAcrossLeaseGenerations is the C4-A regression: fs
// sidecars live at <dir>/g-<generation>/<base>.<kind>.<sha256>.json, so two
// generations of the SAME artifact name own distinct files, every record
// resolves to its own digest and file, and a retry can never overwrite (or
// otherwise mutate) the file the prior generation's record still points at.
// Expired-artifact cleanup then removes only the expired generation's file
// (and its now-empty generation directory).
func TestFSSidecarImmutableAcrossLeaseGenerations(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Pure fs mode: no CAS backend, so records and the gate resolve the
	// local per-generation sidecar files this test pins.
	s.CAS = nil
	s.BlobStore = nil
	runnerID, task := leaseArtifactJob(t, s, sbomPipeline)
	jobID := task.Job.ID
	gen1 := task.LeaseGeneration
	gen2 := gen1 + 1
	jobPath := "/api/v1/jobs/" + jobID + "/artifacts/"
	sbom1 := validSPDX
	sbom2 := strings.Replace(validSPDX, `"name":"bin"`, `"name":"bin-gen2"`, 1)

	// Generation 1: sbom + payload commit, and the record resolves the
	// generation-1 file.
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin.sbom", "token", sbom1, leaseHeaders(task, runnerID)); w.Code != http.StatusCreated {
		t.Fatalf("gen1 sbom upload = %d: %s", w.Code, w.Body.String())
	}
	w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin", "token", "payload-1", leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("gen1 payload upload = %d: %s", w.Code, w.Body.String())
	}
	var rec1 model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec1); err != nil {
		t.Fatal(err)
	}
	if rec1.SBOMSHA256 != digestOf([]byte(sbom1)) {
		t.Fatalf("gen1 sbom digest = %q, want %q", rec1.SBOMSHA256, digestOf([]byte(sbom1)))
	}
	if !strings.Contains(rec1.SBOMPath, string(filepath.Separator)+"g-"+strconv.FormatInt(gen1, 10)+string(filepath.Separator)) ||
		!strings.HasSuffix(rec1.SBOMPath, "."+rec1.SBOMSHA256+".json") {
		t.Fatalf("gen1 sbom path %q is not generation+digest qualified", rec1.SBOMPath)
	}
	before1, err := os.ReadFile(rec1.SBOMPath)
	if err != nil || string(before1) != sbom1 {
		t.Fatalf("gen1 sidecar bytes = %q, %v", before1, err)
	}

	// Retry generation 2: its own sbom (different bytes) and payload commit.
	hdrs2 := bumpMemoryLeaseGeneration(t, s, jobID, runnerID, "retry-token", gen2)
	if w := doJSONHeaders(t, s, http.MethodPut, jobPath+"bin.sbom", "token", sbom2, hdrs2); w.Code != http.StatusCreated {
		t.Fatalf("gen2 sbom upload = %d: %s", w.Code, w.Body.String())
	}
	w = doJSONHeaders(t, s, http.MethodPut, jobPath+"bin", "token", "payload-2", hdrs2)
	if w.Code != http.StatusCreated {
		t.Fatalf("gen2 payload upload = %d: %s", w.Code, w.Body.String())
	}
	var rec2 model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec2); err != nil {
		t.Fatal(err)
	}
	if rec2.SBOMSHA256 != digestOf([]byte(sbom2)) {
		t.Fatalf("gen2 sbom digest = %q, want %q", rec2.SBOMSHA256, digestOf([]byte(sbom2)))
	}
	if rec1.SBOMPath == rec2.SBOMPath {
		t.Fatalf("generations share one sidecar file: %q", rec1.SBOMPath)
	}
	if !strings.Contains(rec2.SBOMPath, string(filepath.Separator)+"g-"+strconv.FormatInt(gen2, 10)+string(filepath.Separator)) {
		t.Fatalf("gen2 sbom path %q is not generation-qualified", rec2.SBOMPath)
	}
	// Each record's digest matches the bytes at its own path.
	for name, rec := range map[string]model.ArtifactRecord{"gen1": rec1, "gen2": rec2} {
		b, err := os.ReadFile(rec.SBOMPath)
		if err != nil {
			t.Fatalf("%s sidecar unreadable: %v", name, err)
		}
		if sha256Hex(b) != rec.SBOMSHA256 {
			t.Fatalf("%s sidecar digest mismatch: file=%s record=%s", name, sha256Hex(b), rec.SBOMSHA256)
		}
	}
	if b1, _ := os.ReadFile(rec1.SBOMPath); string(b1) != sbom1 {
		t.Fatalf("gen2 upload rewrote the gen1 file: %q", b1)
	}
	if b2, _ := os.ReadFile(rec2.SBOMPath); string(b2) != sbom2 {
		t.Fatalf("gen2 file bytes = %q", b2)
	}
	// Gate resolution stays generation-qualified even without the pending
	// mirror (a restart): the generation directory holds exactly one file.
	s.mu.Lock()
	delete(s.pendingSidecars, sidecarPendingKey(jobID, gen1, "bin", "sbom"))
	delete(s.pendingSidecars, sidecarPendingKey(jobID, gen2, "bin", "sbom"))
	s.mu.Unlock()
	dir := filepath.Join(s.store.Root, "artifacts", task.Job.RunID, jobID)
	if b, err := s.sidecarBytes(context.Background(), model.Job{ID: jobID, LeaseGeneration: gen2}, "bin", "sbom", dir); err != nil || string(b) != sbom2 {
		t.Fatalf("gen2 file fallback = %q, %v", b, err)
	}
	if b, err := s.sidecarBytes(context.Background(), model.Job{ID: jobID, LeaseGeneration: gen1}, "bin", "sbom", dir); err != nil || string(b) != sbom1 {
		t.Fatalf("gen1 file fallback = %q, %v", b, err)
	}

	// Cleanup removes ONLY the expired generation's sidecar file; the live
	// generation's file and directory survive.
	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)
	s.mu.Lock()
	r1 := s.artifacts[rec1.ID]
	r1.ExpiresAt = &past
	s.artifacts[rec1.ID] = r1
	r2 := s.artifacts[rec2.ID]
	r2.ExpiresAt = &future
	s.artifacts[rec2.ID] = r2
	removed := s.cleanupExpiredArtifactsLocked(time.Now().UTC())
	s.mu.Unlock()
	if removed != 1 {
		t.Fatalf("cleanup removed %d records, want 1", removed)
	}
	if _, err := os.Stat(rec1.SBOMPath); !os.IsNotExist(err) {
		t.Fatalf("expired generation's sidecar survived cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(rec1.SBOMPath)); !os.IsNotExist(err) {
		t.Fatalf("expired generation's directory survived cleanup: %v", err)
	}
	if b, err := os.ReadFile(rec2.SBOMPath); err != nil || !bytes.Equal(b, []byte(sbom2)) {
		t.Fatalf("live generation's sidecar was removed or changed: %q, %v", b, err)
	}
}
