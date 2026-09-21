package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// twoArtifactPipeline declares TWO SBOM-gated artifacts in one job, so the
// sidecar subsystem's artifact scoping (and the per-artifact commit's
// consumption) can be exercised without touching another artifact's pending
// state.
const twoArtifactPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        paths:
          - out/
        sbom: spdx-json
      - name: lib
        paths:
          - out/
        sbom: spdx-json
    steps:
      - run: echo hi
`

// sidecarReplicaFixture builds TWO DB-mode replicas over one durable store
// and one shared CAS, with a single leased job whose artifact contract
// comes from the given pipeline. Replica B's lease key is pinned to A's so
// the same lease token validates on both replicas.
func sidecarReplicaFixture(t *testing.T, pipelineText string) (*Server, *Server, *dbFakeStore, string, Task) {
	t.Helper()
	f := newDBFakeStore()
	shared := cas.New(blob.NewFS(t.TempDir()))
	s1, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s1.SetBlobStore(shared.Blobs)
	if err := s1.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s2.SetBlobStore(shared.Blobs)
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// Production replicas share the lease HMAC key (dataDir); the test pins
	// them together so one lease token validates on both.
	s2.leaseKey = s1.leaseKey
	runnerID, task := leaseArtifactJob(t, s1, pipelineText)
	return s1, s2, f, runnerID, task
}

// restartedReplica builds a fresh replica on the same durable store and CAS
// backend as s (a restart with no in-memory pending mirror).
func restartedReplica(t *testing.T, s *Server, f *dbFakeStore) *Server {
	t.Helper()
	s3, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s3.SetBlobStore(s.BlobStore)
	if err := s3.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s3.leaseKey = s.leaseKey
	return s3
}

// putSidecar uploads the sidecar for the fixture's "bin" artifact.
func putSidecar(t *testing.T, s *Server, jobID, suffix, body, runnerID string, task Task) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin"+suffix, "token", body, leaseHeaders(task, runnerID))
}

// putArtifact uploads the "bin" artifact payload.
func putArtifact(t *testing.T, s *Server, jobID, payload, runnerID string, task Task) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", payload, leaseHeaders(task, runnerID))
}

// bumpLeaseGeneration moves the seeded job onto a NEW lease generation with
// a fresh token (the retry-generation boundary) and returns the lease headers
// a runner of that generation presents.
func bumpLeaseGeneration(t *testing.T, f *dbFakeStore, s *Server, jobID, runnerID, token string, generation int64) map[string]string {
	t.Helper()
	exp := time.Now().UTC().Add(time.Hour)
	f.mu.Lock()
	j := f.jobs[jobID]
	j.LeaseGeneration = generation
	j.LeaseTokenHash = hashLeaseToken(s.leaseKey, token)
	j.LeaseExpiresAt = &exp
	f.jobs[jobID] = j
	f.mu.Unlock()
	return map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": strconv.FormatInt(generation, 10),
	}
}

// storedArtifact returns the fake store's record for one (job, generation,
// name) identity.
func storedArtifact(t *testing.T, f *dbFakeStore, jobID string, generation int64, name string) (model.ArtifactRecord, bool) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.artifacts {
		if a.JobID == jobID && a.LeaseGeneration == generation && a.Name == name {
			return a, true
		}
	}
	return model.ArtifactRecord{}, false
}

// pendingRows returns the fake store's pending-sidecar rows keyed by their
// (job, generation, artifact, kind) key.
func pendingRows(f *dbFakeStore) map[string]fakePendingSidecar {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]fakePendingSidecar, len(f.pendingSidecars))
	for k, v := range f.pendingSidecars {
		out[k] = v
	}
	return out
}

// TestPendingSidecarCrossReplicaGatesAndConsumes proves the durable
// generation-qualified pending-sidecar contract across replicas: replica A
// stores the SBOM (a shared CAS blob plus a durable pending row), replica B's
// payload upload resolves it through the store, the record carries the
// digest, and the pending row is consumed only after the record is durable.
func TestPendingSidecarCrossReplicaGatesAndConsumes(t *testing.T) {
	s1, s2, f, runnerID, task := sidecarReplicaFixture(t, sbomPipeline)
	sbomDigest := sha256Hex([]byte(validSPDX))

	if w := putSidecar(t, s1, task.Job.ID, ".sbom", validSPDX, runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("sbom upload on replica A = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	_, pending := f.pendingSidecars[fakePendingKey(task.Job.ID, task.LeaseGeneration, "bin", "sbom")]
	f.mu.Unlock()
	if !pending {
		t.Fatal("durable pending row not written by replica A")
	}

	// Replica B gates the payload on the DURABLE row (its own mirror is
	// empty) and records the digest reference.
	w := putArtifact(t, s2, task.Job.ID, "cross-replica-payload", runnerID, task)
	if w.Code != http.StatusCreated {
		t.Fatalf("artifact upload on replica B = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.SBOMSHA256 != sbomDigest || rec.SBOMPath != "cas:"+sbomDigest {
		t.Fatalf("record sbom references = %q/%q, want cas:%s", rec.SBOMPath, rec.SBOMSHA256, sbomDigest)
	}
	// The durable record (not just the response) carries the reference.
	f.mu.Lock()
	stored := model.ArtifactRecord{}
	for _, a := range f.artifacts {
		if a.ID == rec.ID {
			stored = a
		}
	}
	_, stillPending := f.pendingSidecars[fakePendingKey(task.Job.ID, task.LeaseGeneration, "bin", "sbom")]
	remaining := len(f.pendingSidecars)
	f.mu.Unlock()
	if stored.SBOMSHA256 != sbomDigest {
		t.Fatalf("stored record sbom = %q, want %q", stored.SBOMSHA256, sbomDigest)
	}
	if stillPending || remaining != 0 {
		t.Fatalf("pending rows after record commit = %d (mine=%v), want 0", remaining, stillPending)
	}
	// The CAS blob stays (content-addressed, referenced by the record).
	if rc, _, err := s2.CAS.Open(context.Background(), sbomDigest); err != nil {
		t.Fatalf("sbom CAS blob missing after consume: %v", err)
	} else {
		rc.Close()
	}
}

// TestPendingSidecarSurvivesReplicaRestart proves the pending state is
// durable: a sidecar uploaded before a restart still gates the artifact
// payload on a brand-new replica instance.
func TestPendingSidecarSurvivesReplicaRestart(t *testing.T) {
	s1, _, f, runnerID, task := sidecarReplicaFixture(t, sbomPipeline)
	sbomDigest := sha256Hex([]byte(validSPDX))
	if w := putSidecar(t, s1, task.Job.ID, ".sbom", validSPDX, runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("sbom upload = %d: %s", w.Code, w.Body.String())
	}

	// "Restart": a fresh server on the same store+CAS has no memory mirror.
	s3 := restartedReplica(t, s1, f)
	w := putArtifact(t, s3, task.Job.ID, "post-restart-payload", runnerID, task)
	if w.Code != http.StatusCreated {
		t.Fatalf("artifact upload after restart = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.SBOMSHA256 != sbomDigest {
		t.Fatalf("post-restart record sbom = %q, want %q", rec.SBOMSHA256, sbomDigest)
	}
	f.mu.Lock()
	remaining := len(f.pendingSidecars)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("pending rows after restart+commit = %d, want 0", remaining)
	}
}

// TestPendingSidecarConsumeOnlyAfterDurableRecord proves the ordering: a
// failed artifact record insert leaves the pending row in place (a crash
// window retry still gates), and only the successful commit consumes it.
func TestPendingSidecarConsumeOnlyAfterDurableRecord(t *testing.T) {
	_, s2, f, runnerID, task := sidecarReplicaFixture(t, sbomPipeline)
	if w := putSidecar(t, s2, task.Job.ID, ".sbom", validSPDX, runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("sbom upload = %d: %s", w.Code, w.Body.String())
	}

	f.mu.Lock()
	f.artifactInsertErr = errors.New("artifact insert: injected failure")
	f.mu.Unlock()
	if w := putArtifact(t, s2, task.Job.ID, "payload-before-crash", runnerID, task); w.Code < 500 {
		t.Fatalf("artifact upload with failing insert = %d, want 5xx", w.Code)
	}
	f.mu.Lock()
	_, pending := f.pendingSidecars[fakePendingKey(task.Job.ID, task.LeaseGeneration, "bin", "sbom")]
	f.mu.Unlock()
	if !pending {
		t.Fatal("failed record insert consumed the durable pending row")
	}

	f.mu.Lock()
	f.artifactInsertErr = nil
	f.mu.Unlock()
	w := putArtifact(t, s2, task.Job.ID, "payload-before-crash", runnerID, task)
	if w.Code != http.StatusCreated {
		t.Fatalf("retried artifact upload = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	remaining := len(f.pendingSidecars)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("pending rows after retried commit = %d, want 0", remaining)
	}
}

// TestRequiredSigstoreWithoutDurablePendingIs422 proves the gate stays
// fail-closed when no DURABLE pending row exists, even with a live lease and
// a configured trust root, and that a row keyed for a different artifact
// name never satisfies the gate.
func TestRequiredSigstoreWithoutDurablePendingIs422(t *testing.T) {
	s1, _, f, runnerID, task := sidecarReplicaFixture(t, sigstorePipeline)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinSigstoreRoot(s1, "key-1", pub)

	if w := putArtifact(t, s1, task.Job.ID, "gated-payload", runnerID, task); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("artifact without pending sigstore = %d, want 422: %s", w.Code, w.Body.String())
	}
	// A pending row for a DIFFERENT artifact name never satisfies this one.
	bundle, _ := buildSigstoreBundle(t, digestOf([]byte("gated-payload")))
	sum := sha256Hex(bundle)
	f.mu.Lock()
	f.pendingSidecars[fakePendingKey(task.Job.ID, task.LeaseGeneration, "other", "sigstore")] = fakePendingSidecar{digest: sum, createdAt: time.Now().UTC()}
	f.mu.Unlock()
	if w := putArtifact(t, s1, task.Job.ID, "gated-payload", runnerID, task); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("artifact with another artifact's pending row = %d, want 422: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	records := len(f.artifacts)
	f.mu.Unlock()
	if records != 0 {
		t.Fatalf("gated uploads recorded %d artifacts, want 0", records)
	}
}

// TestSidecarPendingPersistFailureIs503 proves the sidecar upload fails
// closed (503, never 201) when the durable pending row cannot be written.
func TestSidecarPendingPersistFailureIs503(t *testing.T) {
	s1, _, f, runnerID, task := sidecarReplicaFixture(t, sbomPipeline)
	f.mu.Lock()
	f.pendingErr = errors.New("pending table down")
	f.mu.Unlock()
	w := putSidecar(t, s1, task.Job.ID, ".sbom", validSPDX, runnerID, task)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("sbom upload with failing pending store = %d, want 503: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	f.pendingErr = nil
	rows := len(f.pendingSidecars)
	f.mu.Unlock()
	if rows != 0 {
		t.Fatalf("pending rows after failed upload = %d, want 0", rows)
	}
}

// TestSidecarAttachFailureIs503AndSuccessUnchanged pins P2-11: an existing
// artifact whose sidecar DB attachment fails is answered 503, never 201;
// once the store recovers the identical upload succeeds.
func TestSidecarAttachFailureIs503AndSuccessUnchanged(t *testing.T) {
	s1, _, f, runnerID, task := sidecarReplicaFixture(t, sigstoreOptionalPipeline)
	// The payload commits first (sigstore is declared but not required).
	if w := putArtifact(t, s1, task.Job.ID, "attached-payload", runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	bundle, pub := buildSigstoreBundle(t, digestOf([]byte("attached-payload")))
	pinSigstoreRoot(s1, "key-1", pub)

	f.mu.Lock()
	f.sidecarAttachErr = errors.New("artifact sidecar attach: injected failure")
	f.mu.Unlock()
	w := putSidecar(t, s1, task.Job.ID, ".sigstore", string(bundle), runnerID, task)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("sidecar attach failure = %d, want 503: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"sha256"`) {
		t.Fatalf("failed attachment returned a success body: %s", w.Body.String())
	}

	f.mu.Lock()
	f.sidecarAttachErr = nil
	f.mu.Unlock()
	if w := putSidecar(t, s1, task.Job.ID, ".sigstore", string(bundle), runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("recovered sidecar upload = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	attached := ""
	for _, a := range f.artifacts {
		attached = a.SigstoreSHA256
	}
	f.mu.Unlock()
	if attached != sha256Hex(bundle) {
		t.Fatalf("attached sigstore digest = %q, want %q", attached, sha256Hex(bundle))
	}
}

// TestPendingSidecarMaintenancePrunesExpiredRows proves the tick prune:
// rows older than 7 days are dropped in DB mode (through the durable store)
// and in memory/fs mode (the dev-mode mirror), while fresh rows survive.
func TestPendingSidecarMaintenancePrunesExpiredRows(t *testing.T) {
	now := time.Now().UTC()
	stale := now.Add(-8 * 24 * time.Hour)
	fresh := now.Add(-time.Hour)

	t.Run("db", func(t *testing.T) {
		_, s2, f, _, task := sidecarReplicaFixture(t, sbomPipeline)
		jobID := task.Job.ID
		f.mu.Lock()
		f.pendingSidecars[fakePendingKey(jobID, task.LeaseGeneration, "bin", "sbom")] = fakePendingSidecar{digest: strings.Repeat("a", 64), createdAt: stale}
		f.pendingSidecars[fakePendingKey(jobID, task.LeaseGeneration, "bin", "sigstore")] = fakePendingSidecar{digest: strings.Repeat("b", 64), createdAt: fresh}
		f.mu.Unlock()

		s2.GC(context.Background(), now)

		f.mu.Lock()
		_, staleLeft := f.pendingSidecars[fakePendingKey(jobID, task.LeaseGeneration, "bin", "sbom")]
		_, freshLeft := f.pendingSidecars[fakePendingKey(jobID, task.LeaseGeneration, "bin", "sigstore")]
		f.mu.Unlock()
		if staleLeft {
			t.Fatal("expired pending row survived the maintenance tick")
		}
		if !freshLeft {
			t.Fatal("fresh pending row was pruned by the maintenance tick")
		}
	})

	t.Run("memory", func(t *testing.T) {
		s, err := NewPersistent("token", "token", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.pendingSidecars[sidecarPendingKey("job-m", 1, "bin", "sbom")] = encodePendingSidecar(strings.Repeat("a", 64), stale)
		s.pendingSidecars[sidecarPendingKey("job-m", 2, "bin", "sigstore")] = encodePendingSidecar(strings.Repeat("b", 64), fresh)
		s.mu.Unlock()

		s.GC(context.Background(), now)

		s.mu.Lock()
		_, staleLeft := s.pendingSidecars[sidecarPendingKey("job-m", 1, "bin", "sbom")]
		_, freshLeft := s.pendingSidecars[sidecarPendingKey("job-m", 2, "bin", "sigstore")]
		s.mu.Unlock()
		if staleLeft {
			t.Fatal("expired mirror entry survived the maintenance tick")
		}
		if !freshLeft {
			t.Fatal("fresh mirror entry was pruned by the maintenance tick")
		}
	})
}

// TestPendingSidecarMemoryMirrorConsumed proves the fs/memory mirror path:
// only the committed record's own (job, generation, artifact) entry is
// consumed; another generation's entry survives.
func TestPendingSidecarMemoryMirrorConsumed(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	gen := task.LeaseGeneration
	s.mu.Lock()
	s.pendingSidecars[sidecarPendingKey(task.Job.ID, gen, "bin", "sbom")] = encodePendingSidecar(strings.Repeat("c", 64), time.Now().UTC())
	s.pendingSidecars[sidecarPendingKey(task.Job.ID, gen+1, "bin", "sbom")] = encodePendingSidecar(strings.Repeat("d", 64), time.Now().UTC())
	s.mu.Unlock()
	// The artifact contract declares no attestation, so the payload upload
	// succeeds and the mirror entry for the committed record is dropped.
	if w := putArtifact(t, s, task.Job.ID, "mirror-payload", runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	_, left := s.pendingSidecars[sidecarPendingKey(task.Job.ID, gen, "bin", "sbom")]
	_, otherGen := s.pendingSidecars[sidecarPendingKey(task.Job.ID, gen+1, "bin", "sbom")]
	s.mu.Unlock()
	if left {
		t.Fatal("dev-mode mirror entry survived the record commit")
	}
	if !otherGen {
		t.Fatal("record commit consumed another generation's mirror entry")
	}
}

// TestPendingSidecarsAreArtifactScoped proves the pending-sidecar identity is
// artifact-scoped: one artifact's pending sidecar never satisfies another
// artifact's gate, and an artifact's commit consumes ONLY its own rows.
func TestPendingSidecarsAreArtifactScoped(t *testing.T) {
	s1, _, f, runnerID, task := sidecarReplicaFixture(t, twoArtifactPipeline)
	jobID := task.Job.ID
	gen := task.LeaseGeneration

	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin.sbom", "token", validSPDX, leaseHeaders(task, runnerID)); w.Code != http.StatusCreated {
		t.Fatalf("bin sbom upload = %d: %s", w.Code, w.Body.String())
	}
	// bin's pending SBOM must not satisfy lib's gate.
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/lib", "token", "lib-payload", leaseHeaders(task, runnerID)); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("lib payload with only bin's pending sbom = %d, want 422: %s", w.Code, w.Body.String())
	}
	// Upload lib's own sidecar and payload; lib's commit must not consume
	// bin's still-waiting pending row.
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/lib.sbom", "token", validSPDX, leaseHeaders(task, runnerID)); w.Code != http.StatusCreated {
		t.Fatalf("lib sbom upload = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/lib", "token", "lib-payload", leaseHeaders(task, runnerID)); w.Code != http.StatusCreated {
		t.Fatalf("lib payload upload = %d: %s", w.Code, w.Body.String())
	}
	rows := pendingRows(f)
	if _, ok := rows[fakePendingKey(jobID, gen, "bin", "sbom")]; !ok {
		t.Fatalf("lib's commit consumed bin's pending row: %v", rows)
	}
	if _, ok := rows[fakePendingKey(jobID, gen, "lib", "sbom")]; ok {
		t.Fatalf("lib's own pending row survived its commit: %v", rows)
	}
	// bin still gates on its own row and consumes only it.
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "bin-payload", leaseHeaders(task, runnerID)); w.Code != http.StatusCreated {
		t.Fatalf("bin payload upload = %d: %s", w.Code, w.Body.String())
	}
	if rows := pendingRows(f); len(rows) != 0 {
		t.Fatalf("pending rows after both commits = %v, want none", rows)
	}
}

// TestPendingSidecarsAreLeaseGenerationScoped proves a pending sidecar is
// bound to its lease generation: a previous generation's row never satisfies
// a retry generation's gate, never gets consumed by it, and both generations
// of the SAME artifact name can hold their own rows.
func TestPendingSidecarsAreLeaseGenerationScoped(t *testing.T) {
	s1, _, f, runnerID, task := sidecarReplicaFixture(t, sbomPipeline)
	jobID := task.Job.ID
	gen1 := task.LeaseGeneration
	gen2 := gen1 + 1
	sbom1 := validSPDX
	sbom2 := strings.Replace(validSPDX, `"name":"bin"`, `"name":"bin-gen2"`, 1)
	digest2 := sha256Hex([]byte(sbom2))

	if w := putSidecar(t, s1, jobID, ".sbom", sbom1, runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("gen1 sbom upload = %d: %s", w.Code, w.Body.String())
	}
	// The retry generation must not resolve (or consume) generation 1's row.
	hdrs2 := bumpLeaseGeneration(t, f, s1, jobID, runnerID, "retry-token", gen2)
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "retry-payload", hdrs2); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("retry payload resolved the prior generation's pending sbom = %d, want 422: %s", w.Code, w.Body.String())
	}
	if _, found := storedArtifact(t, f, jobID, gen2, "bin"); found {
		t.Fatal("gated retry upload recorded an artifact")
	}
	// Generation 2 uploads its own sidecar and payload; generation 1's row
	// survives generation 2's commit.
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin.sbom", "token", sbom2, hdrs2); w.Code != http.StatusCreated {
		t.Fatalf("gen2 sbom upload = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "retry-payload", hdrs2); w.Code != http.StatusCreated {
		t.Fatalf("gen2 payload upload = %d: %s", w.Code, w.Body.String())
	}
	rec2, found := storedArtifact(t, f, jobID, gen2, "bin")
	if !found {
		t.Fatal("generation 2 artifact missing")
	}
	if rec2.SBOMSHA256 != digest2 {
		t.Fatalf("generation 2 record sbom = %q, want %q", rec2.SBOMSHA256, digest2)
	}
	rows := pendingRows(f)
	if _, ok := rows[fakePendingKey(jobID, gen1, "bin", "sbom")]; !ok {
		t.Fatalf("generation 2's commit consumed generation 1's pending row: %v", rows)
	}
	if _, ok := rows[fakePendingKey(jobID, gen2, "bin", "sbom")]; ok {
		t.Fatalf("generation 2's own pending row survived its commit: %v", rows)
	}
}

// TestSigstoreRetryGenerationDoesNotInspectPriorArtifact proves the sigstore
// upload's immediate verification is generation-qualified: with a prior
// generation's artifact already recorded, a retry generation's bundle is
// stored (not verified against the wrong payload), and the artifact gate for
// the retry generation verifies it against the RETRY generation's digest.
func TestSigstoreRetryGenerationDoesNotInspectPriorArtifact(t *testing.T) {
	s1, _, f, runnerID, task := sidecarReplicaFixture(t, sigstorePipeline)
	jobID := task.Job.ID
	gen1 := task.LeaseGeneration
	gen2 := gen1 + 1
	priorPayload := "prior-generation-payload"

	// Generation 1 commits an attested payload.
	bundle1, pub1 := buildSigstoreBundle(t, digestOf([]byte(priorPayload)))
	pinSigstoreRoot(s1, "key-1", pub1)
	if w := putSidecar(t, s1, jobID, ".sigstore", string(bundle1), runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("gen1 sigstore upload = %d: %s", w.Code, w.Body.String())
	}
	if w := putArtifact(t, s1, jobID, priorPayload, runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("gen1 payload upload = %d: %s", w.Code, w.Body.String())
	}
	prior, found := storedArtifact(t, f, jobID, gen1, "bin")
	if !found || prior.SigstoreSHA256 != sha256Hex(bundle1) {
		t.Fatalf("generation 1 record = %+v (found=%v), want its bundle attached", prior, found)
	}

	// Retry generation: the bundle attests the RETRY payload's digest. The
	// old code verified it against the prior generation's record (a 422
	// against the wrong digest); generation-qualified selection must store it
	// as pending for the retry generation instead.
	retryPayload := "retry-generation-payload"
	bundle2, pub2 := buildSigstoreBundle(t, digestOf([]byte(retryPayload)))
	pinSigstoreRoot(s1, "key-1", pub2)
	hdrs2 := bumpLeaseGeneration(t, f, s1, jobID, runnerID, "retry-token", gen2)
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin.sigstore", "token", string(bundle2), hdrs2); w.Code != http.StatusCreated {
		t.Fatalf("retry sigstore upload inspected the prior generation's artifact = %d: %s", w.Code, w.Body.String())
	}
	if _, ok := pendingRows(f)[fakePendingKey(jobID, gen2, "bin", "sigstore")]; !ok {
		t.Fatal("retry bundle not stored as pending for the retry generation")
	}
	// The prior generation's record is untouched by the retry upload.
	priorAfter, _ := storedArtifact(t, f, jobID, gen1, "bin")
	if priorAfter.SigstoreSHA256 != sha256Hex(bundle1) || priorAfter.SHA256 != prior.SHA256 {
		t.Fatalf("prior generation artifact mutated: %+v", priorAfter)
	}
	// A payload whose digest the retry bundle does NOT attest is rejected by
	// the gate (deferred verification against the retry digest, not the prior
	// one).
	wrongHdrs := bumpLeaseGeneration(t, f, s1, jobID, runnerID, "retry-token", gen2)
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "wrong-retry-payload", wrongHdrs); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mismatched retry payload = %d, want 422: %s", w.Code, w.Body.String())
	}
	// The attested payload commits and carries the retry bundle.
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", retryPayload, hdrs2); w.Code != http.StatusCreated {
		t.Fatalf("attested retry payload upload = %d: %s", w.Code, w.Body.String())
	}
	rec2, found := storedArtifact(t, f, jobID, gen2, "bin")
	if !found || rec2.SigstoreSHA256 != sha256Hex(bundle2) {
		t.Fatalf("retry generation record = %+v (found=%v), want the retry bundle attached", rec2, found)
	}
}

// TestSidecarUploadDoesNotMutatePriorGenerationArtifact proves a retry
// generation's sidecar upload never attaches to (or otherwise mutates) the
// previous generation's artifact record: it stays pending for its own
// generation.
func TestSidecarUploadDoesNotMutatePriorGenerationArtifact(t *testing.T) {
	s1, _, f, runnerID, task := sidecarReplicaFixture(t, sigstoreOptionalPipeline)
	jobID := task.Job.ID
	gen1 := task.LeaseGeneration
	gen2 := gen1 + 1

	if w := putArtifact(t, s1, jobID, "prior-generation-payload", runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("gen1 payload upload = %d: %s", w.Code, w.Body.String())
	}
	prior, _ := storedArtifact(t, f, jobID, gen1, "bin")

	bundle, pub := buildSigstoreBundle(t, digestOf([]byte("future-retry-payload")))
	pinSigstoreRoot(s1, "key-1", pub)
	hdrs2 := bumpLeaseGeneration(t, f, s1, jobID, runnerID, "retry-token", gen2)
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin.sigstore", "token", string(bundle), hdrs2); w.Code != http.StatusCreated {
		t.Fatalf("retry sigstore upload = %d: %s", w.Code, w.Body.String())
	}
	after, found := storedArtifact(t, f, jobID, gen1, "bin")
	if !found {
		t.Fatal("prior generation artifact disappeared")
	}
	if after.SigstoreSHA256 != "" || after.SigstorePath != "" {
		t.Fatalf("retry sidecar mutated the prior generation's record: %+v", after)
	}
	if after != prior {
		t.Fatalf("prior generation record changed: %+v -> %+v", prior, after)
	}
}

// TestConcurrentMultiArtifactSidecarsSurviveIndependentCommits races two
// replicas uploading two artifacts' sidecars, then commits the two payloads
// concurrently: each artifact's own pending row is consumed by its own
// commit, and neither commit can delete the other artifact's pending state.
func TestConcurrentMultiArtifactSidecarsSurviveIndependentCommits(t *testing.T) {
	s1, s2, f, runnerID, task := sidecarReplicaFixture(t, twoArtifactPipeline)
	jobID := task.Job.ID
	gen := task.LeaseGeneration

	var wg sync.WaitGroup
	errs := make(chan string, 4)
	for _, pair := range []struct {
		srv  *Server
		name string
	}{
		{s1, "bin"},
		{s2, "lib"},
	} {
		wg.Add(1)
		go func(srv *Server, name string) {
			defer wg.Done()
			w := doJSONHeaders(t, srv, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/"+name+".sbom", "token", validSPDX, leaseHeaders(task, runnerID))
			if w.Code != http.StatusCreated {
				errs <- name + " sidecar upload: " + w.Body.String()
			}
		}(pair.srv, pair.name)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("%s", e)
	}
	rows := pendingRows(f)
	for _, name := range []string{"bin", "lib"} {
		if _, ok := rows[fakePendingKey(jobID, gen, name, "sbom")]; !ok {
			t.Fatalf("%s pending row missing before commits: %v", name, rows)
		}
	}

	// Commit both payloads concurrently; the per-job upload lock serializes
	// the commits, but each must consume ONLY its own artifact's rows.
	wg = sync.WaitGroup{}
	commitErrs := make(chan string, 2)
	for _, pair := range []struct {
		srv     *Server
		name    string
		payload string
	}{
		{s1, "bin", "bin-payload"},
		{s2, "lib", "lib-payload"},
	} {
		wg.Add(1)
		go func(srv *Server, name, payload string) {
			defer wg.Done()
			w := doJSONHeaders(t, srv, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/"+name, "token", payload, leaseHeaders(task, runnerID))
			if w.Code != http.StatusCreated {
				commitErrs <- name + " payload upload: " + w.Body.String()
			}
		}(pair.srv, pair.name, pair.payload)
	}
	wg.Wait()
	close(commitErrs)
	for e := range commitErrs {
		t.Fatalf("%s", e)
	}
	for _, name := range []string{"bin", "lib"} {
		rec, found := storedArtifact(t, f, jobID, gen, name)
		if !found {
			t.Fatalf("%s artifact not recorded", name)
		}
		if rec.SBOMSHA256 != sha256Hex([]byte(validSPDX)) {
			t.Fatalf("%s record sbom = %q", name, rec.SBOMSHA256)
		}
	}
	if rows := pendingRows(f); len(rows) != 0 {
		t.Fatalf("pending rows after both commits = %v, want none", rows)
	}
}

// TestSidecarGenerationStoreAPISurface pins the generation-qualified store
// calls the server makes: every pending operation carries the lease
// generation, and a consume for one generation never deletes another's row.
func TestSidecarGenerationStoreAPISurface(t *testing.T) {
	s1, _, f, runnerID, task := sidecarReplicaFixture(t, sbomPipeline)
	_ = runnerID
	if _, ok := s1.sidecarStore(); !ok {
		t.Fatal("DB mode must expose the artifact sidecar store")
	}
	jobID := task.Job.ID
	gen := task.LeaseGeneration
	digest := strings.Repeat("e", 64)
	if err := s1.rememberPendingSidecar(context.Background(), task.Job, "bin", storage.ArtifactSidecarKindSBOM, digest); err != nil {
		t.Fatal(err)
	}
	if d, ok, err := f.PendingSidecar(context.Background(), jobID, gen, "bin", storage.ArtifactSidecarKindSBOM); err != nil || !ok || d != digest {
		t.Fatalf("generation-qualified pending lookup = %q ok=%v err=%v", d, ok, err)
	}
	if _, ok, _ := f.PendingSidecar(context.Background(), jobID, gen+1, "bin", storage.ArtifactSidecarKindSBOM); ok {
		t.Fatal("pending lookup leaked across generations")
	}
	// The server-side consume carries the RECORD's generation; a stale
	// generation's consume leaves the row in place.
	stale := model.ArtifactRecord{JobID: jobID, Name: "bin", LeaseGeneration: gen + 1, SBOMSHA256: digest}
	if err := s1.consumeArtifactPendingSidecars(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.PendingSidecar(context.Background(), jobID, gen, "bin", storage.ArtifactSidecarKindSBOM); !ok {
		t.Fatal("stale-generation consume deleted the pending row")
	}
	own := model.ArtifactRecord{JobID: jobID, Name: "bin", LeaseGeneration: gen, SBOMSHA256: digest}
	if err := s1.consumeArtifactPendingSidecars(context.Background(), own); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.PendingSidecar(context.Background(), jobID, gen, "bin", storage.ArtifactSidecarKindSBOM); ok {
		t.Fatal("own-generation consume left the pending row behind")
	}
}
