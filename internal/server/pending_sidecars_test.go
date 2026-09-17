package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

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

// TestPendingSidecarCrossReplicaGatesAndConsumes proves the durable
// pending-sidecar contract across replicas: replica A stores the SBOM (a
// shared CAS blob plus a durable pending row), replica B's payload upload
// resolves it through the store, the record carries the digest, and the
// pending row is consumed only after the record is durable.
func TestPendingSidecarCrossReplicaGatesAndConsumes(t *testing.T) {
	s1, s2, f, runnerID, task := sidecarReplicaFixture(t, sbomPipeline)
	sbomDigest := sha256Hex([]byte(validSPDX))

	if w := putSidecar(t, s1, task.Job.ID, ".sbom", validSPDX, runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("sbom upload on replica A = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	_, pending := f.pendingSidecars[fakePendingKey(task.Job.ID, "bin", "sbom")]
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
	_, stillPending := f.pendingSidecars[fakePendingKey(task.Job.ID, "bin", "sbom")]
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
	_, pending := f.pendingSidecars[fakePendingKey(task.Job.ID, "bin", "sbom")]
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
	f.pendingSidecars[fakePendingKey(task.Job.ID, "other", "sigstore")] = fakePendingSidecar{digest: sum, createdAt: time.Now().UTC()}
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
		f.pendingSidecars[fakePendingKey(jobID, "bin", "sbom")] = fakePendingSidecar{digest: strings.Repeat("a", 64), createdAt: stale}
		f.pendingSidecars[fakePendingKey(jobID, "bin", "sigstore")] = fakePendingSidecar{digest: strings.Repeat("b", 64), createdAt: fresh}
		f.mu.Unlock()

		s2.GC(context.Background(), now)

		f.mu.Lock()
		_, staleLeft := f.pendingSidecars[fakePendingKey(jobID, "bin", "sbom")]
		_, freshLeft := f.pendingSidecars[fakePendingKey(jobID, "bin", "sigstore")]
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
		s.pendingSidecars[sidecarPendingKey("job-m", "bin", "sbom")] = encodePendingSidecar(strings.Repeat("a", 64), stale)
		s.pendingSidecars[sidecarPendingKey("job-m", "bin", "sigstore")] = encodePendingSidecar(strings.Repeat("b", 64), fresh)
		s.mu.Unlock()

		s.GC(context.Background(), now)

		s.mu.Lock()
		_, staleLeft := s.pendingSidecars[sidecarPendingKey("job-m", "bin", "sbom")]
		_, freshLeft := s.pendingSidecars[sidecarPendingKey("job-m", "bin", "sigstore")]
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
// the dev-mode pending entry is consumed with the record commit.
func TestPendingSidecarMemoryMirrorConsumed(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	s.mu.Lock()
	s.pendingSidecars[sidecarPendingKey(task.Job.ID, "bin", "sbom")] = encodePendingSidecar(strings.Repeat("c", 64), time.Now().UTC())
	s.mu.Unlock()
	// The artifact contract declares no attestation, so the payload upload
	// succeeds and the mirror entry for the committed record is dropped.
	if w := putArtifact(t, s, task.Job.ID, "mirror-payload", runnerID, task); w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	_, left := s.pendingSidecars[sidecarPendingKey(task.Job.ID, "bin", "sbom")]
	s.mu.Unlock()
	if left {
		t.Fatal("dev-mode mirror entry survived the record commit")
	}
}
