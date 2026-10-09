package server

import (
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestAttestationBindsCompletionDigestWithoutRawValues proves the signed
// attestation binds the durable v2 completion identity by DIGEST only: the
// envelope carries completionResultDigest and the full evidence root, never a
// raw output or error value, and a different output set produces a different
// digest and therefore a different attestation subject.
func TestAttestationBindsCompletionDigestWithoutRawValues(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedAttestationJob(t, s, "job-a", "run-a", 3)
	outputs := map[string]string{"release": "OUTPUT-SENTINEL-9f3a"}
	runtimeA := &model.ObservedRuntime{OS: "linux", Arch: "amd64"}
	digestA := storage.CompletionResultDigestV2(model.StatusSuccess, "", outputs, runtimeA)
	s.mu.Lock()
	s.completions[completionReceiptKey("job-a", 3, "runner-a")] = model.CompletionReceipt{
		JobID: "job-a", Generation: 3, RunnerID: "runner-a",
		ResultHash: digestA, ResultHashVersion: storage.CompletionResultHashVersionV2,
	}
	s.mu.Unlock()

	if err := s.attestExecution(context.Background(), "job-a", 3); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	s.mu.Lock()
	rec, found := s.attestations[model.AttemptID("job-a", 3)]
	s.mu.Unlock()
	if !found {
		t.Fatal("attestation record missing")
	}
	st, envBytes := verifyAttestationEnvelope(t, s, rec)
	if st.Attestation.CompletionResultDigest != digestA {
		t.Fatalf("completionResultDigest = %q, want %q", st.Attestation.CompletionResultDigest, digestA)
	}
	if st.Attestation.EvidenceRootSHA256 == "" {
		t.Fatal("evidenceRootSha256 not bound")
	}
	// No raw output or error value may appear anywhere in the envelope.
	raw := string(envBytes)
	if strings.Contains(raw, "OUTPUT-SENTINEL-9f3a") {
		t.Fatalf("envelope leaked a raw output value: %s", raw)
	}
	// The signed root is exactly the canonical root of the durable records.
	ev, ok := s.gatherAttestationEvidenceLocal("job-a", 3)
	if !ok {
		t.Fatal("evidence no longer gatherable")
	}
	in := attestationInput(ev, 3)
	if in.EvidenceRootSHA256 != st.Attestation.EvidenceRootSHA256 {
		t.Fatalf("signed evidence root = %q, recomputed = %q", st.Attestation.EvidenceRootSHA256, in.EvidenceRootSHA256)
	}

	// A different completion payload (changed outputs) changes the completion
	// digest and therefore the attestation subject digest.
	seedAttestationJob(t, s, "job-b", "run-b", 1)
	digestB := storage.CompletionResultDigestV2(model.StatusSuccess, "", map[string]string{"release": "other"}, runtimeA)
	s.mu.Lock()
	s.completions[completionReceiptKey("job-b", 1, "runner-a")] = model.CompletionReceipt{
		JobID: "job-b", Generation: 1, RunnerID: "runner-a",
		ResultHash: digestB, ResultHashVersion: storage.CompletionResultHashVersionV2,
	}
	s.mu.Unlock()
	if err := s.attestExecution(context.Background(), "job-b", 1); err != nil {
		t.Fatalf("attestExecution job-b: %v", err)
	}
	s.mu.Lock()
	recB := s.attestations[model.AttemptID("job-b", 1)]
	s.mu.Unlock()
	stB, _ := verifyAttestationEnvelope(t, s, recB)
	if stB.Attestation.CompletionResultDigest != digestB {
		t.Fatalf("job-b completionResultDigest = %q, want %q", stB.Attestation.CompletionResultDigest, digestB)
	}
	if st.Subject[0].Digest["sha256"] == stB.Subject[0].Digest["sha256"] {
		t.Fatal("different completion identities produced the same attestation digest")
	}
}

// TestAttestationEvidenceRootBindsSidecarRefs proves changing an artifact
// sidecar reference (SBOM/sigstore/provenance) changes the evidence root and
// therefore the signed subject, and that tampering with the root field breaks
// verification while the intact statement verifies.
func TestAttestationEvidenceRootBindsSidecarRefs(t *testing.T) {
	build := func(sbomPath string) (*Server, model.ExecutionAttestationRecord, provenance.Statement) {
		t.Helper()
		s, err := NewPersistent("token", "token", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		seedAttestationJob(t, s, "job-a", "run-a", 3)
		s.mu.Lock()
		art := s.artifacts["art-1"]
		art.SBOMPath = sbomPath
		art.SBOMSHA256 = strings.Repeat("b", 64)
		art.SigstorePath = "cas:sigstore-1"
		art.SigstoreSHA256 = strings.Repeat("c", 64)
		s.artifacts["art-1"] = art
		s.mu.Unlock()
		if err := s.attestExecution(context.Background(), "job-a", 3); err != nil {
			t.Fatalf("attestExecution: %v", err)
		}
		s.mu.Lock()
		rec := s.attestations[model.AttemptID("job-a", 3)]
		s.mu.Unlock()
		st, _ := verifyAttestationEnvelope(t, s, rec)
		return s, rec, st
	}
	_, _, first := build("cas:sbom-alpha")
	_, _, second := build("cas:sbom-beta")
	if first.Attestation.EvidenceRootSHA256 == "" || second.Attestation.EvidenceRootSHA256 == "" {
		t.Fatal("evidence root not bound")
	}
	if first.Attestation.EvidenceRootSHA256 == second.Attestation.EvidenceRootSHA256 {
		t.Fatal("changing an SBOM sidecar ref did not change the evidence root")
	}
	if first.Subject[0].Digest["sha256"] == second.Subject[0].Digest["sha256"] {
		t.Fatal("changing a sidecar ref did not change the attestation digest")
	}
	// The intact statement verifies; a block whose root disagrees with the
	// subject must be refused even though the per-item lists are unchanged.
	if err := provenance.VerifyExecutionAttestation(first); err != nil {
		t.Fatalf("intact statement does not verify: %v", err)
	}
	tampered := first
	cp := *first.Attestation
	cp.EvidenceRootSHA256 = strings.Repeat("f", 64)
	tampered.Attestation = &cp
	if err := provenance.VerifyExecutionAttestation(tampered); err == nil {
		t.Fatal("tampered evidence root accepted")
	}
}

// TestAttestationScopesEvidenceToTheJob keeps the per-generation assertion
// and adds the multi-job dimension: a run with two completed jobs at the SAME
// generation attests each job with only its own artifacts/reports/snapshots.
func TestAttestationScopesEvidenceToTheJob(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedAttestationJob(t, s, "job-a", "run-a", 3)
	s.mu.Lock()
	s.jobs["job-z"] = model.Job{ID: "job-z", RunID: "run-a", Key: "other", Status: model.StatusSuccess, LeaseGeneration: 3}
	s.artifacts["art-z"] = model.ArtifactRecord{ID: "art-z", RunID: "run-a", JobID: "job-z", Name: "zbin", SHA256: strings.Repeat("a", 64), Size: 1, LeaseGeneration: 3}
	s.reports["rep-z"] = model.TestReport{ID: "rep-z", RunID: "run-a", JobID: "job-z", JobKey: "other", LeaseGeneration: 3}
	s.snapshots["snap-z"] = model.SnapshotRecord{ID: "snap-z", RunID: "run-a", JobID: "job-z", Phase: model.SnapshotPhasePostJob, SHA256: strings.Repeat("b", 64), LeaseGeneration: 3}
	s.mu.Unlock()

	if err := s.attestExecution(context.Background(), "job-a", 3); err != nil {
		t.Fatalf("attestExecution job-a: %v", err)
	}
	if err := s.attestExecution(context.Background(), "job-z", 3); err != nil {
		t.Fatalf("attestExecution job-z: %v", err)
	}
	s.mu.Lock()
	recA := s.attestations[model.AttemptID("job-a", 3)]
	recZ := s.attestations[model.AttemptID("job-z", 3)]
	s.mu.Unlock()
	stA, _ := verifyAttestationEnvelope(t, s, recA)
	stZ, _ := verifyAttestationEnvelope(t, s, recZ)

	for _, a := range stA.Attestation.Artifacts {
		if a.Name == "zbin" {
			t.Fatalf("job-a attestation includes job-z artifact: %+v", a)
		}
	}
	if len(stA.Attestation.Artifacts) != 1 || stA.Attestation.Artifacts[0].Name != "bin" {
		t.Fatalf("job-a artifacts = %+v", stA.Attestation.Artifacts)
	}
	if len(stA.Attestation.TestReports) != 1 || stA.Attestation.TestReports[0].Name != "test" {
		t.Fatalf("job-a reports = %+v", stA.Attestation.TestReports)
	}
	if len(stA.Attestation.Snapshots) != 2 {
		t.Fatalf("job-a snapshots = %+v", stA.Attestation.Snapshots)
	}
	if len(stZ.Attestation.Artifacts) != 1 || stZ.Attestation.Artifacts[0].Name != "zbin" {
		t.Fatalf("job-z artifacts = %+v", stZ.Attestation.Artifacts)
	}
	if len(stZ.Attestation.TestReports) != 1 || stZ.Attestation.TestReports[0].Name != "other" {
		t.Fatalf("job-z reports = %+v", stZ.Attestation.TestReports)
	}
	if len(stZ.Attestation.Snapshots) != 1 || stZ.Attestation.Snapshots[0].ID != "snap-z" {
		t.Fatalf("job-z snapshots = %+v", stZ.Attestation.Snapshots)
	}
}

// attestationCountingStore records which evidence reads the emitter performs.
// The scoped and run-scoped methods are BOTH visible: the emitter must pick
// the attempt-scoped contract.
type attestationCountingStore struct {
	*dbFakeStore
	scopedCalls int
	runCalls    int
}

func (c *attestationCountingStore) ListArtifactsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.ArtifactRecord, error) {
	c.scopedCalls++
	return c.dbFakeStore.ListArtifactsByJobGeneration(ctx, jobID, generation)
}

func (c *attestationCountingStore) ListTestReportsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.TestReport, error) {
	c.scopedCalls++
	return c.dbFakeStore.ListTestReportsByJobGeneration(ctx, jobID, generation)
}

func (c *attestationCountingStore) ListSnapshotsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.SnapshotRecord, error) {
	c.scopedCalls++
	return c.dbFakeStore.ListSnapshotsByJobGeneration(ctx, jobID, generation)
}

func (c *attestationCountingStore) ListArtifacts(ctx context.Context, runID string) ([]model.ArtifactRecord, error) {
	c.runCalls++
	return c.dbFakeStore.ListArtifacts(ctx, runID)
}

func (c *attestationCountingStore) ListTestReports(ctx context.Context, runID string) ([]model.TestReport, error) {
	c.runCalls++
	return c.dbFakeStore.ListTestReports(ctx, runID)
}

func (c *attestationCountingStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	c.runCalls++
	return c.dbFakeStore.ListSnapshotsByRun(ctx, runID)
}

// TestAttestationUsesAttemptScopedQueries proves the emitter issues the
// indexed attempt-scoped reads when the store implements the optional
// contract, and performs no run-scoped load at all.
func TestAttestationUsesAttemptScopedQueries(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	counting := &attestationCountingStore{dbFakeStore: newDBFakeStore()}
	s.DB = counting
	s.ensureProvenanceKey()
	seedAttestationJob(t, s, "job-a", "run-a", 2)
	counting.mu.Lock()
	counting.runs["run-a"] = s.runs["run-a"]
	counting.jobs["job-a"] = s.jobs["job-a"]
	counting.artifacts = append(counting.artifacts,
		model.ArtifactRecord{ID: "a-1", RunID: "run-a", JobID: "job-a", Name: "bin", SHA256: strings.Repeat("1", 64), LeaseGeneration: 2},
		model.ArtifactRecord{ID: "a-old", RunID: "run-a", JobID: "job-a", Name: "old", SHA256: strings.Repeat("2", 64), LeaseGeneration: 1},
	)
	counting.reports = append(counting.reports,
		model.TestReport{ID: "r-1", RunID: "run-a", JobID: "job-a", JobKey: "test", LeaseGeneration: 2},
		model.TestReport{ID: "r-old", RunID: "run-a", JobID: "job-a", JobKey: "test", LeaseGeneration: 1},
	)
	counting.snapshots = append(counting.snapshots,
		model.SnapshotRecord{ID: "s-1", RunID: "run-a", JobID: "job-a", Phase: model.SnapshotPhasePostJob, SHA256: strings.Repeat("3", 64), LeaseGeneration: 2},
	)
	counting.mu.Unlock()

	if err := s.attestExecution(context.Background(), "job-a", 2); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	counting.mu.Lock()
	scoped, run := counting.scopedCalls, counting.runCalls
	counting.mu.Unlock()
	if scoped != 3 {
		t.Fatalf("attempt-scoped evidence queries = %d, want 3", scoped)
	}
	if run != 0 {
		t.Fatalf("run-scoped evidence loads = %d, want 0 when the optional contract is present", run)
	}
	counting.mu.Lock()
	rec := counting.attestations[model.AttemptID("job-a", 2)]
	counting.mu.Unlock()
	st, _ := verifyAttestationEnvelope(t, s, rec)
	if len(st.Attestation.Artifacts) != 1 || st.Attestation.Artifacts[0].Name != "bin" {
		t.Fatalf("scoped evidence not used: %+v", st.Attestation.Artifacts)
	}
}

// attestationRunScopedOnlyStore hides the optional AttemptEvidenceStore
// contract by embedding the storage.Store INTERFACE (not the fake): only the
// explicitly declared methods exist on the wrapper, so the emitter must take
// the documented run-scoped fallback.
type attestationRunScopedOnlyStore struct {
	storage.Store
	inner    *dbFakeStore
	runCalls int
}

func (w *attestationRunScopedOnlyStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	return w.inner.GetJob(ctx, id)
}

func (w *attestationRunScopedOnlyStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	return w.inner.GetRun(ctx, id)
}

func (w *attestationRunScopedOnlyStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	return w.inner.HasCompletionReceipt(ctx, jobID, generation, runnerID)
}

func (w *attestationRunScopedOnlyStore) ListArtifacts(ctx context.Context, runID string) ([]model.ArtifactRecord, error) {
	w.runCalls++
	return w.inner.ListArtifacts(ctx, runID)
}

func (w *attestationRunScopedOnlyStore) ListTestReports(ctx context.Context, runID string) ([]model.TestReport, error) {
	w.runCalls++
	return w.inner.ListTestReports(ctx, runID)
}

func (w *attestationRunScopedOnlyStore) InsertSnapshotRecord(ctx context.Context, rec model.SnapshotRecord) error {
	return w.inner.InsertSnapshotRecord(ctx, rec)
}

func (w *attestationRunScopedOnlyStore) GetSnapshot(ctx context.Context, runID, snapshotID string) (model.SnapshotRecord, bool, error) {
	return w.inner.GetSnapshot(ctx, runID, snapshotID)
}

func (w *attestationRunScopedOnlyStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	w.runCalls++
	return w.inner.ListSnapshotsByRun(ctx, runID)
}

func (w *attestationRunScopedOnlyStore) GetExecutionAttestation(ctx context.Context, jobID string, generation int64) (model.ExecutionAttestationRecord, bool, error) {
	return w.inner.GetExecutionAttestation(ctx, jobID, generation)
}

func (w *attestationRunScopedOnlyStore) CommitExecutionAttestation(ctx context.Context, rec model.ExecutionAttestationRecord, event model.ExecutionEvent) (model.ExecutionAttestationRecord, bool, error) {
	return w.inner.CommitExecutionAttestation(ctx, rec, event)
}

// The DB-mode attestation path publishes the envelope through the CAS digest
// fence capability; the fallback store delegates it like every other
// capability the fake implements.
func (w *attestationRunScopedOnlyStore) WithDigestFence(ctx context.Context, digest string, fn func() error) error {
	return w.inner.WithDigestFence(ctx, digest, fn)
}

func (w *attestationRunScopedOnlyStore) AcquireDigestFence(ctx context.Context, digest string) (func(), error) {
	return w.inner.AcquireDigestFence(ctx, digest)
}

func (w *attestationRunScopedOnlyStore) AcquireNamedFence(ctx context.Context, namespace, key string) (func(), error) {
	return w.inner.AcquireNamedFence(ctx, namespace, key)
}

// TestAttestationFallsBackWithoutScopedContract proves a store that lacks the
// optional attempt-scoped contract still attests, via the documented
// run-scoped load plus the Go-side attempt filter.
func TestAttestationFallsBackWithoutScopedContract(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inner := newDBFakeStore()
	fallback := &attestationRunScopedOnlyStore{inner: inner}
	s.DB = fallback
	s.ensureProvenanceKey()
	seedAttestationJob(t, s, "job-a", "run-a", 2)
	inner.mu.Lock()
	inner.runs["run-a"] = s.runs["run-a"]
	inner.jobs["job-a"] = s.jobs["job-a"]
	inner.artifacts = append(inner.artifacts,
		model.ArtifactRecord{ID: "a-1", RunID: "run-a", JobID: "job-a", Name: "bin", SHA256: strings.Repeat("1", 64), LeaseGeneration: 2},
		model.ArtifactRecord{ID: "a-old", RunID: "run-a", JobID: "job-a", Name: "old", SHA256: strings.Repeat("2", 64), LeaseGeneration: 1},
	)
	inner.reports = append(inner.reports, model.TestReport{ID: "r-1", RunID: "run-a", JobID: "job-a", JobKey: "test", LeaseGeneration: 2})
	inner.snapshots = append(inner.snapshots, model.SnapshotRecord{ID: "s-1", RunID: "run-a", JobID: "job-a", Phase: model.SnapshotPhasePostJob, SHA256: strings.Repeat("3", 64), LeaseGeneration: 2})
	inner.mu.Unlock()

	if err := s.attestExecution(context.Background(), "job-a", 2); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	if fallback.runCalls != 3 {
		t.Fatalf("run-scoped fallback loads = %d, want 3", fallback.runCalls)
	}
	inner.mu.Lock()
	rec, found := inner.attestations[model.AttemptID("job-a", 2)]
	inner.mu.Unlock()
	if !found {
		t.Fatal("fallback attestation not committed")
	}
	st, _ := verifyAttestationEnvelope(t, s, rec)
	if len(st.Attestation.Artifacts) != 1 || st.Attestation.Artifacts[0].Name != "bin" {
		t.Fatalf("fallback filter wrong: %+v", st.Attestation.Artifacts)
	}
}
