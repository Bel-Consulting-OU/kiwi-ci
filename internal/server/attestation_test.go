package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

const attestationTestPipeline = "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc\n    steps:\n      - run: echo hi\n"

// seedAttestationJob seeds one completed attempt with per-generation
// artifacts, reports, snapshots, observed runtime and a bindable compiled
// payload so both capsule digests resolve.
func seedAttestationJob(t *testing.T, s *Server, jobID, runID string, generation int64) {
	t.Helper()
	spec, err := pipeline.Parse([]byte(attestationTestPipeline))
	if err != nil {
		t.Fatal(err)
	}
	pd, err := pipeline.PipelineDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	cj := graph.Jobs["build"]
	cjJSON, err := json.Marshal(cj)
	if err != nil {
		t.Fatal(err)
	}
	policyJSON, err := json.Marshal(policy.DefaultTrustedCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	jobSum := sha256.Sum256(cjJSON)
	compiled := &model.CompiledJobPayload{
		SchemaVersion: 1, CompilerVersion: "test",
		PipelineDigest: pd, JobDigest: hex.EncodeToString(jobSum[:]),
		EffectiveJob: json.RawMessage(cjJSON), EffectivePolicy: json.RawMessage(policyJSON),
	}
	start := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	finish := start.Add(2 * time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[runID] = model.Run{ID: runID, RepoID: "github.com/acme/repo-a", Repo: "https://github.com/acme/repo-a.git", RepoFullName: "acme/repo-a", Ref: "refs/heads/main", SHA: "abc", Status: model.StatusSuccess}
	s.jobs[jobID] = model.Job{
		ID: jobID, RunID: runID, Key: "build", Status: model.StatusSuccess,
		StartedAt: &start, FinishedAt: &finish, LeaseGeneration: generation,
		AttemptRunnerID: "runner-a", Trusted: true,
		Pipeline:           attestationTestPipeline,
		CompiledJobPayload: compiled,
		ObservedRuntime:    &model.ObservedRuntime{OS: "linux", Arch: "amd64", RuntimeName: "docker", MainImage: "alpine:3.20"},
	}
	s.artifacts["art-1"] = model.ArtifactRecord{ID: "art-1", RunID: runID, JobID: jobID, Name: "bin", SHA256: strings.Repeat("1", 64), Size: 11, LeaseGeneration: generation, ProvenanceSHA256: strings.Repeat("2", 64)}
	s.artifacts["art-old"] = model.ArtifactRecord{ID: "art-old", RunID: runID, JobID: jobID, Name: "old", SHA256: strings.Repeat("3", 64), Size: 9, LeaseGeneration: generation - 1}
	s.reports["rep-1"] = model.TestReport{ID: "rep-1", RunID: runID, JobID: jobID, JobKey: "test", LeaseGeneration: generation, Cases: []model.TestResult{{Name: "a", Passed: true}}}
	s.reports["rep-old"] = model.TestReport{ID: "rep-old", RunID: runID, JobID: jobID, JobKey: "test", LeaseGeneration: generation - 1}
	s.snapshots["snap-pre"] = model.SnapshotRecord{ID: "snap-pre", RunID: runID, JobID: jobID, Phase: model.SnapshotPhasePreJob, SHA256: strings.Repeat("4", 64), RootSHA256: strings.Repeat("5", 64), LeaseGeneration: generation}
	s.snapshots["snap-post"] = model.SnapshotRecord{ID: "snap-post", RunID: runID, JobID: jobID, Phase: model.SnapshotPhasePostJob, SHA256: strings.Repeat("6", 64), RootSHA256: strings.Repeat("7", 64), LeaseGeneration: generation}
	s.snapshots["snap-old"] = model.SnapshotRecord{ID: "snap-old", RunID: runID, JobID: jobID, Phase: model.SnapshotPhasePostJob, SHA256: strings.Repeat("8", 64), LeaseGeneration: generation - 1}
}

// verifyAttestationEnvelope opens and verifies one stored attestation record
// with the server's provenance key.
func verifyAttestationEnvelope(t *testing.T, s *Server, rec model.ExecutionAttestationRecord) (provenance.Statement, []byte) {
	t.Helper()
	envBytes, err := s.readExecutionAttestationEnvelope(context.Background(), rec)
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	pub := s.ensureProvenanceKey().Public
	st, err := provenance.VerifyWith(envBytes, nil, provenance.VerifyOptions{TrustedKey: pub})
	if err != nil {
		t.Fatalf("verify envelope: %v", err)
	}
	if err := provenance.VerifyExecutionAttestation(st); err != nil {
		t.Fatalf("attestation consistency: %v", err)
	}
	return st, envBytes
}

// TestAttestationEffectBindsDurableEvidence builds the attestation in
// fs/memory mode and proves the statement binds the attempt's exact
// per-generation evidence, observed runtime and capsule digests.
func TestAttestationEffectBindsDurableEvidence(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedAttestationJob(t, s, "job-a", "run-a", 3)
	if err := s.attestExecution(context.Background(), "job-a", 3); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	s.mu.Lock()
	rec, found := s.attestations[model.AttemptID("job-a", 3)]
	records := len(s.attestations)
	s.mu.Unlock()
	if !found || records != 1 {
		t.Fatalf("attestation records = %d found=%v", records, found)
	}
	if rec.RunID != "run-a" || rec.Status != string(model.StatusSuccess) || rec.StatementSHA256 == "" || rec.EnvelopeRef == "" {
		t.Fatalf("record = %+v", rec)
	}
	st, _ := verifyAttestationEnvelope(t, s, rec)
	att := st.Attestation
	if att == nil || att.AttemptID != "job-a:3" || att.Status != "success" || att.RunnerIdentity != "runner-a" {
		t.Fatalf("attestation = %+v", att)
	}
	if att.CapsuleDigest == "" || att.ExecutionCapsuleDigest == "" {
		t.Fatalf("capsule digests not bound: %+v", att)
	}
	if att.ObservedRuntime == nil || att.ObservedRuntime.OS != "linux" || att.ObservedRuntime.MainImage != "alpine:3.20" {
		t.Fatalf("observed runtime not bound: %+v", att.ObservedRuntime)
	}
	if len(att.Artifacts) != 1 || att.Artifacts[0].Name != "bin" || att.Artifacts[0].ProvenanceSHA256 == "" {
		t.Fatalf("artifacts = %+v", att.Artifacts)
	}
	if len(att.TestReports) != 1 || att.TestReports[0].Generation != 3 || att.TestReports[0].SuiteDigest == "" {
		t.Fatalf("reports = %+v", att.TestReports)
	}
	if len(att.Snapshots) != 2 || att.WorkspaceRootSHA256 != strings.Repeat("5", 64) || att.MaterialRootSHA256 != strings.Repeat("7", 64) {
		t.Fatalf("snapshots/roots = %+v %q %q", att.Snapshots, att.WorkspaceRootSHA256, att.MaterialRootSHA256)
	}
	// execution.attested lands next to the marker in the fs event journal.
	events, _, err := s.store.ListExecutionEvents(context.Background(), 0, 100, "run-a")
	if err != nil {
		t.Fatal(err)
	}
	attested := 0
	for _, e := range events {
		if e.Type == model.EventExecutionAttested {
			attested++
			if e.Attempt != 3 {
				t.Fatalf("attested event attempt = %d, want 3", e.Attempt)
			}
		}
	}
	if attested != 1 {
		t.Fatalf("execution.attested events = %d, want 1", attested)
	}
	// Re-running the effect is a marker no-op: still one record and one event.
	if err := s.attestExecution(context.Background(), "job-a", 3); err != nil {
		t.Fatal(err)
	}
	events, _, err = s.store.ListExecutionEvents(context.Background(), 0, 100, "run-a")
	if err != nil {
		t.Fatal(err)
	}
	attested = 0
	for _, e := range events {
		if e.Type == model.EventExecutionAttested {
			attested++
		}
	}
	if attested != 1 {
		t.Fatalf("repeated reconcile emitted %d attested events, want 1", attested)
	}
}

// TestAttestationEffectIdempotentDBWithCAS proves the DB-mode effect commits
// exactly one row, one CAS object and one execution.attested event under
// repeated and concurrent reconciliation.
func TestAttestationEffectIdempotentDBWithCAS(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	s.DB = f
	s.ensureProvenanceKey()
	f.mu.Lock()
	f.runs["run-a"] = model.Run{ID: "run-a", RepoID: "github.com/acme/repo-a", Repo: "https://github.com/acme/repo-a.git", RepoFullName: "acme/repo-a", Status: model.StatusSuccess}
	f.jobs["job-a"] = model.Job{
		ID: "job-a", RunID: "run-a", Key: "build", Status: model.StatusSuccess, LeaseGeneration: 2,
		AttemptRunnerID: "runner-a",
		ObservedRuntime: &model.ObservedRuntime{OS: "linux", Arch: "amd64"},
	}
	f.artifacts = append(f.artifacts, model.ArtifactRecord{ID: "a1", RunID: "run-a", JobID: "job-a", Name: "bin", SHA256: strings.Repeat("1", 64), LeaseGeneration: 2})
	f.reports = append(f.reports, model.TestReport{ID: "r1", RunID: "run-a", JobID: "job-a", JobKey: "test", LeaseGeneration: 2})
	f.snapshots = append(f.snapshots, model.SnapshotRecord{ID: "sn1", RunID: "run-a", JobID: "job-a", Phase: model.SnapshotPhasePreJob, SHA256: strings.Repeat("4", 64), RootSHA256: strings.Repeat("5", 64), LeaseGeneration: 2})
	f.mu.Unlock()

	for i := 0; i < 3; i++ {
		if err := s.attestExecution(context.Background(), "job-a", 2); err != nil {
			t.Fatalf("attestExecution %d: %v", i, err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.attestExecution(context.Background(), "job-a", 2); err != nil {
				t.Errorf("concurrent attestExecution: %v", err)
			}
		}()
	}
	wg.Wait()

	f.mu.Lock()
	records := len(f.attestations)
	events := append([]model.ExecutionEvent{}, f.executionEvents...)
	rec := f.attestations[model.AttemptID("job-a", 2)]
	f.mu.Unlock()
	if records != 1 {
		t.Fatalf("attestation rows = %d, want 1", records)
	}
	attested := 0
	for _, e := range events {
		if e.Type == model.EventExecutionAttested {
			attested++
		}
	}
	if attested != 1 {
		t.Fatalf("execution.attested events = %d, want 1", attested)
	}
	if !strings.HasPrefix(rec.EnvelopeRef, "cas:") {
		t.Fatalf("envelope ref = %q, want a cas: object", rec.EnvelopeRef)
	}
	st, envBytes := verifyAttestationEnvelope(t, s, rec)
	if st.Attestation.AttemptID != "job-a:2" {
		t.Fatalf("attempt = %q", st.Attestation.AttemptID)
	}
	// The CAS object is the envelope exactly once.
	digest := strings.TrimPrefix(rec.EnvelopeRef, "cas:")
	rc, obj, err := s.CAS.Open(context.Background(), digest)
	if err != nil {
		t.Fatalf("CAS object missing: %v", err)
	}
	_ = rc.Close()
	if obj.Size != int64(len(envBytes)) || obj.SHA256 != digest {
		t.Fatalf("CAS object = %+v, want digest %s size %d", obj, digest, len(envBytes))
	}
	files := 0
	blobRoot := s.BlobStore.(*blob.FS).Root
	walkErr := filepath.WalkDir(filepath.Join(blobRoot, "sha256"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files++
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if files != 1 {
		t.Fatalf("CAS objects under the blob root = %d, want exactly 1", files)
	}
}

// TestControllerCapabilityAttestationScope pins the new endpoint's tier and
// run-scoped evidence:read decision, plus its 404-when-absent and signed
// envelope content.
func TestControllerCapabilityAttestationScope(t *testing.T) {
	s, runA, runB := capabilityServer(t)
	jobA := jobIDForRun(t, s, runA.ID)
	jobB := jobIDForRun(t, s, runB.ID)

	cases := []struct {
		name, token, path string
		want              int
	}{
		{"repo-scoped evidence reaches its run (no attestation yet)", "repo-evidence", "/api/v1/jobs/" + jobA + "/attestation", http.StatusNotFound},
		{"global evidence reaches any run", "global-evidence", "/api/v1/jobs/" + jobA + "/attestation", http.StatusNotFound},
		{"admin token unchanged", "admin-tok", "/api/v1/jobs/" + jobA + "/attestation", http.StatusNotFound},
		{"repo-scoped evidence denied another repo", "repo-evidence", "/api/v1/jobs/" + jobB + "/attestation", http.StatusForbidden},
		{"checkpoints capability denied", "checkpoints-a", "/api/v1/jobs/" + jobA + "/attestation", http.StatusForbidden},
		{"plain repo reader denied", "reader-a", "/api/v1/jobs/" + jobA + "/attestation", http.StatusForbidden},
		{"runner bearer refused", "runner-tok", "/api/v1/jobs/" + jobA + "/attestation", http.StatusUnauthorized},
		{"unknown job 404", "admin-tok", "/api/v1/jobs/missing/attestation", http.StatusNotFound},
	}
	for _, tc := range cases {
		if w := doJSON(t, s, http.MethodGet, tc.path, tc.token, ""); w.Code != tc.want {
			t.Errorf("%s: GET %s with %s = %d, want %d: %s", tc.name, tc.path, tc.token, w.Code, tc.want, w.Body.String())
		}
	}

	// Seed the attestation for the queued job (generation 0) and serve it.
	if err := s.attestExecution(context.Background(), jobA, 0); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/jobs/"+jobA+"/attestation", "repo-evidence", "")
	if w.Code != http.StatusOK {
		t.Fatalf("attestation GET = %d: %s", w.Code, w.Body.String())
	}
	var env provenance.Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	st, err := provenance.VerifyWith(w.Body.Bytes(), nil, provenance.VerifyOptions{TrustedKey: s.ensureProvenanceKey().Public})
	if err != nil {
		t.Fatalf("verify served envelope: %v", err)
	}
	if st.Attestation == nil || st.Attestation.JobID != jobA {
		t.Fatalf("served attestation = %+v", st.Attestation)
	}
	// A generation with no attestation answers 404.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/jobs/"+jobA+"/attestation?generation=9", "repo-evidence", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing generation = %d, want 404", w.Code)
	}
	// A malformed generation is a 400 after authorization.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/jobs/"+jobA+"/attestation?generation=x", "repo-evidence", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("bad generation = %d, want 400", w.Code)
	}
}

// TestAttestationFailsClosedOnStoreFailure proves a store failure keeps the
// effect retryable: no marker is written and the error surfaces.
func TestAttestationFailsClosedOnStoreFailure(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	s.DB = f
	seedAttestationJob(t, s, "job-a", "run-a", 1)
	f.mu.Lock()
	f.jobs["job-a"] = s.jobs["job-a"]
	f.runs["run-a"] = s.runs["run-a"]
	f.mu.Unlock()
	f.mu.Lock()
	f.attestationErr = errTestAttestationStore
	f.mu.Unlock()
	if err := s.attestExecution(context.Background(), "job-a", 1); err == nil {
		t.Fatal("store failure must surface so the outbox retries")
	}
	if _, found, _ := s.lookupExecutionAttestation(context.Background(), "job-a", 1); found {
		t.Fatal("failed commit left a lookup marker")
	}
}

var errTestAttestationStore = errTestStore("attestation store down")

type errTestStore string

func (e errTestStore) Error() string { return string(e) }
