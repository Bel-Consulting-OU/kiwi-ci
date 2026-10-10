package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// seedAssuranceAttestationJob seeds one completed attempt whose durable
// records fully determine the execution-assurance classification under the
// supplied pipeline, trust state and effective policy.
func seedAssuranceAttestationJob(t *testing.T, s *Server, jobID, runID, pipelineText string, generation int64, trusted bool, caps policy.Capabilities) model.Job {
	t.Helper()
	spec, err := pipeline.Parse([]byte(pipelineText))
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
	var key string
	for k := range graph.Jobs {
		key = k
		break
	}
	cj := graph.Jobs[key]
	cjJSON, err := json.Marshal(cj)
	if err != nil {
		t.Fatal(err)
	}
	policyJSON, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	jobSum := sha256.Sum256(cjJSON)
	compiled := &model.CompiledJobPayload{
		SchemaVersion: 1, CompilerVersion: "test",
		PipelineDigest: pd, JobDigest: hex.EncodeToString(jobSum[:]),
		EffectiveJob: json.RawMessage(cjJSON), EffectivePolicy: json.RawMessage(policyJSON),
	}
	start := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	finish := start.Add(time.Minute)
	job := model.Job{
		ID: jobID, RunID: runID, Key: key, Status: model.StatusSuccess,
		StartedAt: &start, FinishedAt: &finish, LeaseGeneration: generation,
		AttemptRunnerID: "runner-a", Trusted: trusted,
		Pipeline:           pipelineText,
		CompiledJobPayload: compiled,
		ExecutionSemantics: model.ExecutionSemanticsVersion,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[runID] = model.Run{ID: runID, RepoID: "github.com/acme/repo-a", Repo: "https://github.com/acme/repo-a.git", RepoFullName: "acme/repo-a", Ref: "refs/heads/main", SHA: "abc", Status: model.StatusSuccess, ExecutionSemantics: model.ExecutionSemanticsVersion}
	s.jobs[jobID] = job
	return job
}

const hermeticUntrustedPipeline = "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc\n    network: none\n    steps:\n      - run: echo hi\n"

// TestAttestationBindsAssuranceEvidence proves the v4 attestation carries the
// execution-assurance classification derived from durable records, the
// canonical policy digest, the fs event-ledger frontier read at emission time
// and the run graph fingerprint, and that verification refuses a tampered
// classification even though the signature remains intact.
func TestAttestationBindsAssuranceEvidence(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	job := seedAssuranceAttestationJob(t, s, "job-a", "run-a", attestationTestPipeline, 3, true, policy.DefaultTrustedCapabilities())
	// A durable ledger with events gives the frontier a non-zero value.
	for _, typ := range []string{"test.marker-one", "test.marker-two"} {
		if err := s.store.AppendExecutionEvent(context.Background(), model.ExecutionEvent{
			Type: typ, RunID: "run-a", JobID: "job-a", CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	frontier, err := s.store.LatestExecutionEventSeq(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if frontier == 0 {
		t.Fatal("frontier did not advance")
	}
	wantPolicyDigest, err := provenance.EffectivePolicyDigest(job.CompiledJobPayload)
	if err != nil {
		t.Fatal(err)
	}
	wantGraph := provenance.GraphFingerprint([]model.Job{job})

	if err := s.attestExecution(context.Background(), "job-a", 3); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	s.mu.Lock()
	rec := s.attestations[model.AttemptID("job-a", 3)]
	s.mu.Unlock()
	st, _ := verifyAttestationEnvelope(t, s, rec)
	att := st.Attestation
	// Trusted container with the unrestricted trusted default secret policy:
	// filesystem isolation is enforced, ambient credentials are possible.
	if att.ExecutionAssurance.Level != int(model.AssuranceIsolatedFilesystem) || att.ExecutionAssurance.Name != "isolated_filesystem" {
		t.Fatalf("assurance = %+v, want level 1 isolated_filesystem", att.ExecutionAssurance)
	}
	if att.ExternalEffects != model.EffectsOpaqueExternal {
		t.Fatalf("externalEffects = %q, want opaque_external", att.ExternalEffects)
	}
	if att.PolicyDigest != wantPolicyDigest || att.PolicyDigest == "" {
		t.Fatalf("policyDigest = %q, want %q", att.PolicyDigest, wantPolicyDigest)
	}
	if att.EventFrontier != frontier {
		t.Fatalf("eventFrontier = %d, want %d", att.EventFrontier, frontier)
	}
	if att.GraphFingerprint != wantGraph || att.GraphFingerprint == "" {
		t.Fatalf("graphFingerprint = %q, want %q", att.GraphFingerprint, wantGraph)
	}
	// Tampering with any v4 field breaks internal consistency verification
	// even though the envelope signature itself still verifies.
	for name, mutate := range map[string]func(a *provenance.ExecutionAttestation){
		"assurance level": func(a *provenance.ExecutionAttestation) {
			a.ExecutionAssurance = provenance.ExecutionAssuranceEvidence{Level: 5, Name: "hermetic"}
		},
		"external effects": func(a *provenance.ExecutionAttestation) { a.ExternalEffects = model.EffectsPure },
		"policy digest":    func(a *provenance.ExecutionAttestation) { a.PolicyDigest = strings.Repeat("f", 64) },
		"event frontier":   func(a *provenance.ExecutionAttestation) { a.EventFrontier++ },
		"graph fingerprint": func(a *provenance.ExecutionAttestation) {
			a.GraphFingerprint = strings.Repeat("f", 64)
		},
	} {
		cp := *st.Attestation
		mutate(&cp)
		tampered := st
		tampered.Attestation = &cp
		if err := provenance.VerifyExecutionAttestation(tampered); err == nil {
			t.Fatalf("tampered %s accepted", name)
		}
	}
}

// TestAttestationAssuranceEndToEndUntrustedHermetic proves the derivation
// reaches the attestation for an untrusted network-none job with an explicit
// deny-all secret allowlist: pure and hermetic.
func TestAttestationAssuranceEndToEndUntrustedHermetic(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedAssuranceAttestationJob(t, s, "job-a", "run-a", hermeticUntrustedPipeline, 1, false, policy.DefaultUntrustedCapabilities())
	if err := s.attestExecution(context.Background(), "job-a", 1); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	s.mu.Lock()
	rec := s.attestations[model.AttemptID("job-a", 1)]
	s.mu.Unlock()
	st, _ := verifyAttestationEnvelope(t, s, rec)
	if st.Attestation.ExecutionAssurance.Level != int(model.AssuranceHermetic) {
		t.Fatalf("assurance = %+v, want hermetic", st.Attestation.ExecutionAssurance)
	}
	if st.Attestation.ExternalEffects != model.EffectsPure {
		t.Fatalf("externalEffects = %q, want pure", st.Attestation.ExternalEffects)
	}
}

// cursorFakeStore adds the optional ExecutionEventCursorStore contract to the
// DB fake so the db-mode attestation path reads the frontier.
type cursorFakeStore struct {
	*dbFakeStore
	latest int64
}

func (c *cursorFakeStore) LatestExecutionEventSeq(context.Context) (int64, error) {
	return c.latest, nil
}

// TestAttestationEventFrontierOmitsWithoutCursorContract proves the frontier
// is omitted when the store does not expose the cursor contract and read from
// the contract when it does, while the graph fingerprint is always derived
// from the durable run jobs.
func TestAttestationEventFrontierOmitsWithoutCursorContract(t *testing.T) {
	build := func(t *testing.T, cursor bool) provenance.Statement {
		t.Helper()
		s, err := NewPersistent("token", "token", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		f := newDBFakeStore()
		if cursor {
			s.DB = &cursorFakeStore{dbFakeStore: f, latest: 7}
		} else {
			s.DB = f
		}
		s.ensureProvenanceKey()
		seedAttestationJob(t, s, "job-a", "run-a", 2)
		f.mu.Lock()
		f.runs["run-a"] = s.runs["run-a"]
		f.jobs["job-a"] = s.jobs["job-a"]
		f.mu.Unlock()
		if err := s.attestExecution(context.Background(), "job-a", 2); err != nil {
			t.Fatalf("attestExecution: %v", err)
		}
		f.mu.Lock()
		rec := f.attestations[model.AttemptID("job-a", 2)]
		f.mu.Unlock()
		st, _ := verifyAttestationEnvelope(t, s, rec)
		return st
	}
	st := build(t, false)
	if st.Attestation.EventFrontier != 0 {
		t.Fatalf("frontier = %d without the cursor contract, want omitted (0)", st.Attestation.EventFrontier)
	}
	if st.Attestation.GraphFingerprint == "" {
		t.Fatal("graph fingerprint missing without the cursor contract")
	}
	st = build(t, true)
	if st.Attestation.EventFrontier != 7 {
		t.Fatalf("frontier = %d with the cursor contract, want 7", st.Attestation.EventFrontier)
	}
}

// TestAttestationGraphFingerprintTracksDurableGraph proves the fingerprint is
// computed from the durable jobs of the run at emission time: adding a job to
// the run changes the signed fingerprint.
func TestAttestationGraphFingerprintTracksDurableGraph(t *testing.T) {
	build := func(t *testing.T, extra bool) provenance.Statement {
		s, err := NewPersistent("token", "token", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		seedAttestationJob(t, s, "job-a", "run-a", 2)
		if extra {
			s.mu.Lock()
			s.jobs["job-b"] = model.Job{ID: "job-b", RunID: "run-a", Key: "extra", Status: model.StatusQueued}
			s.mu.Unlock()
		}
		if err := s.attestExecution(context.Background(), "job-a", 2); err != nil {
			t.Fatalf("attestExecution: %v", err)
		}
		s.mu.Lock()
		rec := s.attestations[model.AttemptID("job-a", 2)]
		s.mu.Unlock()
		st, _ := verifyAttestationEnvelope(t, s, rec)
		return st
	}
	one := build(t, false)
	two := build(t, true)
	if one.Attestation.GraphFingerprint == "" || two.Attestation.GraphFingerprint == "" {
		t.Fatal("graph fingerprint missing")
	}
	if one.Attestation.GraphFingerprint == two.Attestation.GraphFingerprint {
		t.Fatal("adding a durable job did not change the signed graph fingerprint")
	}
	if one.Subject[0].Digest["sha256"] == two.Subject[0].Digest["sha256"] {
		t.Fatal("changed graph fingerprint did not change the attestation digest")
	}
}
