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
	// filesystem isolation is enforced, credential injection is possible.
	// The AUTHORITATIVE object is the fact vector; the label must be exactly
	// what the shared derivation recomputes from it.
	if att.ExecutionAssurance.Level != int(model.AssuranceIsolatedFilesystem) || att.ExecutionAssurance.Name != "isolated_filesystem" {
		t.Fatalf("assurance = %+v, want level 1 isolated_filesystem", att.ExecutionAssurance)
	}
	facts := att.ExecutionAssurance.Facts
	if facts == nil {
		t.Fatal("attestation carries no execution facts")
	}
	if facts.Runtime != model.RuntimeFactContainer || !facts.FilesystemIsolated {
		t.Fatalf("facts = %+v, want an isolated container", facts)
	}
	if !facts.KiwiSecretsInjected {
		t.Fatalf("facts = %+v, want injected credentials possible under the unrestricted trusted policy", facts)
	}
	if got := model.DeriveAssuranceProfile(*facts); int(got) != att.ExecutionAssurance.Level {
		t.Fatalf("profile %d disagrees with its facts (derive %d)", att.ExecutionAssurance.Level, int(got))
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
	// Tampering with any evidence field breaks internal consistency
	// verification even though the envelope signature itself still verifies.
	for name, mutate := range map[string]func(a *provenance.ExecutionAttestation){
		"assurance level": func(a *provenance.ExecutionAttestation) {
			a.ExecutionAssurance.Level = 5
			a.ExecutionAssurance.Name = "sealed_pinned_no_network"
		},
		"assurance facts": func(a *provenance.ExecutionAttestation) {
			f := *a.ExecutionAssurance.Facts
			f.FilesystemIsolated = false
			a.ExecutionAssurance.Facts = &f
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

// TestAttestationAssuranceEndToEndUntrustedSealedPinned proves the derivation
// reaches the attestation for an untrusted network-none job with an explicit
// deny-all secret allowlist: pure and sealed_pinned_no_network.
func TestAttestationAssuranceEndToEndUntrustedSealedPinned(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedAssuranceAttestationJob(t, s, "job-a", "run-a", hermeticUntrustedPipeline, 1, false, policy.DefaultUntrustedCapabilities())
	// Proven network denial (v6) requires the executor receipt.
	s.mu.Lock()
	j := s.jobs["job-a"]
	j.ObservedRuntime = &model.ObservedRuntime{
		OS: "linux", Arch: "amd64", RuntimeName: "docker",
		Control: &model.ExecutionControlReceipt{
			Runtime: "docker", SandboxStarted: true, NetworkEnforced: model.ObservedNetworkNone,
		},
	}
	s.jobs["job-a"] = j
	s.mu.Unlock()
	if err := s.attestExecution(context.Background(), "job-a", 1); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	s.mu.Lock()
	rec := s.attestations[model.AttemptID("job-a", 1)]
	s.mu.Unlock()
	st, _ := verifyAttestationEnvelope(t, s, rec)
	if st.Attestation.ExecutionAssurance.Level != int(model.AssuranceSealedPinnedNoNetwork) {
		t.Fatalf("assurance = %+v, want sealed_pinned_no_network", st.Attestation.ExecutionAssurance)
	}
	if st.Attestation.ExternalEffects != model.EffectsPure {
		t.Fatalf("externalEffects = %q, want pure", st.Attestation.ExternalEffects)
	}
	facts := st.Attestation.ExecutionAssurance.Facts
	if facts == nil || facts.NetworkMode != model.NetworkModeFactNone {
		t.Fatalf("facts = %+v, want network none policy", facts)
	}
	if !facts.NetworkAccessDenied {
		t.Fatalf("facts = %+v, want proven network_access_denied", facts)
	}
	if !facts.FilesystemIsolated || !facts.ImagesDigestPinned || facts.KiwiSecretsInjected {
		t.Fatalf("facts = %+v, want isolated, pinned and no injected credentials", facts)
	}
}

// nativeUntrustedPipeline is a native untrusted job: the runner enforces a
// workspace quota but no filesystem confinement, so the signed facts must
// never claim filesystem isolation.
const nativeUntrustedPipeline = "version: 1\njobs:\n  build:\n    runtime: native\n    steps:\n      - run: echo hi\n"

// TestAttestationAssuranceNativeQuotaNotIsolated is the end-to-end regression
// test for the audit's P1: an untrusted native job carries an enforced
// workspace quota AND filesystem_isolated=false, and its signed profile is
// uncontrolled, never isolated_filesystem.
func TestAttestationAssuranceNativeQuotaNotIsolated(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedAssuranceAttestationJob(t, s, "job-n", "run-n", nativeUntrustedPipeline, 1, false, policy.DefaultUntrustedCapabilities())
	if err := s.attestExecution(context.Background(), "job-n", 1); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	s.mu.Lock()
	rec := s.attestations[model.AttemptID("job-n", 1)]
	s.mu.Unlock()
	st, _ := verifyAttestationEnvelope(t, s, rec)
	if st.Attestation.ExecutionAssurance.Level != int(model.AssuranceUncontrolled) || st.Attestation.ExecutionAssurance.Name != "uncontrolled" {
		t.Fatalf("assurance = %+v, want uncontrolled", st.Attestation.ExecutionAssurance)
	}
	facts := st.Attestation.ExecutionAssurance.Facts
	if facts == nil {
		t.Fatal("attestation carries no execution facts")
	}
	if facts.FilesystemIsolated {
		t.Fatalf("facts = %+v, must not claim filesystem isolation for native", facts)
	}
	// Quota truthfulness (P1): without an observed hard-quota result the
	// attempt may have CONFIGURED a bound (untrusted default), but must not
	// claim enforcement.
	if !facts.WorkspaceQuotaConfigured {
		t.Fatalf("facts = %+v, want the requested workspace quota recorded as configured", facts)
	}
	if facts.WorkspaceQuotaEnforced {
		t.Fatalf("facts = %+v, must not claim quota enforcement without an observed hard-quota result", facts)
	}
	if facts.Runtime != model.RuntimeFactNative {
		t.Fatalf("facts = %+v, want the native runtime", facts)
	}
	if st.Attestation.ExternalEffects != model.EffectsOpaqueExternal {
		t.Fatalf("externalEffects = %q, want opaque_external", st.Attestation.ExternalEffects)
	}
}

// TestAttestationBindsObservedControlReceipt proves the executor-observed
// enforcement receipt rides inside the signed facts, is corroborated against
// the effective vector at verification, and is bound by the digest.
func TestAttestationBindsObservedControlReceipt(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedAssuranceAttestationJob(t, s, "job-a", "run-a", hermeticUntrustedPipeline, 1, false, policy.DefaultUntrustedCapabilities())
	s.mu.Lock()
	j := s.jobs["job-a"]
	j.ObservedRuntime = &model.ObservedRuntime{
		OS: "linux", Arch: "amd64", RuntimeName: "docker",
		Control: &model.ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: model.ObservedNetworkNone},
	}
	s.jobs["job-a"] = j
	s.mu.Unlock()
	if err := s.attestExecution(context.Background(), "job-a", 1); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	s.mu.Lock()
	rec := s.attestations[model.AttemptID("job-a", 1)]
	s.mu.Unlock()
	st, _ := verifyAttestationEnvelope(t, s, rec)
	observed := st.Attestation.ExecutionAssurance.Facts.Observed
	if observed == nil || !observed.SandboxStarted || observed.NetworkEnforced != model.ObservedNetworkNone {
		t.Fatalf("observed receipt = %+v, want the started docker sandbox with network none", observed)
	}
	// The receipt is inside the signed digest: flipping it is rejected.
	cp := *st.Attestation
	f := *cp.ExecutionAssurance.Facts
	obs := *f.Observed
	obs.NetworkEnforced = model.ObservedNetworkContainerNamespace
	f.Observed = &obs
	cp.ExecutionAssurance.Facts = &f
	tampered := st
	tampered.Attestation = &cp
	if err := provenance.VerifyExecutionAttestation(tampered); err == nil {
		t.Fatal("tampered observed receipt accepted")
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

// TestAttestationQuotaEnforcedOnlyFromObservedHardQuota is the P1 end-to-end
// pin: a signed workspace_quota_enforced=true requires the attempt's observed
// hard-quota result. A configured bound alone signs false; a hard receipt
// signs true; a contradictory pair refuses to sign.
func TestAttestationQuotaEnforcedOnlyFromObservedHardQuota(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Configured bound, soft receipt → configured, not enforced.
	seedAssuranceAttestationJob(t, s, "job-soft", "run-soft", nativeUntrustedPipeline, 1, false, policy.DefaultUntrustedCapabilities())
	s.mu.Lock()
	j := s.jobs["job-soft"]
	j.ObservedRuntime = &model.ObservedRuntime{
		OS: "linux", Arch: "amd64", RuntimeName: "native",
		Control: &model.ExecutionControlReceipt{Runtime: "native", NetworkEnforced: model.ObservedNetworkHost},
	}
	s.jobs["job-soft"] = j
	s.mu.Unlock()
	if err := s.attestExecution(context.Background(), "job-soft", 1); err != nil {
		t.Fatalf("attestExecution soft: %v", err)
	}
	s.mu.Lock()
	rec := s.attestations[model.AttemptID("job-soft", 1)]
	s.mu.Unlock()
	st, _ := verifyAttestationEnvelope(t, s, rec)
	facts := st.Attestation.ExecutionAssurance.Facts
	if facts.WorkspaceQuotaEnforced {
		t.Fatalf("facts = %+v, soft receipt must not claim enforcement", facts)
	}
	if !facts.WorkspaceQuotaConfigured {
		t.Fatalf("facts = %+v, want configured", facts)
	}

	// Hard receipt → enforced.
	seedAssuranceAttestationJob(t, s, "job-hard", "run-hard", nativeUntrustedPipeline, 1, false, policy.DefaultUntrustedCapabilities())
	s.mu.Lock()
	j = s.jobs["job-hard"]
	j.ObservedRuntime = &model.ObservedRuntime{
		OS: "linux", Arch: "amd64", RuntimeName: "native",
		Control: &model.ExecutionControlReceipt{Runtime: "native", NetworkEnforced: model.ObservedNetworkHost, WorkspaceQuotaEnforced: true},
	}
	s.jobs["job-hard"] = j
	s.mu.Unlock()
	if err := s.attestExecution(context.Background(), "job-hard", 1); err != nil {
		t.Fatalf("attestExecution hard: %v", err)
	}
	s.mu.Lock()
	rec = s.attestations[model.AttemptID("job-hard", 1)]
	s.mu.Unlock()
	st, _ = verifyAttestationEnvelope(t, s, rec)
	facts = st.Attestation.ExecutionAssurance.Facts
	if !facts.WorkspaceQuotaEnforced {
		t.Fatalf("facts = %+v, hard receipt must record enforcement", facts)
	}

	// Contradictory receipt (effective network none vs connected namespace)
	// must refuse to sign.
	seedAssuranceAttestationJob(t, s, "job-bad", "run-bad", hermeticUntrustedPipeline, 1, false, policy.DefaultUntrustedCapabilities())
	s.mu.Lock()
	j = s.jobs["job-bad"]
	j.ObservedRuntime = &model.ObservedRuntime{
		OS: "linux", Arch: "amd64", RuntimeName: "docker",
		Control: &model.ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: model.ObservedNetworkContainerNamespace},
	}
	s.jobs["job-bad"] = j
	s.mu.Unlock()
	if err := s.attestExecution(context.Background(), "job-bad", 1); err == nil {
		t.Fatal("contradictory effective/observed pair must fail signing")
	}
}

// TestAttestationRejectsHostileObservedContradiction: a hostile runner that
// reports a receipt contradicting the effective vector cannot get that pair
// signed, and a crafted statement carrying one fails verification.
func TestAttestationRejectsHostileObservedContradiction(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedAssuranceAttestationJob(t, s, "job-h", "run-h", hermeticUntrustedPipeline, 1, false, policy.DefaultUntrustedCapabilities())
	s.mu.Lock()
	j := s.jobs["job-h"]
	j.ObservedRuntime = &model.ObservedRuntime{
		OS: "linux", Arch: "amd64", RuntimeName: "docker",
		Control: &model.ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: model.ObservedNetworkHost},
	}
	s.jobs["job-h"] = j
	s.mu.Unlock()
	if err := s.attestExecution(context.Background(), "job-h", 1); err == nil {
		t.Fatal("hostile receipt (network host under effective none) must fail signing")
	}

	// A validly signed statement whose facts are then rewritten to a
	// contradictory pair must fail verification.
	seedAssuranceAttestationJob(t, s, "job-ok", "run-ok", hermeticUntrustedPipeline, 1, false, policy.DefaultUntrustedCapabilities())
	if err := s.attestExecution(context.Background(), "job-ok", 1); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
	s.mu.Lock()
	rec := s.attestations[model.AttemptID("job-ok", 1)]
	s.mu.Unlock()
	st, _ := verifyAttestationEnvelope(t, s, rec)
	cp := *st.Attestation
	f := *cp.ExecutionAssurance.Facts
	f.Observed = &model.ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: model.ObservedNetworkContainerNamespace}
	cp.ExecutionAssurance.Facts = &f
	tampered := st
	tampered.Attestation = &cp
	if err := provenance.VerifyExecutionAttestation(tampered); err == nil {
		t.Fatal("verification accepted contradictory effective/observed pair")
	}
}
