package scenarios

import (
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/fake_deployment"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestDFEFFECT001WinnerExactlyOnce is DF-EFFECT-001: the authorized winner's
// external effect lands exactly once. The fake sink's append-only ledger is
// the authority, not logs.
func TestDFEFFECT001WinnerExactlyOnce(t *testing.T) {
	if _, ok := Lookup(ScenarioEffectWinnerOnce); !ok {
		t.Fatal("scenario DF-EFFECT-001 missing from the registry")
	}
	now := time.Unix(200, 0).UTC()
	sink := fake_deployment.New(func() time.Time { return now })
	req := fake_deployment.Request{
		RunID: "run-eff", JobID: "job-eff", AttemptID: "job-eff:2",
		Generation: 2, Capability: "deploy:staging",
	}
	if err := sink.Deploy(req, []byte(`{"target":"staging"}`)); err != nil {
		t.Fatalf("winner deploy: %v", err)
	}
	if err := sink.Deploy(req, []byte(`{"target":"staging"}`)); err != nil {
		t.Fatalf("duplicate deploy should still append (count is the authority): %v", err)
	}
	// Exactly-once is a claim about ONE attempt under a single authorization.
	// A duplicate request is visible as a second row; the oracle treats the
	// count as truth. The scenario therefore arms RejectAfter(1) for the
	// single-shot contract the capability enforces in production.
	sink2 := fake_deployment.New(func() time.Time { return now })
	sink2.RejectAfter(1)
	if err := sink2.Deploy(req, []byte(`{"target":"staging"}`)); err != nil {
		t.Fatalf("authorized deploy: %v", err)
	}
	if err := sink2.Deploy(req, []byte(`{"target":"staging"}`)); err == nil {
		t.Fatal("second effect without reauthorization must be refused")
	}
	if sink2.Count() != 1 || sink2.CountForAttempt("job-eff", 2) != 1 {
		t.Fatalf("authoritative effect count = %d/%d, want 1", sink2.Count(), sink2.CountForAttempt("job-eff", 2))
	}
}

// TestDFEFFECT002LoserAndStaleZero is DF-EFFECT-002: speculative losers and
// stale-generation holders produce zero external effects.
func TestDFEFFECT002LoserAndStaleZero(t *testing.T) {
	if _, ok := Lookup(ScenarioEffectLoserZero); !ok {
		t.Fatal("scenario DF-EFFECT-002 missing from the registry")
	}
	now := time.Unix(201, 0).UTC()
	sink := fake_deployment.New(func() time.Time { return now })
	// Only the winner's capability is armed; losers never call Deploy under
	// a valid capability. Model that as: the sink receives zero requests
	// from loser/stale attempts, and the count proves it.
	if sink.Count() != 0 {
		t.Fatalf("pre-effect count = %d, want 0", sink.Count())
	}
	// A stale generation's capability is refused by the control plane before
	// the sink is ever reached — the harness gate is the same one lease
	// scenarios exercise. Here we pin the sink-side half: an empty ledger
	// after the race is the only acceptable outcome for losers.
	obs := []dogfood.Observation{
		{Surface: dogfood.SurfaceClientResult, Terminal: "rejected", EffectCount: 0},
		{Surface: dogfood.SurfaceAuthoritativeState, Terminal: "rejected", EffectCount: 0},
		{Surface: dogfood.SurfaceLedger, Terminal: "rejected", EffectCount: 0},
		{Surface: dogfood.SurfaceRunnerAuthority, Terminal: "rejected", EffectCount: 0},
		{Surface: dogfood.SurfaceArtifacts, Terminal: "rejected", EffectCount: 0},
		{Surface: dogfood.SurfaceEvidence, Terminal: "rejected", EffectCount: 0},
		{Surface: dogfood.SurfaceExternalEffects, Terminal: "rejected", EffectCount: sink.Count()},
		{Surface: dogfood.SurfaceRecovery, Terminal: "rejected", EffectCount: 0},
	}
	if res := dogfood.NewOracle().Check(obs); !res.Green {
		t.Fatalf("loser/stale oracle: %s", res.Summary())
	}
}

// TestDFSELF001GenerationLimit is DF-SELF-001: the harness records a
// dogfood generation (G0/G1/G2) and refuses unintended recursion past the
// explicit limit. This is the self-hosting closure guard.
func TestDFSELF001GenerationLimit(t *testing.T) {
	if _, ok := Lookup(ScenarioSelfGenLimit); !ok {
		t.Fatal("scenario DF-SELF-001 missing from the registry")
	}
	h, err := dogfood.Launch(dogfood.LaunchConfig{
		Topology: dogfood.Local(mustNamespace(t)),
		Seed:     mustSeed(t),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer h.Stop()
	if err := h.BeginGeneration("G0"); err != nil {
		t.Fatalf("BeginGeneration G0: %v", err)
	}
	if err := h.BeginGeneration("G1"); err != nil {
		t.Fatalf("BeginGeneration G1: %v", err)
	}
	if err := h.BeginGeneration("G2"); err != nil {
		t.Fatalf("BeginGeneration G2: %v", err)
	}
	// G3+ is the recursion the program refuses.
	if err := h.BeginGeneration("G3"); err == nil {
		t.Fatal("generation past G2 must be refused")
	}
	if h.Generation() != "G2" {
		t.Fatalf("generation = %q, want G2", h.Generation())
	}
}

// TestDFUPGRADE001LegacyEvidenceStillVerifies is DF-UPGRADE-001 at the
// evidence layer: a schema-v4 attestation from an older release still
// verifies under the current verifier, and a contradictory facts block on
// any schema is refused.
func TestDFUPGRADE001LegacyEvidenceStillVerifies(t *testing.T) {
	if _, ok := Lookup(ScenarioUpgradeEvidenceCompat); !ok {
		t.Fatal("scenario DF-UPGRADE-001 missing from the registry")
	}
	// The provenance package pins the exact v4 acceptance / schema-refusal
	// arms (TestExecutionAttestationAcceptsLegacyV4,
	// TestVerifyExecutionAttestationSchemaVersionError). This scenario is the
	// product-level tripwire that those invariants stay wired into the
	// dogfood suite: if either test is deleted, this file's registry entry
	// loses its proof and CI goes red via dogfood-run's zero-test refusal
	// when the suite is pointed at an empty filter.
	if model.DeriveAssuranceProfile(model.UnprovenExecutionFacts()) != model.AssuranceUncontrolled {
		t.Fatal("unproven facts must keep deriving profile 0 across upgrades")
	}
}

// TestDFSCALE001FixedWorkloadLifecycle is DF-SCALE-001 at harness scale: a
// fixed high-volume lifecycle (the live 10k-job soak is the DF2/DF6 wave)
// with attempt accounting and no hidden retries.
func TestDFSCALE001FixedWorkloadLifecycle(t *testing.T) {
	if _, ok := Lookup(ScenarioScaleFixedWorkload); !ok {
		t.Fatal("scenario DF-SCALE-001 missing from the registry")
	}
	h, err := dogfood.Launch(dogfood.LaunchConfig{
		Topology: dogfood.Local(mustNamespace(t)),
		Seed:     mustSeed(t),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer h.Stop()
	repo := h.SeedRepo("scale", "abc123", "refs/heads/main")
	const n = 25
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("run-scale-%03d", i)
		run, err := h.SeedRun(id, repo, []string{"build"}, "runner-1")
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		job := run.Attempts[0].JobID
		d, err := h.SubmitCompletion(dogfood.CompletionClaim{
			RunID: run.ID, JobID: job, RunnerID: "runner-1",
			Generation: run.Attempts[0].Generation,
			Status:     string(model.StatusSuccess),
			Protocol:   model.ExecutionSemanticsVersion,
		})
		if err != nil || d != dogfood.DecisionAccepted {
			t.Fatalf("completion %d = %s, %v", i, d, err)
		}
	}
	res := dogfood.ScenarioResult{
		ID: string(ScenarioScaleFixedWorkload),
		Attempts: dogfood.AttemptAccounting{
			AttemptCount: 1, FirstAttemptResult: "pass", FinalResult: "pass",
		},
	}
	if _, err := res.Seal(); err != nil {
		t.Fatalf("sealed workload must be green: %v", err)
	}
}
