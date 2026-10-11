package scenarios

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestDFBOOT001CleanLocalBootstrapAndRestart is DF-BOOT-001: the local
// topology bootstraps cleanly, runs one attempt to green under the
// eight-oracle rule, restarts over the same durable state without losing or
// double-counting anything, and never collides namespaces across
// invocations.
func TestDFBOOT001CleanLocalBootstrapAndRestart(t *testing.T) {
	if _, ok := Lookup(ScenarioBootCleanLocal); !ok {
		t.Fatal("scenario DF-BOOT-001 missing from the registry")
	}
	seed := mustSeed(t)
	h, err := dogfood.Launch(dogfood.LaunchConfig{
		Topology: dogfood.Local(mustNamespace(t)),
		Seed:     seed,
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	// Topology under test is the declared local shape.
	if err := h.Topology().Validate(); err != nil {
		t.Fatalf("topology: %v", err)
	}
	if !h.Namespace().Valid() {
		t.Fatalf("namespace is not fully isolated: %+v", h.Namespace())
	}
	repo := h.SeedRepo("app", "cafe0001", "refs/heads/main")
	run, err := h.SeedRun("run-boot", repo, []string{"build"}, "runner-1")
	if err != nil {
		t.Fatalf("seed run: %v", err)
	}
	if len(run.Attempts) != 1 {
		t.Fatalf("seeded %d attempts, want 1", len(run.Attempts))
	}
	// Complete the attempt under its live lease.
	claim := dogfood.CompletionClaim{
		RunID: "run-boot", JobID: run.Attempts[0].JobID,
		RunnerID: "runner-1", Generation: run.Attempts[0].Generation,
		Status: string(model.StatusSuccess), Protocol: model.ExecutionSemanticsVersion,
		ArtifactSHA256: "1111111111111111111111111111111111111111111111111111111111111111",
	}
	if d, err := h.SubmitCompletion(claim); err != nil || d != dogfood.DecisionAccepted {
		t.Fatalf("completion = %s, %v, want accepted", d, err)
	}
	if err := h.AttachArtifact("run-boot", run.Attempts[0].JobID, claim.ArtifactSHA256); err != nil {
		t.Fatalf("attach artifact: %v", err)
	}
	oracle := dogfood.NewOracle()
	obs, err := h.Observations("run-boot", 0)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	res := oracle.Check(obs)
	if !res.Green {
		t.Fatalf("eight-oracle after bootstrap: %s", res.Summary())
	}
	// Restart over the same durable state: the recovery surface must still
	// agree with every other surface (nothing lost, nothing doubled).
	if err := h.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := h.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	obsAfter, err := h.Observations("run-boot", 0)
	if err != nil {
		t.Fatalf("observations after restart: %v", err)
	}
	resAfter := oracle.Check(obsAfter)
	if !resAfter.Green {
		t.Fatalf("eight-oracle after restart: %s", resAfter.Summary())
	}
	snap := h.StateOracle()
	var completions int
	for _, e := range snap.Ledger {
		if e.Kind == "completion" {
			completions++
		}
	}
	if completions != 1 {
		t.Fatalf("completion ledger entries after restart = %d, want exactly 1", completions)
	}
	if err := h.Stop(); err != nil {
		t.Fatalf("final stop: %v", err)
	}
	// Negative arm: a second invocation must get a disjoint namespace.
	other, err := dogfood.Launch(dogfood.LaunchConfig{
		Topology: dogfood.Local(mustNamespace(t)),
		Seed:     mustSeed(t),
	})
	if err != nil {
		t.Fatalf("second launch: %v", err)
	}
	defer other.Stop()
	if other.Namespace().Prefix == h.Namespace().Prefix {
		t.Fatal("two invocations share a namespace prefix")
	}
}

// TestEightOracleDisagreementFails pins the eight-oracle rule itself: a
// panel missing a surface is red, a panel whose surfaces disagree is red,
// and only a full agreeing panel is green. One surface cannot grade itself.
func TestEightOracleDisagreementFails(t *testing.T) {
	full := func(term string, effects int) []dogfood.Observation {
		obs := make([]dogfood.Observation, 0, len(dogfood.AllSurfaces))
		for _, s := range dogfood.AllSurfaces {
			obs = append(obs, dogfood.Observation{Surface: s, Terminal: term, EffectCount: effects})
		}
		return obs
	}
	oracle := dogfood.NewOracle()
	if res := oracle.Check(full(string(model.StatusSuccess), 1)); !res.Green {
		t.Fatalf("agreeing panel is red: %s", res.Summary())
	}
	// Missing surface.
	partial := full(string(model.StatusSuccess), 1)[:7]
	if res := oracle.Check(partial); res.Green {
		t.Fatal("panel with a missing surface graded green")
	}
	// Disagreeing terminal.
	bad := full(string(model.StatusSuccess), 1)
	bad[0].Terminal = string(model.StatusFailure)
	if res := oracle.Check(bad); res.Green {
		t.Fatal("panel with a terminal disagreement graded green")
	}
	// Disagreeing effect count.
	counts := full(string(model.StatusSuccess), 1)
	counts[2].EffectCount = 2
	if res := oracle.Check(counts); res.Green {
		t.Fatal("panel with an effect-count disagreement graded green")
	}
	// Unknown and duplicate surfaces fail closed.
	if res := oracle.Check(append(full("success", 0), dogfood.Observation{Surface: "ninth", Terminal: "success"})); res.Green {
		t.Fatal("panel with an unknown ninth surface graded green")
	}
	dup := append(full("success", 0), full("success", 0)[0])
	if res := oracle.Check(dup); res.Green {
		t.Fatal("panel with a duplicated surface graded green")
	}
}

// TestNoHiddenRetries pins the flaky-retry accounting rule: retries are
// recorded in full, but a retry of a non-retry-under-test scenario can
// never be green.
func TestNoHiddenRetries(t *testing.T) {
	single := dogfood.ScenarioResult{
		ID: "DF-X-001", Arm: "positive",
		Attempts: dogfood.AttemptAccounting{
			AttemptCount: 1, FirstAttemptResult: "success", FinalResult: "success",
		},
		Green: true,
	}
	if _, err := single.Seal(); err != nil {
		t.Fatalf("single-attempt arm must seal: %v", err)
	}
	// Hidden-retry shape: multi-attempt without retry_under_test.
	flaky := dogfood.ScenarioResult{
		ID: "DF-X-002", Arm: "positive",
		Attempts: dogfood.AttemptAccounting{
			AttemptCount: 2, RetryCause: "transient infra",
			FirstAttemptResult: "failure", FinalResult: "success",
		},
		Green: true, // the arm WANTED green; the seal must take it away
	}
	sealed, err := flaky.Seal()
	if err != dogfood.ErrFlakyRetry {
		t.Fatalf("flaky seal err = %v, want ErrFlakyRetry", err)
	}
	if sealed.Green {
		t.Fatal("flaky retry of a non-retry-under-test scenario sealed green")
	}
	// A declared retry-under-test arm may retry and still be green, but the
	// accounting must be complete.
	retryArm := dogfood.ScenarioResult{
		ID: "DF-X-003", Arm: "retry", RetryUnderTest: true,
		Attempts: dogfood.AttemptAccounting{
			AttemptCount: 2, RetryCause: "lease lost",
			FirstAttemptResult: "failure", FinalResult: "success",
		},
		Green: true,
	}
	if _, err := retryArm.Seal(); err != nil {
		t.Fatalf("retry-under-test arm must seal: %v", err)
	}
	// Incomplete accounting never seals.
	incomplete := dogfood.ScenarioResult{
		ID: "DF-X-004", Arm: "positive",
		Attempts: dogfood.AttemptAccounting{AttemptCount: 2, RetryCause: "x", FirstAttemptResult: "failure"},
	}
	if _, err := incomplete.Seal(); err == nil {
		t.Fatal("incomplete attempt accounting sealed")
	}
	// The aggregate reddens on any flaky arm.
	agg := dogfood.DogfoodResult{Scenarios: []dogfood.ScenarioResult{single, flaky}}
	out, err := agg.Seal()
	if err == nil {
		t.Fatal("aggregate sealed a flaky arm without error")
	}
	if out.Green {
		t.Fatal("aggregate stayed green with a flaky arm")
	}
}

// TestNamespaceIsolationSurfaces pins the per-invocation namespace: every
// mutable surface is uniquely keyed and two namespaces never share one.
func TestNamespaceIsolationSurfaces(t *testing.T) {
	a, err := dogfood.NewNamespace(time.Unix(1700000000, 0), rand.Reader)
	if err != nil {
		t.Fatalf("namespace a: %v", err)
	}
	b, err := dogfood.NewNamespace(time.Unix(1700000000, 0), rand.Reader)
	if err != nil {
		t.Fatalf("namespace b: %v", err)
	}
	if !a.Valid() || !b.Valid() {
		t.Fatalf("namespaces incomplete: %+v / %+v", a, b)
	}
	if a.Prefix == b.Prefix || a.Schema == b.Schema || a.OIDCAudience == b.OIDCAudience {
		t.Fatalf("namespace collision: %+v / %+v", a, b)
	}
	if a.RepoName("app") == b.RepoName("app") {
		t.Fatal("seeded repo names collide across invocations")
	}
	if a.ContainerName("main") == b.ContainerName("main") {
		t.Fatal("container names collide across invocations")
	}
}

// TestFaultPointsAreDeterministic pins the pause-hook contract: a scenario
// that arms a fault hits it exactly at the named window and can inject a
// competing action while the control plane is frozen.
func TestFaultPointsAreDeterministic(t *testing.T) {
	h, err := dogfood.Launch(dogfood.LaunchConfig{
		Topology: dogfood.Local(mustNamespace(t)),
		Seed:     mustSeed(t),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer h.Stop()
	repo := h.SeedRepo("app", "cafe0002", "refs/heads/main")
	run, err := h.SeedRun("run-fault", repo, []string{"build"}, "runner-1")
	if err != nil {
		t.Fatalf("seed run: %v", err)
	}
	release, arrived, err := h.Faults().PauseAt(dogfood.AfterStateMutationBeforeLedger)
	if err != nil {
		t.Fatalf("pause: %v", err)
	}
	injected := make(chan dogfood.AcceptanceDecision, 1)
	go func() {
		d, _ := h.SubmitCompletion(dogfood.CompletionClaim{
			RunID: "run-fault", JobID: run.Attempts[0].JobID,
			RunnerID: "runner-1", Generation: run.Attempts[0].Generation,
			Status: string(model.StatusSuccess), Protocol: model.ExecutionSemanticsVersion,
		})
		injected <- d
	}()
	select {
	case <-arrived:
	case <-time.After(2 * time.Second):
		t.Fatal("fault hook never arrived")
	}
	// The control plane is frozen AFTER the state mutation and BEFORE the
	// ledger write: a duplicate in this window must lose to the CAS.
	d, err := h.SubmitCompletion(dogfood.CompletionClaim{
		RunID: "run-fault", JobID: run.Attempts[0].JobID,
		RunnerID: "runner-1", Generation: run.Attempts[0].Generation,
		Status: string(model.StatusFailure), Protocol: model.ExecutionSemanticsVersion,
	})
	if err != nil || d != dogfood.DecisionRejected {
		t.Fatalf("duplicate in the mutation window = %s, %v, want rejected", d, err)
	}
	release()
	if d := <-injected; d != dogfood.DecisionAccepted {
		t.Fatalf("frozen completion = %s, want accepted after release", d)
	}
	if h.Faults().Hits(dogfood.AfterStateMutationBeforeLedger) != 1 {
		t.Fatalf("fault hits = %d, want 1", h.Faults().Hits(dogfood.AfterStateMutationBeforeLedger))
	}
}
