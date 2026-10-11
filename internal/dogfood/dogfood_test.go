package dogfood

import (
	"strings"
	"testing"
	"time"
)

// TestNamespaceIsUniqueAndSanitized pins the isolation contract: every dogfood
// invocation gets a distinct namespace, and derived names stay valid even
// when the base is hostile.
func TestNamespaceIsUniqueAndSanitized(t *testing.T) {
	a, err := NewNamespace(time.Unix(0, 0).UTC(), strings.NewReader(strings.Repeat("a", 64)))
	if err != nil {
		t.Fatalf("NewNamespace: %v", err)
	}
	b, err := NewNamespace(time.Unix(0, 0).UTC(), strings.NewReader(strings.Repeat("b", 64)))
	if err != nil {
		t.Fatalf("NewNamespace: %v", err)
	}
	if a.Prefix == b.Prefix || a.Schema == b.Schema {
		t.Fatalf("namespaces collided: %+v %+v", a, b)
	}
	if !a.Valid() || !b.Valid() {
		t.Fatalf("namespaces invalid: %+v %+v", a, b)
	}
	repo := a.RepoName("app")
	if !strings.HasPrefix(repo, a.RepoPrefix) {
		t.Fatalf("repo name = %q, want prefix %q", repo, a.RepoPrefix)
	}
	c := a.ContainerName("runner-1")
	if !strings.HasPrefix(c, a.ContainerPrefix) {
		t.Fatalf("container name = %q, want prefix %q", c, a.ContainerPrefix)
	}
}

// TestFaultInjectorPauseAndRelease proves a pause freezes the hitting
// goroutine until release, and that release is idempotent — the deterministic
// window the chaos scenarios rely on instead of sleeps.
func TestFaultInjectorPauseAndRelease(t *testing.T) {
	f := NewFaultInjector()
	release, arrived, err := f.PauseAt(AfterStateMutationBeforeLedger)
	if err != nil {
		t.Fatalf("PauseAt: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- f.Hit(AfterStateMutationBeforeLedger) }()
	select {
	case <-arrived:
	case <-time.After(time.Second):
		t.Fatal("pause never arrived")
	}
	select {
	case err := <-done:
		t.Fatalf("Hit returned while paused: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	release()
	release()
	if err := <-done; err != nil {
		t.Fatalf("Hit after release: %v", err)
	}
	if f.Hits(AfterStateMutationBeforeLedger) != 1 {
		t.Fatalf("hits = %d, want 1", f.Hits(AfterStateMutationBeforeLedger))
	}
}

// TestSeedValidate pins that a chaos run is reproducible only when its seed
// and environment metadata are fully recorded.
func TestSeedValidate(t *testing.T) {
	s := NewSeed(42, time.Unix(1, 0).UTC(), RunMetadata{
		Commit: "abc",
		Versions: VersionInfo{
			Server: "1", Runner: "1", Protocol: "kiwi.execution.v1",
		},
		Executor:     "docker",
		PolicyDigest: "deadbeef",
	})
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !s.Valid() {
		t.Fatal("seed should be valid")
	}
	if s.Source() == nil {
		t.Fatal("Source must produce a deterministic rand")
	}
	bad := s
	bad.Metadata.Commit = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("incomplete seed metadata must be refused")
	}
}

// TestScenarioResultRejectsHiddenRetries: a scenario that failed first and
// passed on retry is non-green unless the retry itself was under test.
func TestScenarioResultRejectsHiddenRetries(t *testing.T) {
	r := ScenarioResult{
		ID: "DF-BOOT-001",
		Attempts: AttemptAccounting{
			AttemptCount: 2, RetryCause: "flake",
			FirstAttemptResult: "fail", FinalResult: "pass",
		},
	}
	if err := r.Validate(); err == nil {
		t.Fatal("hidden retry must fail Validate")
	}
	sealed, err := r.Seal()
	if err == nil {
		t.Fatal("Seal must surface the flaky-retry error")
	}
	if sealed.Green {
		t.Fatal("flaky retry must not be green")
	}
	r2 := r
	r2.RetryUnderTest = true
	if err := r2.Validate(); err != nil {
		t.Fatalf("retry-under-test must validate: %v", err)
	}
	if _, err := r2.Seal(); err != nil {
		t.Fatalf("Seal retry-under-test: %v", err)
	}
}

// TestOracleFailsOnDisagreement is the eight-oracle rule: one disagreeing
// surface reddens the whole scenario.
func TestOracleFailsOnDisagreement(t *testing.T) {
	ok := []Observation{
		{Surface: SurfaceClientResult, Terminal: "success", EffectCount: 0},
		{Surface: SurfaceAuthoritativeState, Terminal: "success", EffectCount: 0},
		{Surface: SurfaceLedger, Terminal: "success", EffectCount: 0},
		{Surface: SurfaceRunnerAuthority, Terminal: "success", EffectCount: 0},
		{Surface: SurfaceArtifacts, Terminal: "success", EffectCount: 0},
		{Surface: SurfaceEvidence, Terminal: "success", EffectCount: 0},
		{Surface: SurfaceExternalEffects, Terminal: "success", EffectCount: 0},
		{Surface: SurfaceRecovery, Terminal: "success", EffectCount: 0},
	}
	if res := NewOracle().Check(ok); !res.Green {
		t.Fatalf("all-green observations reddened: %s", res.Summary())
	}
	bad := append([]Observation(nil), ok...)
	bad[6] = Observation{Surface: SurfaceExternalEffects, Terminal: "success", EffectCount: 2}
	if res := NewOracle().Check(bad); res.Green {
		t.Fatal("disagreeing external-effects surface must fail the oracle")
	}
}

// TestTopologyValidate pins that a distributed topology really has separate
// components — the smallest configuration that can truthfully validate Kiwi
// as a distributed system.
func TestTopologyValidate(t *testing.T) {
	ns, err := NewNamespace(time.Unix(0, 0).UTC(), strings.NewReader(strings.Repeat("c", 64)))
	if err != nil {
		t.Fatal(err)
	}
	local := Local(ns)
	if err := local.Validate(); err != nil {
		t.Fatalf("local topology: %v", err)
	}
	dist := Distributed(ns)
	if err := dist.Validate(); err != nil {
		t.Fatalf("distributed topology: %v", err)
	}
	kinds := dist.Kinds()
	if kinds[ComponentServer] < 1 || kinds[ComponentRunner] < 2 {
		t.Fatalf("distributed topology must have a server and two runners: %+v", kinds)
	}
	if len(dist.RunnerNames()) < 2 {
		t.Fatalf("runner names = %v", dist.RunnerNames())
	}
}
