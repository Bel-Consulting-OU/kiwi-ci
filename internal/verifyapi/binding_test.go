package verifyapi

import (
	"errors"
	"testing"
	"time"
)

// testClock is a controllable registry clock for freshness tests.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }

func mustDigest(t *testing.T, seed string) Digest {
	t.Helper()
	// Any stable lowercase-hex string is a valid digest under the package
	// rule; tests use deterministic pseudo-digests so fixtures are readable.
	const hexDigits = "0123456789abcdef"
	d := make([]byte, 64)
	for i := range d {
		d[i] = hexDigits[(int(seed[i%len(seed)])+i)%16]
	}
	return Digest(d)
}

func baseObligation(t *testing.T) VerificationObligation {
	t.Helper()
	return VerificationObligation{
		ObligationID:               "ob-1",
		Subject:                    "cand-1",
		ImmutableCandidateDigest:   mustDigest(t, "candidate"),
		SourceSnapshotDigest:       mustDigest(t, "snapshot"),
		VerificationContractDigest: mustDigest(t, "contract"),
		RequiredChecks:             []string{"digest-match", "signature"},
		RequiredAssurance:          "attested-v1",
		Freshness:                  FreshnessPolicy{MaxAgeSeconds: 3600},
		OpaqueCorrelationMetadata:  map[string]string{"trace": "abc"},
		IssuedAt:                   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

func baseOutcome(t *testing.T, ob VerificationObligation) VerificationOutcome {
	t.Helper()
	return VerificationOutcome{
		VerificationID:   "ver-1",
		ObligationID:     ob.ObligationID,
		CandidateDigest:  ob.ImmutableCandidateDigest,
		SnapshotDigest:   ob.SourceSnapshotDigest,
		ContractDigest:   ob.VerificationContractDigest,
		Outcome:          OutcomePass,
		AssuranceProfile: ob.RequiredAssurance,
		CompletedChecks:  []string{"digest-match", "signature"},
		ExecutionIDs:     []string{"exec-1", "exec-2"},
		EvidenceRoot:     "evidence-root-1",
		Resources: ResourceFacts{
			QueueLatencyNS:     1_000_000,
			ExecutionLatencyNS: 5_000_000_000,
			WallTimeNS:         5_200_000_000,
			CPUTimeNS:          4_800_000_000,
			PeakMemoryBytes:    64 << 20,
			IOBytes:            1 << 20,
			CacheHits:          3,
			CacheMisses:        1,
			RunnerClass:        "standard",
			RetryCount:         0,
		},
		StartedAt:   ob.IssuedAt.Add(time.Second),
		CompletedAt: ob.IssuedAt.Add(10 * time.Second),
	}
}

// TestBindingWrongCandidateDigestRefused is the core claim-bound rule: an
// outcome for a different candidate is a different obligation and must not
// discharge this one.
func TestBindingWrongCandidateDigestRefused(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.CandidateDigest = mustDigest(t, "other-candidate")
	err := Bind(ob, v, ob.IssuedAt.Add(30*time.Second))
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("Bind with wrong candidate digest = %v, want ErrBinding", err)
	}
}

func TestBindingWrongSnapshotAndContractRefused(t *testing.T) {
	ob := baseObligation(t)

	vs := baseOutcome(t, ob)
	vs.SnapshotDigest = mustDigest(t, "other-snapshot")
	if err := Bind(ob, vs, ob.IssuedAt.Add(30*time.Second)); !errors.Is(err, ErrBinding) {
		t.Fatalf("wrong snapshot: err = %v, want ErrBinding", err)
	}

	vc := baseOutcome(t, ob)
	vc.ContractDigest = mustDigest(t, "other-contract")
	if err := Bind(ob, vc, ob.IssuedAt.Add(30*time.Second)); !errors.Is(err, ErrBinding) {
		t.Fatalf("wrong contract: err = %v, want ErrBinding", err)
	}
}

func TestBindingExactMatchAccepted(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	if err := Bind(ob, v, ob.IssuedAt.Add(30*time.Second)); err != nil {
		t.Fatalf("Bind exact match = %v, want nil", err)
	}
}

// TestBindingPassRequiresAllChecks proves a pass claim is refused when a
// required check is missing — the binding rule includes evidence coverage.
func TestBindingPassRequiresAllChecks(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.CompletedChecks = []string{"digest-match"}
	err := Bind(ob, v, ob.IssuedAt.Add(30*time.Second))
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("pass missing required check = %v, want ErrBinding", err)
	}
	// A fail verdict does not claim coverage and is acceptable with a subset.
	v.Outcome = OutcomeFail
	if err := Bind(ob, v, ob.IssuedAt.Add(30*time.Second)); err != nil {
		t.Fatalf("fail with subset of checks = %v, want nil", err)
	}
}

func TestBindingAssuranceMismatchRefused(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.AssuranceProfile = "lower-v0"
	err := Bind(ob, v, ob.IssuedAt.Add(30*time.Second))
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("assurance mismatch = %v, want ErrBinding", err)
	}
}

// TestRegistryRefusesUnboundOutcome proves the registry applies the same
// fail-closed rule when recording: nothing is stored on a mismatch.
func TestRegistryRefusesUnboundOutcome(t *testing.T) {
	r := NewRegistry(nil)
	ob := baseObligation(t)
	if err := r.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}
	v := baseOutcome(t, ob)
	v.CandidateDigest = mustDigest(t, "wrong")
	if err := r.RecordOutcome(v); !errors.Is(err, ErrBinding) {
		t.Fatalf("RecordOutcome wrong candidate = %v, want ErrBinding", err)
	}
	if got := r.OutcomesForObligation(ob.ObligationID); len(got) != 0 {
		t.Fatalf("outcomes stored after refusal = %d, want 0", len(got))
	}
}

func TestFreshnessExpiryEnforced(t *testing.T) {
	ob := baseObligation(t)
	expiry := ob.IssuedAt.Add(60 * time.Second)
	ob.Freshness = FreshnessPolicy{NotAfter: &expiry}
	nowBefore := ob.IssuedAt.Add(30 * time.Second)
	nowAfter := ob.IssuedAt.Add(90 * time.Second)

	if err := ob.CheckFreshness(nowBefore, ob.IssuedAt, nowBefore); err != nil {
		t.Fatalf("fresh obligation refused: %v", err)
	}
	if err := ob.CheckFreshness(nowAfter, ob.IssuedAt, nowAfter); !errors.Is(err, ErrFreshness) {
		t.Fatalf("expired obligation accepted: err = %v, want ErrFreshness", err)
	}
	// A completion timestamped past expiry is refused even if the clock has
	// not reached it yet (backdated/forward-dated laundering).
	if err := ob.CheckFreshness(nowBefore, ob.IssuedAt, nowAfter); !errors.Is(err, ErrFreshness) {
		t.Fatalf("post-expiry completed_at accepted: err = %v, want ErrFreshness", err)
	}
}

func TestFreshnessMaxAgeEnforced(t *testing.T) {
	ob := baseObligation(t) // MaxAgeSeconds 3600
	v := baseOutcome(t, ob)
	v.StartedAt = ob.IssuedAt.Add(3500 * time.Second)
	v.CompletedAt = ob.IssuedAt.Add(3700 * time.Second)
	err := Bind(ob, v, ob.IssuedAt.Add(3650*time.Second))
	if !errors.Is(err, ErrFreshness) {
		t.Fatalf("stale outcome accepted: err = %v, want ErrFreshness", err)
	}
	// Inside the window the same outcome binds.
	v.CompletedAt = ob.IssuedAt.Add(3550 * time.Second)
	if err := Bind(ob, v, ob.IssuedAt.Add(3550*time.Second)); err != nil {
		t.Fatalf("fresh outcome refused: %v", err)
	}
}

func TestRegistryFreshnessUsesClock(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)}
	r := NewRegistry(clk.now)
	ob := baseObligation(t)
	ob.IssuedAt = clk.t
	expiry := clk.t.Add(30 * time.Second)
	ob.Freshness = FreshnessPolicy{NotAfter: &expiry}
	if err := r.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}
	v := baseOutcome(t, ob)
	v.StartedAt = clk.t.Add(time.Second)
	v.CompletedAt = clk.t.Add(2 * time.Second)
	if err := r.RecordOutcome(v); err != nil {
		t.Fatalf("RecordOutcome fresh = %v", err)
	}

	clk.t = expiry.Add(time.Second)
	v2 := baseOutcome(t, ob)
	v2.VerificationID = "ver-2"
	v2.StartedAt = clk.t
	v2.CompletedAt = clk.t.Add(time.Second)
	if err := r.RecordOutcome(v2); !errors.Is(err, ErrFreshness) {
		t.Fatalf("RecordOutcome after expiry = %v, want ErrFreshness", err)
	}
}

// TestSpeculativeGroupThreeCandidatesSharedBase: three candidates on one
// shared base snapshot produce comparable resource facts; an outcome bound
// to a different base is refused.
func TestSpeculativeGroupThreeCandidatesSharedBase(t *testing.T) {
	r := NewRegistry(nil)
	base := mustDigest(t, "base-snapshot")
	group := SpeculativeGroup{
		VerificationGroupID: "grp-1",
		BaseSnapshotDigest:  base,
		CandidateDigests: map[string]Digest{
			"alpha": mustDigest(t, "alpha"),
			"beta":  mustDigest(t, "beta"),
			"gamma": mustDigest(t, "gamma"),
		},
	}
	if err := r.RegisterGroup(group); err != nil {
		t.Fatalf("RegisterGroup = %v", err)
	}

	// One obligation+outcome per candidate, all on the shared base.
	stats := map[string]ResourceFacts{
		"alpha": {QueueLatencyNS: 10, ExecutionLatencyNS: 100, WallTimeNS: 110, CPUTimeNS: 90, PeakMemoryBytes: 1000, IOBytes: 10, CacheHits: 1, CacheMisses: 0, RunnerClass: "standard"},
		"beta":  {QueueLatencyNS: 20, ExecutionLatencyNS: 200, WallTimeNS: 220, CPUTimeNS: 180, PeakMemoryBytes: 2000, IOBytes: 20, CacheHits: 0, CacheMisses: 1, RunnerClass: "standard"},
		"gamma": {QueueLatencyNS: 30, ExecutionLatencyNS: 300, WallTimeNS: 330, CPUTimeNS: 280, PeakMemoryBytes: 3000, IOBytes: 30, CacheHits: 2, CacheMisses: 2, RunnerClass: "standard"},
	}
	for i, cand := range []string{"alpha", "beta", "gamma"} {
		ob := VerificationObligation{
			ObligationID:               "ob-" + cand,
			Subject:                    cand,
			ImmutableCandidateDigest:   group.CandidateDigests[cand],
			SourceSnapshotDigest:       base,
			VerificationContractDigest: mustDigest(t, "contract"),
			RequiredChecks:             []string{"digest-match"},
			RequiredAssurance:          "attested-v1",
			Freshness:                  FreshnessPolicy{MaxAgeSeconds: 3600},
			IssuedAt:                   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		}
		if err := r.SubmitObligation(ob); err != nil {
			t.Fatalf("SubmitObligation %s = %v", cand, err)
		}
		rf := stats[cand]
		rf.Speculative = true
		rf.VerificationGroupID = group.VerificationGroupID
		rf.CandidateID = cand
		v := VerificationOutcome{
			VerificationID:   "ver-" + cand,
			ObligationID:     ob.ObligationID,
			CandidateDigest:  ob.ImmutableCandidateDigest,
			SnapshotDigest:   base,
			ContractDigest:   ob.VerificationContractDigest,
			Outcome:          OutcomePass,
			AssuranceProfile: ob.RequiredAssurance,
			CompletedChecks:  []string{"digest-match"},
			EvidenceRoot:     "evidence-" + cand,
			Resources:        rf,
			StartedAt:        ob.IssuedAt.Add(time.Duration(i+1) * time.Second),
			CompletedAt:      ob.IssuedAt.Add(time.Duration(i+2) * time.Second),
		}
		if err := r.RecordOutcome(v); err != nil {
			t.Fatalf("RecordOutcome %s = %v", cand, err)
		}
	}

	cmp, err := r.CompareGroup("grp-1")
	if err != nil {
		t.Fatalf("CompareGroup = %v", err)
	}
	if len(cmp.Candidates) != 3 {
		t.Fatalf("candidates = %d, want 3", len(cmp.Candidates))
	}
	// Rows are ordered by candidate id; each row carries that candidate's
	// facts so the three are directly comparable.
	wantOrder := []string{"alpha", "beta", "gamma"}
	for i, row := range cmp.Candidates {
		if row.CandidateID != wantOrder[i] {
			t.Fatalf("row %d candidate = %q, want %q", i, row.CandidateID, wantOrder[i])
		}
		if row.Resources != stats[wantOrder[i]] && !equalFacts(row.Resources, stats[wantOrder[i]]) {
			t.Fatalf("row %s facts = %+v, want %+v", row.CandidateID, row.Resources, stats[wantOrder[i]])
		}
		if row.Outcome != OutcomePass {
			t.Fatalf("row %s outcome = %v, want pass", row.CandidateID, row.Outcome)
		}
	}
	if cmp.BaseSnapshotDigest != base {
		t.Fatalf("comparison base = %s, want %s", cmp.BaseSnapshotDigest, base)
	}

	// An outcome claiming the group but a different base snapshot is refused.
	bad := VerificationOutcome{
		VerificationID:   "ver-bad",
		ObligationID:     "ob-alpha",
		CandidateDigest:  group.CandidateDigests["alpha"],
		SnapshotDigest:   mustDigest(t, "other-base"),
		ContractDigest:   mustDigest(t, "contract"),
		Outcome:          OutcomePass,
		AssuranceProfile: "attested-v1",
		CompletedChecks:  []string{"digest-match"},
		EvidenceRoot:     "evidence-bad",
		Resources: ResourceFacts{
			RunnerClass:         "standard",
			Speculative:         true,
			VerificationGroupID: "grp-1",
			CandidateID:         "alpha",
		},
		StartedAt:   time.Date(2026, 1, 2, 3, 4, 6, 0, time.UTC),
		CompletedAt: time.Date(2026, 1, 2, 3, 4, 7, 0, time.UTC),
	}
	// First the obligation binding refuses the foreign snapshot…
	obAlpha, err := r.Obligation("ob-alpha")
	if err != nil {
		t.Fatalf("Obligation = %v", err)
	}
	if err := r.RecordOutcome(bad); !errors.Is(err, ErrBinding) {
		t.Fatalf("foreign-base outcome = %v, want ErrBinding", err)
	}
	// …and a hypothetically rebound outcome still fails the group rule.
	rebound := bad
	rebound.SnapshotDigest = obAlpha.SourceSnapshotDigest
	rebound.Resources.CandidateID = "delta"
	if err := r.RecordOutcome(rebound); !errors.Is(err, ErrGroupBinding) {
		t.Fatalf("non-member candidate = %v, want ErrGroupBinding", err)
	}
}

// equalFacts compares resource facts with the speculative/group fields reset,
// because the fixtures in the table omit group bookkeeping until submit time.
func equalFacts(a, b ResourceFacts) bool {
	a.Speculative, b.Speculative = false, false
	a.VerificationGroupID, b.VerificationGroupID = "", ""
	a.CandidateID, b.CandidateID = "", ""
	return a == b
}
