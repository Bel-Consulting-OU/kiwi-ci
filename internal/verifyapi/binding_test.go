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
	// Digests are exactly 64 lowercase hex chars; tests use deterministic
	// pseudo-digests so fixtures are readable.
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
		EvidenceRoot:     mustDigest(t, "evidence"),
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

// TestFreshnessIntervalMustStartAfterIssue is the P1 adversarial rule: the
// ENTIRE proof execution interval must begin at or after the obligation's
// issuance. Pre-issued work (started before issued_at) can never satisfy a
// later obligation, even when completed_at is in range.
func TestFreshnessIntervalMustStartAfterIssue(t *testing.T) {
	ob := baseObligation(t) // MaxAgeSeconds 3600
	issued := ob.IssuedAt

	// started < issued < completed MUST fail with ErrFreshness.
	v := baseOutcome(t, ob)
	v.StartedAt = issued.Add(-10 * time.Second)
	v.CompletedAt = issued.Add(5 * time.Second)
	err := Bind(ob, v, issued.Add(30*time.Second))
	if !errors.Is(err, ErrFreshness) {
		t.Fatalf("started < issued < completed accepted: err = %v, want ErrFreshness", err)
	}

	// Direct CheckFreshness has the same rule.
	if err := ob.CheckFreshness(issued.Add(30*time.Second), issued.Add(-10*time.Second), issued.Add(5*time.Second)); !errors.Is(err, ErrFreshness) {
		t.Fatalf("CheckFreshness pre-issued window = %v, want ErrFreshness", err)
	}

	// started == issued == completed is OK (instantaneous proof at issue).
	v = baseOutcome(t, ob)
	v.StartedAt = issued
	v.CompletedAt = issued
	if err := Bind(ob, v, issued); err != nil {
		t.Fatalf("started == issued == completed refused: %v", err)
	}

	// started == issued < completed is OK.
	v = baseOutcome(t, ob)
	v.StartedAt = issued
	v.CompletedAt = issued.Add(5 * time.Second)
	if err := Bind(ob, v, issued.Add(30*time.Second)); err != nil {
		t.Fatalf("started == issued < completed refused: %v", err)
	}

	// started after issued is OK.
	v = baseOutcome(t, ob)
	v.StartedAt = issued.Add(time.Second)
	v.CompletedAt = issued.Add(5 * time.Second)
	if err := Bind(ob, v, issued.Add(30*time.Second)); err != nil {
		t.Fatalf("started after issued refused: %v", err)
	}

	// completed before started is refused (interval order).
	v = baseOutcome(t, ob)
	v.StartedAt = issued.Add(10 * time.Second)
	v.CompletedAt = issued.Add(5 * time.Second)
	if err := ob.CheckFreshness(issued.Add(30*time.Second), v.StartedAt, v.CompletedAt); !errors.Is(err, ErrFreshness) {
		t.Fatalf("completed before started accepted: err = %v, want ErrFreshness", err)
	}
}

// TestFreshnessNotBeforeWindow proves freshness.not_before delays the start
// of the acceptable execution interval: work starting after issue but before
// not_before is still refused.
func TestFreshnessNotBeforeWindow(t *testing.T) {
	ob := baseObligation(t)
	notBefore := ob.IssuedAt.Add(60 * time.Second)
	ob.Freshness = FreshnessPolicy{MaxAgeSeconds: 3600, NotBefore: &notBefore}

	// started after issued but before not_before is refused.
	v := baseOutcome(t, ob)
	v.StartedAt = ob.IssuedAt.Add(30 * time.Second)
	v.CompletedAt = ob.IssuedAt.Add(90 * time.Second)
	err := Bind(ob, v, ob.IssuedAt.Add(120*time.Second))
	if !errors.Is(err, ErrFreshness) {
		t.Fatalf("started before not_before accepted: err = %v, want ErrFreshness", err)
	}

	// started == not_before is OK.
	v.StartedAt = notBefore
	v.CompletedAt = notBefore.Add(time.Second)
	if err := Bind(ob, v, notBefore.Add(10*time.Second)); err != nil {
		t.Fatalf("started == not_before refused: %v", err)
	}

	// started after max(issued, not_before) is OK.
	v.StartedAt = notBefore.Add(10 * time.Second)
	v.CompletedAt = notBefore.Add(20 * time.Second)
	if err := Bind(ob, v, notBefore.Add(30*time.Second)); err != nil {
		t.Fatalf("started after not_before refused: %v", err)
	}
}

// TestFreshnessPolicyWindowValidation refuses an unsatisfiable freshness
// window at obligation construction time (fail closed before any outcome).
func TestFreshnessPolicyWindowValidation(t *testing.T) {
	ob := baseObligation(t)
	notBefore := ob.IssuedAt.Add(10 * time.Second)
	notAfter := ob.IssuedAt.Add(5 * time.Second)
	ob.Freshness = FreshnessPolicy{NotBefore: &notBefore, NotAfter: &notAfter}
	if err := ob.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("not_after before not_before = %v, want ErrInvalid", err)
	}

	ob = baseObligation(t)
	notBefore = ob.IssuedAt.Add(4000 * time.Second) // past max_age 3600
	ob.Freshness = FreshnessPolicy{MaxAgeSeconds: 3600, NotBefore: &notBefore}
	if err := ob.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("not_before outside max_age window = %v, want ErrInvalid", err)
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

// TestRegistryRefusesPreIssuedOutcome proves the registry applies the interval
// rule at record time: nothing is stored when started_at precedes issued_at.
func TestRegistryRefusesPreIssuedOutcome(t *testing.T) {
	r := NewRegistry(nil)
	ob := baseObligation(t)
	if err := r.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}
	v := baseOutcome(t, ob)
	v.StartedAt = ob.IssuedAt.Add(-time.Minute)
	v.CompletedAt = ob.IssuedAt.Add(10 * time.Second)
	if err := r.RecordOutcome(v); !errors.Is(err, ErrFreshness) {
		t.Fatalf("RecordOutcome pre-issued = %v, want ErrFreshness", err)
	}
	if got := r.OutcomesForObligation(ob.ObligationID); len(got) != 0 {
		t.Fatalf("outcomes stored after refusal = %d, want 0", len(got))
	}
}

// TestDigestValidation pins the SHA-256 digest shape: exactly 64 lowercase
// hex chars. Truncated, extended, uppercase, empty and non-hex values are all
// refused at Validate/Bind/decode.
func TestDigestValidation(t *testing.T) {
	good := mustDigest(t, "candidate")
	if err := validateDigest("test", good); err != nil {
		t.Fatalf("64-char lowercase hex rejected: %v", err)
	}

	cases := []struct {
		name string
		d    Digest
	}{
		{"63-char", Digest(string(good[:63]))},
		{"65-char", Digest(string(good) + "a")},
		{"uppercase", Digest("A" + string(good[1:]))},
		{"empty", Digest("")},
		{"non-hex", Digest("z" + string(good[1:]))},
		{"mixed-case-mid", Digest(string(good[:32]) + "B" + string(good[33:]))},
	}
	for _, tc := range cases {
		if err := validateDigest("test", tc.d); !errors.Is(err, ErrInvalid) {
			t.Fatalf("validateDigest(%s) = %v, want ErrInvalid", tc.name, err)
		}
	}

	// Obligation construction fails closed on a malformed pin.
	ob := baseObligation(t)
	ob.ImmutableCandidateDigest = "deadbeef" // not 64 hex chars
	if err := ob.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("obligation with short digest = %v, want ErrInvalid", err)
	}

	// Outcome construction fails closed on a malformed evidence root.
	v := baseOutcome(t, baseObligation(t))
	v.EvidenceRoot = "evidence-root-1"
	if err := v.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("outcome with non-digest evidence_root = %v, want ErrInvalid", err)
	}

	// Bind refuses a malformed digest even if the caller skipped Validate.
	ob = baseObligation(t)
	v = baseOutcome(t, ob)
	v.EvidenceRoot = Digest(string(good[:63]))
	if err := Bind(ob, v, ob.IssuedAt.Add(30*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Bind with 63-char evidence_root = %v, want ErrInvalid", err)
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
			EvidenceRoot:     mustDigest(t, "evidence-"+cand),
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
		EvidenceRoot:     mustDigest(t, "evidence-bad"),
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

// TestCompareGroupDeterministicSelection proves CompareGroup picks a
// canonical attempt per candidate (latest completed_at, ties broken by
// ascending verification_id) and that two calls over the same records return
// identical ordering and winner.
func TestCompareGroupDeterministicSelection(t *testing.T) {
	r := NewRegistry(nil)
	base := mustDigest(t, "base-snapshot")
	group := SpeculativeGroup{
		VerificationGroupID: "grp-det",
		BaseSnapshotDigest:  base,
		CandidateDigests: map[string]Digest{
			"alpha": mustDigest(t, "alpha"),
			"beta":  mustDigest(t, "beta"),
		},
	}
	if err := r.RegisterGroup(group); err != nil {
		t.Fatalf("RegisterGroup = %v", err)
	}

	issued := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	record := func(vid, cand, candID string, completed time.Time) {
		t.Helper()
		ob := VerificationObligation{
			ObligationID:               "ob-" + vid,
			Subject:                    candID,
			ImmutableCandidateDigest:   group.CandidateDigests[candID],
			SourceSnapshotDigest:       base,
			VerificationContractDigest: mustDigest(t, "contract"),
			RequiredChecks:             []string{"digest-match"},
			RequiredAssurance:          "attested-v1",
			Freshness:                  FreshnessPolicy{MaxAgeSeconds: 3600},
			IssuedAt:                   issued,
		}
		if err := r.SubmitObligation(ob); err != nil {
			t.Fatalf("SubmitObligation %s = %v", vid, err)
		}
		v := VerificationOutcome{
			VerificationID:   vid,
			ObligationID:     ob.ObligationID,
			CandidateDigest:  ob.ImmutableCandidateDigest,
			SnapshotDigest:   base,
			ContractDigest:   ob.VerificationContractDigest,
			Outcome:          OutcomePass,
			AssuranceProfile: ob.RequiredAssurance,
			CompletedChecks:  []string{"digest-match"},
			EvidenceRoot:     mustDigest(t, "evidence-"+vid),
			Resources: ResourceFacts{
				RunnerClass:         "standard",
				ExecutionLatencyNS:  100,
				Speculative:         true,
				VerificationGroupID: group.VerificationGroupID,
				CandidateID:         candID,
			},
			StartedAt:   completed.Add(-time.Second),
			CompletedAt: completed,
		}
		if err := r.RecordOutcome(v); err != nil {
			t.Fatalf("RecordOutcome %s = %v", vid, err)
		}
	}

	// alpha: three attempts. Two share the latest completed_at (t+20), so
	// the ascending-verification_id tie-break picks ver-alpha-late over
	// ver-alpha-mid; ver-alpha-early (t+10) loses on completed_at.
	record("ver-alpha-early", "alpha", "alpha", issued.Add(10*time.Second))
	record("ver-alpha-mid", "alpha", "alpha", issued.Add(20*time.Second))
	record("ver-alpha-late", "alpha", "alpha", issued.Add(20*time.Second))

	// beta: two attempts; the later completed_at is strictly newer and wins
	// even though its verification id sorts later.
	record("ver-beta-a", "beta", "beta", issued.Add(30*time.Second))
	record("ver-beta-b", "beta", "beta", issued.Add(40*time.Second))

	var first GroupComparison
	for i := 0; i < 2; i++ {
		cmp, err := r.CompareGroup("grp-det")
		if err != nil {
			t.Fatalf("CompareGroup #%d = %v", i, err)
		}
		if i == 0 {
			first = cmp
			continue
		}
		if len(cmp.Candidates) != len(first.Candidates) {
			t.Fatalf("candidate count drift: %d vs %d", len(cmp.Candidates), len(first.Candidates))
		}
		for j := range cmp.Candidates {
			if !sameCandidateFacts(cmp.Candidates[j], first.Candidates[j]) {
				t.Fatalf("CompareGroup not deterministic at row %d:\nfirst = %+v\nsecond = %+v", j, first.Candidates[j], cmp.Candidates[j])
			}
		}
	}

	if len(first.Candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(first.Candidates))
	}
	alpha := first.Candidates[0]
	if alpha.CandidateID != "alpha" {
		t.Fatalf("row 0 = %q, want alpha", alpha.CandidateID)
	}
	// Tie on completed_at at t+20: ascending verification_id picks
	// ver-alpha-late (l < m).
	if alpha.VerificationID != "ver-alpha-late" {
		t.Fatalf("alpha winner = %q, want ver-alpha-late", alpha.VerificationID)
	}
	beta := first.Candidates[1]
	if beta.CandidateID != "beta" {
		t.Fatalf("row 1 = %q, want beta", beta.CandidateID)
	}
	if beta.VerificationID != "ver-beta-b" {
		t.Fatalf("beta winner = %q, want ver-beta-b (latest completed_at)", beta.VerificationID)
	}
}

// TestRecordOutcomeFillsMeasured proves the registry derives Measured.DurationNS
// from the execution interval and overwrites any caller-supplied value.
func TestRecordOutcomeFillsMeasured(t *testing.T) {
	r := NewRegistry(nil)
	ob := baseObligation(t)
	if err := r.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}
	v := baseOutcome(t, ob)
	v.Resources.Measured = &MeasuredResourceFacts{DurationNS: 999} // dishonest reporter
	if err := r.RecordOutcome(v); err != nil {
		t.Fatalf("RecordOutcome = %v", err)
	}
	stored, err := r.Outcome(v.VerificationID)
	if err != nil {
		t.Fatalf("Outcome = %v", err)
	}
	want := v.CompletedAt.Sub(v.StartedAt).Nanoseconds()
	if stored.Resources.Measured == nil {
		t.Fatal("Measured is nil after record")
	}
	if stored.Resources.Measured.DurationNS != want {
		t.Fatalf("Measured.DurationNS = %d, want %d", stored.Resources.Measured.DurationNS, want)
	}
}

// sameCandidateFacts compares two comparison rows by value, including the
// pointed-to Measured facts (struct equality would compare pointer identity).
func sameCandidateFacts(a, b CandidateFacts) bool {
	if a.CandidateID != b.CandidateID ||
		a.CandidateDigest != b.CandidateDigest ||
		a.VerificationID != b.VerificationID ||
		a.Outcome != b.Outcome {
		return false
	}
	ar, br := a.Resources, b.Resources
	if (ar.Measured == nil) != (br.Measured == nil) {
		return false
	}
	if ar.Measured != nil && *ar.Measured != *br.Measured {
		return false
	}
	ar.Measured, br.Measured = nil, nil
	return ar == br
}

// equalFacts compares resource facts with the speculative/group fields and
// substrate-derived Measured reset, because the fixtures in the table omit
// group bookkeeping and measured values until submit time.
func equalFacts(a, b ResourceFacts) bool {
	a.Speculative, b.Speculative = false, false
	a.VerificationGroupID, b.VerificationGroupID = "", ""
	a.CandidateID, b.CandidateID = "", ""
	a.Measured, b.Measured = nil, nil
	return a == b
}
