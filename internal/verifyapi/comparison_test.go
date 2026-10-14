package verifyapi

import (
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// testClaimCandidateFact builds a claim-authority row (never pass: a claim
// is never projected into a plain pass) for the open comparison surface.
func testClaimCandidateFact(t *testing.T, id string) CandidateFact {
	t.Helper()
	return CandidateFact{
		CandidateID:       id,
		CandidateDigest:   mustDigest(t, "cand-"+id),
		VerificationID:    "ver-" + id,
		Terminal:          TerminalFailed,
		Outcome:           OutcomeFail,
		Assurance:         "uncontrolled",
		Authority:         RowAuthorityClaim,
		WallTimeNS:        Observed(int64(5_000_000_000)),
		CPUTimeNS:         Observed(int64(1_000_000_000)),
		PeakMemoryBytes:   Observed(int64(64 << 20)),
		IOBytes:           Observed(int64(1 << 20)),
		CacheHits:         Observed(int64(10)),
		CacheMisses:       Observed(int64(2)),
		ArtifactSizeBytes: Epistemic[int64]{Value: 1024, Level: EpistemicObserved},
	}
}

// testForgedVerifiedCandidateFact builds a caller-forged row that claims
// verified authority — the attack CompareCandidates must refuse.
func testForgedVerifiedCandidateFact(t *testing.T, id string) CandidateFact {
	t.Helper()
	f := testClaimCandidateFact(t, id)
	f.Terminal = TerminalPassed
	f.Outcome = OutcomePass
	f.Authority = RowAuthorityVerified
	return f
}

func TestCompareCandidatesNeutralAndDeterministic(t *testing.T) {
	// CompareCandidates is claim-only (a forged verified row is refused,
	// see TestCompareCandidatesRefusesForgedVerifiedAuthority); the rows
	// here are honest claims.
	a := testClaimCandidateFact(t, "b")
	b := testClaimCandidateFact(t, "a")
	base := mustDigest(t, "snap")

	cmp, err := CompareCandidates(base, []CandidateFact{a, b})
	if err != nil {
		t.Fatalf("CompareCandidates = %v", err)
	}
	if cmp.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %d", cmp.SchemaVersion)
	}
	if cmp.BaseSnapshotDigest != base {
		t.Fatalf("BaseSnapshotDigest = %s", cmp.BaseSnapshotDigest)
	}
	// Sorted by candidate id regardless of input order.
	if cmp.Candidates[0].CandidateID != "a" || cmp.Candidates[1].CandidateID != "b" {
		t.Fatalf("order = %s, %s", cmp.Candidates[0].CandidateID, cmp.Candidates[1].CandidateID)
	}
	// Neutral by type shape: a comparison carries facts only. A consumer
	// (an evidence consumer or anyone) applies its own utility; nothing here ranks rows.
	if len(cmp.Candidates) != 2 {
		t.Fatalf("rows = %d", len(cmp.Candidates))
	}
	for _, row := range cmp.Candidates {
		if row.Outcome != row.Terminal.ProjectCoarse() {
			t.Fatalf("row %s outcome is not the coarse projection", row.CandidateID)
		}
	}

	// The wire shape is deterministic: same input set, same bytes order.
	cmp2, err := CompareCandidates(base, []CandidateFact{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if cmp2.Candidates[0].CandidateID != cmp.Candidates[0].CandidateID {
		t.Fatal("comparison order must not depend on input order")
	}
}

func TestCompareCandidatesRefuses(t *testing.T) {
	ok := testClaimCandidateFact(t, "a")
	for name, mut := range map[string]func(*[]CandidateFact){
		"empty": func(rows *[]CandidateFact) { *rows = nil },
		"duplicate id": func(rows *[]CandidateFact) {
			*rows = append(*rows, (*rows)[0])
		},
		"missing candidate id": func(rows *[]CandidateFact) {
			c := (*rows)[0]
			c.CandidateID = ""
			*rows = append(*rows, c)
		},
		"bad digest": func(rows *[]CandidateFact) {
			c := (*rows)[0]
			c.CandidateDigest = "nope"
			*rows = append(*rows, c)
		},
		"outcome not projection": func(rows *[]CandidateFact) {
			c := (*rows)[0]
			c.Terminal = TerminalFailed
			c.Outcome = OutcomePass
			*rows = append(*rows, c)
		},
		"negative size": func(rows *[]CandidateFact) {
			c := (*rows)[0]
			c.ArtifactSizeBytes = Epistemic[int64]{Value: -1, Level: EpistemicObserved}
			*rows = append(*rows, c)
		},
	} {
		rows := []CandidateFact{ok}
		mut(&rows)
		if name == "empty" {
			rows = nil
		}
		if _, err := CompareCandidates("", rows); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	// A malformed base digest is refused.
	if _, err := CompareCandidates("nope", []CandidateFact{ok}); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad base digest must be refused")
	}
}

func TestFactFromOutcome(t *testing.T) {
	iv := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	v := VerificationOutcome{
		VerificationID:   "ver-1",
		ObligationID:     "ob-1",
		CandidateDigest:  mustDigest(t, "candidate"),
		SnapshotDigest:   mustDigest(t, "snapshot"),
		ContractDigest:   mustDigest(t, "contract"),
		Outcome:          OutcomePass,
		AssuranceProfile: model.AssuranceUncontrolled.Name(),
		CompletedChecks:  []string{CheckJobStatusSuccess},
		ExecutionIDs:     []string{"exec-1"},
		EvidenceRoot:     mustDigest(t, "evidence"),
		Resources: ResourceFacts{
			WallTimeNS:      3_000_000_000,
			CPUTimeNS:       2_000_000_000,
			PeakMemoryBytes: 1024,
			RunnerClass:     "standard",
			Measured:        &MeasuredResourceFacts{DurationNS: 9, WallTimeNS: 4_000_000_000},
		},
		StartedAt:   iv,
		CompletedAt: iv.Add(time.Minute),
	}
	ev := VerifiedEvidence{
		ExecutionIDs:       []string{"exec-1"},
		EvidenceRoot:       mustDigest(t, "evidence"),
		AttestationDigests: []Digest{mustDigest(t, "att")},
		JobStatus:          "success",
		CompletedChecks:    []string{CheckJobStatusSuccess},
		Assurance:          model.AssuranceUncontrolled,
		VerifierIdentity:   "test-verifier/v1",
		VerifiedAt:         iv.Add(time.Second),
	}
	sealed, err := sealDerivedOutcome(v, v, ev)
	if err != nil {
		t.Fatalf("sealDerivedOutcome = %v", err)
	}
	complete := EvidenceCompleteness{Required: 1, Present: 1, Verified: 1}
	f, err := FactFromOutcome("c1", sealed, complete, 2048)
	if err != nil {
		t.Fatalf("FactFromOutcome = %v", err)
	}
	if f.Terminal != TerminalPassed || f.Outcome != OutcomePass {
		t.Fatalf("fact terminal/outcome = %s/%s", f.Terminal, f.Outcome)
	}
	// Attested wall time wins over derived/reported figures.
	if f.WallTimeNS.Value != 4_000_000_000 || f.WallTimeNS.Level != EpistemicAttested {
		t.Fatalf("WallTimeNS = %+v, want attested 4s", f.WallTimeNS)
	}
	// CPU and memory stay REPORTED on a verified row: Authority=verified
	// describes how the row was minted, not the epistemic strength of
	// every number on it.
	if f.CPUTimeNS.Value != 2_000_000_000 || f.CPUTimeNS.Level != EpistemicObserved {
		t.Fatalf("CPUTimeNS = %+v, want reported/observed 2s", f.CPUTimeNS)
	}
	if f.PeakMemoryBytes.Value != 1024 || f.PeakMemoryBytes.Level != EpistemicObserved {
		t.Fatalf("PeakMemoryBytes = %+v, want reported/observed", f.PeakMemoryBytes)
	}
	if f.IOBytes.Level != EpistemicObserved || f.CacheHits.Level != EpistemicObserved || f.CacheMisses.Level != EpistemicObserved {
		t.Fatalf("io/cache levels = %s/%s/%s, want observed", f.IOBytes.Level, f.CacheHits.Level, f.CacheMisses.Level)
	}
	if f.ArtifactSizeBytes.Value != 2048 {
		t.Fatalf("ArtifactSizeBytes = %d", f.ArtifactSizeBytes)
	}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}

	// A claimed pass with missing evidence never becomes TerminalPassed.
	missing := EvidenceCompleteness{Required: 2, Present: 1, Verified: 1, Missing: 1}
	f2, err := FactFromOutcome("c1", sealed, missing, 0)
	if err != nil {
		t.Fatalf("FactFromOutcome missing = %v", err)
	}
	if f2.Terminal != TerminalEvidenceIncomplete || f2.Outcome != OutcomePartial {
		t.Fatalf("missing-evidence fact = %s/%s", f2.Terminal, f2.Outcome)
	}

	// Substrate-derived duration wins over the reported figure when no
	// attested job window exists (derived > reported).
	derivedOnly := v
	derivedOnly.Resources.Measured = &MeasuredResourceFacts{DurationNS: 9}
	sealedDerived, err := sealDerivedOutcome(derivedOnly, derivedOnly, ev)
	if err != nil {
		t.Fatalf("sealDerivedOutcome derived = %v", err)
	}
	f3, err := FactFromOutcome("c1", sealedDerived, complete, 0)
	if err != nil {
		t.Fatalf("FactFromOutcome derived = %v", err)
	}
	if f3.WallTimeNS.Value != 9 || f3.WallTimeNS.Level != EpistemicDerived {
		t.Fatalf("WallTimeNS = %+v, want derived 9ns", f3.WallTimeNS)
	}

	// Reported wall time is used only when Measured carries neither an
	// attested window nor a derived interval.
	noMeasured := v
	noMeasured.Resources.Measured = nil
	sealedReported, err := sealDerivedOutcome(noMeasured, noMeasured, ev)
	if err != nil {
		t.Fatalf("sealDerivedOutcome reported = %v", err)
	}
	f3b, err := FactFromOutcome("c1", sealedReported, complete, 0)
	if err != nil {
		t.Fatalf("FactFromOutcome reported = %v", err)
	}
	if f3b.WallTimeNS.Value != 3_000_000_000 || f3b.WallTimeNS.Level != EpistemicObserved {
		t.Fatalf("WallTimeNS = %+v, want reported/observed 3s", f3b.WallTimeNS)
	}

	failed := v
	failed.Outcome = OutcomeFail
	failEv := ev
	failEv.JobStatus = string(model.StatusFailure)
	sealedFailed, err := sealDerivedOutcome(failed, failed, failEv)
	if err != nil {
		t.Fatalf("sealDerivedOutcome failed = %v", err)
	}
	f4, err := FactFromOutcome("c1", sealedFailed, complete, 0)
	if err != nil {
		t.Fatalf("FactFromOutcome failed = %v", err)
	}
	if f4.Terminal != TerminalFailed || f4.Outcome != OutcomeFail {
		t.Fatalf("failed fact = %s/%s", f4.Terminal, f4.Outcome)
	}

	// A bare (unsealed) claim is refused: it can never mint RowAuthorityVerified.
	if _, err := FactFromOutcome("c1", DerivedVerifiedOutcome{outcome: v, evidence: ev}, complete, 0); !errors.Is(err, ErrUnverified) {
		t.Fatalf("unsealed FactFromOutcome = %v, want ErrUnverified", err)
	}
}

func TestCandidateFactValidate(t *testing.T) {
	base := testClaimCandidateFact(t, "a")
	for name, mut := range map[string]func(*CandidateFact){
		"no id":        func(c *CandidateFact) { c.CandidateID = "" },
		"bad digest":   func(c *CandidateFact) { c.CandidateDigest = "x" },
		"no ver":       func(c *CandidateFact) { c.VerificationID = "" },
		"bad terminal": func(c *CandidateFact) { c.Terminal = "nope" },
		"no assurance": func(c *CandidateFact) { c.Assurance = "" },
		"neg wall":     func(c *CandidateFact) { c.WallTimeNS = Observed(int64(-1)) },
		"neg cpu":      func(c *CandidateFact) { c.CPUTimeNS = Observed(int64(-1)) },
		"neg mem":      func(c *CandidateFact) { c.PeakMemoryBytes = Observed(int64(-1)) },
		"neg io":       func(c *CandidateFact) { c.IOBytes = Observed(int64(-1)) },
		"neg hits":     func(c *CandidateFact) { c.CacheHits = Observed(int64(-1)) },
		"neg misses":   func(c *CandidateFact) { c.CacheMisses = Observed(int64(-1)) },
		"unknown wall level": func(c *CandidateFact) {
			c.WallTimeNS = Epistemic[int64]{Value: 1, Level: EpistemicUnknown}
		},
		"neg size": func(c *CandidateFact) { c.ArtifactSizeBytes = Epistemic[int64]{Value: -1, Level: EpistemicObserved} },
		"outcome mismatch": func(c *CandidateFact) {
			c.Terminal = TerminalEvidenceIncomplete
			// Outcome left as fail.
		},
	} {
		bad := base
		mut(&bad)
		if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

// TestCompareVerifiedCandidatesRefusesClaims (P2c): the verified comparison
// accepts only sealed DerivedVerifiedOutcome values or re-verified proofs —
// never a raw claim.
func TestCompareVerifiedCandidatesRefusesClaims(t *testing.T) {
	// Unsealed (zero) record is a claim, not proof.
	if _, err := VerifiedFromDerived("c1", DerivedVerifiedOutcome{}, 0); err == nil {
		t.Fatal("unsealed record must be refused by VerifiedFromDerived")
	} else if !errors.Is(err, ErrUnverified) {
		t.Fatalf("unsealed error = %v, want ErrUnverified", err)
	}
	if _, err := CompareVerifiedCandidates("", nil, nil); err == nil {
		t.Fatal("empty comparison must be refused")
	}
}

// TestClaimComparisonNeverProjectsPass (P2c): a claimed pass stays a claim
// and never projects to OutcomePass.
func TestClaimComparisonNeverProjectsPass(t *testing.T) {
	row := ClaimFact{
		CandidateID:      "c1",
		CandidateDigest:  mustDigest(t, "c1"),
		ClaimedOutcome:   OutcomePass,
		ClaimedAssurance: "uncontrolled",
		Authority:        RowAuthorityClaim,
	}
	if err := row.Validate(); err != nil {
		t.Fatalf("Validate = %v", err)
	}
	if got := row.AuthoritativeOutcome(); got != OutcomePartial {
		t.Fatalf("AuthoritativeOutcome = %q, want partial (claim is never a plain pass)", got)
	}
	// A claim row stamped as pass-with-verified-authority is structurally
	// impossible: CandidateFact.Validate refuses a claim row projecting pass.
	bad := testForgedVerifiedCandidateFact(t, "c2")
	bad.Authority = RowAuthorityClaim
	if err := bad.Validate(); err == nil {
		t.Fatal("claim row projecting pass must be refused")
	}
	cmp, err := CompareClaims(mustDigest(t, "base"), []ClaimFact{row})
	if err != nil {
		t.Fatalf("CompareClaims = %v", err)
	}
	if cmp.Candidates[0].Authority != RowAuthorityClaim {
		t.Fatalf("authority = %q", cmp.Candidates[0].Authority)
	}
}

// TestCompareCandidatesRefusesForgedVerifiedAuthority: a caller-built
// CandidateFact stamped Authority=verified is refused by the open
// comparison surface. Verified rows require sealed input (FactFromOutcome
// or CompareVerifiedCandidates).
func TestCompareCandidatesRefusesForgedVerifiedAuthority(t *testing.T) {
	forged := testForgedVerifiedCandidateFact(t, "a")
	if forged.Authority != RowAuthorityVerified {
		t.Fatal("forged row setup")
	}
	if _, err := CompareCandidates(mustDigest(t, "snap"), []CandidateFact{forged}); !errors.Is(err, ErrUnverified) {
		t.Fatalf("forged verified row = %v, want ErrUnverified", err)
	}
	// The same row with claim authority is honest and is accepted.
	honest := forged
	honest.Authority = RowAuthorityClaim
	honest.Terminal = TerminalFailed
	honest.Outcome = OutcomeFail
	if _, err := CompareCandidates(mustDigest(t, "snap"), []CandidateFact{honest}); err != nil {
		t.Fatalf("claim row = %v", err)
	}
}

// TestVerifiedRowReportsReportedCPUEpistemic: a verified row minted from a
// sealed outcome shows reported CPU/memory at the observed rung — row
// Authority=verified never promotes caller assertions to verified numbers.
func TestVerifiedRowReportsReportedCPUEpistemic(t *testing.T) {
	iv := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	v := VerificationOutcome{
		VerificationID:   "ver-ep",
		ObligationID:     "ob-ep",
		CandidateDigest:  mustDigest(t, "candidate"),
		SnapshotDigest:   mustDigest(t, "snapshot"),
		ContractDigest:   mustDigest(t, "contract"),
		Outcome:          OutcomePass,
		AssuranceProfile: model.AssuranceUncontrolled.Name(),
		CompletedChecks:  []string{CheckJobStatusSuccess},
		ExecutionIDs:     []string{"exec-1"},
		EvidenceRoot:     mustDigest(t, "evidence"),
		Resources: ResourceFacts{
			WallTimeNS:      3_000_000_000,
			CPUTimeNS:       2_000_000_000,
			PeakMemoryBytes: 4096,
			IOBytes:         8192,
			CacheHits:       7,
			CacheMisses:     3,
			RunnerClass:     "standard",
		},
		StartedAt:   iv,
		CompletedAt: iv.Add(time.Minute),
	}
	ev := VerifiedEvidence{
		ExecutionIDs:       []string{"exec-1"},
		EvidenceRoot:       mustDigest(t, "evidence"),
		AttestationDigests: []Digest{mustDigest(t, "att")},
		JobStatus:          "success",
		CompletedChecks:    []string{CheckJobStatusSuccess},
		Assurance:          model.AssuranceUncontrolled,
		VerifierIdentity:   "test-verifier/v1",
		VerifiedAt:         iv.Add(time.Second),
	}
	sealed, err := sealDerivedOutcome(v, v, ev)
	if err != nil {
		t.Fatalf("sealDerivedOutcome = %v", err)
	}
	complete := EvidenceCompleteness{Required: 1, Present: 1, Verified: 1}
	f, err := FactFromOutcome("c1", sealed, complete, 0)
	if err != nil {
		t.Fatalf("FactFromOutcome = %v", err)
	}
	if f.Authority != RowAuthorityVerified {
		t.Fatalf("row Authority = %q, want verified (minted from sealed input)", f.Authority)
	}
	// Reported figures stay at the observed rung on a verified row.
	for name, e := range map[string]Epistemic[int64]{
		"cpu":    f.CPUTimeNS,
		"mem":    f.PeakMemoryBytes,
		"io":     f.IOBytes,
		"hits":   f.CacheHits,
		"misses": f.CacheMisses,
		"wall":   f.WallTimeNS,
	} {
		if e.Level != EpistemicObserved {
			t.Fatalf("%s level = %s, want observed (reported)", name, e.Level)
		}
		if e.Known(EpistemicAttested) || e.Known(EpistemicDerived) {
			t.Fatalf("%s %+v must not be known at attested/derived", name, e)
		}
	}
	if f.CPUTimeNS.Value != 2_000_000_000 || f.CacheHits.Value != 7 || f.CacheMisses.Value != 3 {
		t.Fatalf("reported values lost: %+v", f.economic())
	}

	// The sealed verified comparison surface carries the same provenance.
	// P2j: every source must share the comparison's base snapshot.
	src, err := VerifiedFromDerived("c1", sealed, 0)
	if err != nil {
		t.Fatalf("VerifiedFromDerived = %v", err)
	}
	cmp, err := CompareVerifiedCandidates(mustDigest(t, "snapshot"), []VerifiedCandidateSource{src}, nil)
	if err != nil {
		t.Fatalf("CompareVerifiedCandidates = %v", err)
	}
	row := cmp.Candidates[0]
	if row.Authority != RowAuthorityVerified {
		t.Fatalf("verified row Authority = %q", row.Authority)
	}
	if row.CPUTimeNS.Level != EpistemicObserved || row.CPUTimeNS.Value != 2_000_000_000 {
		t.Fatalf("verified row CPUTimeNS = %+v, want reported/observed", row.CPUTimeNS)
	}
	if row.PeakMemoryBytes.Level != EpistemicObserved {
		t.Fatalf("verified row PeakMemoryBytes level = %s", row.PeakMemoryBytes.Level)
	}
}

// TestWallFactEpistemicLadder pins the wall-time source ladder: attested
// job window > substrate-derived execution interval > reported figure.
func TestWallFactEpistemicLadder(t *testing.T) {
	attested := wallFact(ResourceFacts{
		WallTimeNS: 1,
		Measured:   &MeasuredResourceFacts{DurationNS: 2, WallTimeNS: 3},
	})
	if attested.Value != 3 || attested.Level != EpistemicAttested {
		t.Fatalf("attested wall = %+v", attested)
	}
	derived := wallFact(ResourceFacts{
		WallTimeNS: 1,
		Measured:   &MeasuredResourceFacts{DurationNS: 2},
	})
	if derived.Value != 2 || derived.Level != EpistemicDerived {
		t.Fatalf("derived wall = %+v", derived)
	}
	reported := wallFact(ResourceFacts{WallTimeNS: 1})
	if reported.Value != 1 || reported.Level != EpistemicObserved {
		t.Fatalf("reported wall = %+v", reported)
	}
	// Zero-valued measured entries do not outrank a reported figure.
	fallback := wallFact(ResourceFacts{
		WallTimeNS: 1,
		Measured:   &MeasuredResourceFacts{},
	})
	if fallback.Value != 1 || fallback.Level != EpistemicObserved {
		t.Fatalf("empty measured wall = %+v", fallback)
	}
}
