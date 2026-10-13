package verifyapi

import (
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func testCandidateFact(t *testing.T, id string) CandidateFact {
	t.Helper()
	return CandidateFact{
		CandidateID:       id,
		CandidateDigest:   mustDigest(t, "cand-"+id),
		VerificationID:    "ver-" + id,
		Terminal:          TerminalPassed,
		Outcome:           OutcomePass,
		Assurance:         "uncontrolled",
		Authority:         RowAuthorityVerified,
		WallTimeNS:        5_000_000_000,
		CPUTimeNS:         1_000_000_000,
		PeakMemoryBytes:   64 << 20,
		ArtifactSizeBytes: 1024,
	}
}

func TestCompareCandidatesNeutralAndDeterministic(t *testing.T) {
	a := testCandidateFact(t, "b")
	b := testCandidateFact(t, "a")
	b.Terminal = TerminalFailed
	b.Outcome = OutcomeFail
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
	ok := testCandidateFact(t, "a")
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
			c.ArtifactSizeBytes = -1
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
	// Attested wall time wins over the reported figure.
	if f.WallTimeNS != 4_000_000_000 {
		t.Fatalf("WallTimeNS = %d, want attested 4s", f.WallTimeNS)
	}
	if f.CPUTimeNS != 2_000_000_000 || f.PeakMemoryBytes != 1024 || f.ArtifactSizeBytes != 2048 {
		t.Fatalf("facts = %+v", f)
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

	// Reported wall time is used when no attested window exists.
	claim := v
	claim.Resources.Measured = &MeasuredResourceFacts{DurationNS: 9}
	sealedClaim, err := sealDerivedOutcome(claim, claim, ev)
	if err != nil {
		t.Fatalf("sealDerivedOutcome claim = %v", err)
	}
	f3, err := FactFromOutcome("c1", sealedClaim, complete, 0)
	if err != nil {
		t.Fatalf("FactFromOutcome claim = %v", err)
	}
	if f3.WallTimeNS != 3_000_000_000 {
		t.Fatalf("WallTimeNS = %d, want reported 3s", f3.WallTimeNS)
	}

	failed := v
	failed.Outcome = OutcomeFail
	sealedFailed, err := sealDerivedOutcome(failed, failed, ev)
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
	if _, err := FactFromOutcome("c1", DerivedVerifiedOutcome{Outcome: v, Evidence: ev}, complete, 0); !errors.Is(err, ErrUnverified) {
		t.Fatalf("unsealed FactFromOutcome = %v, want ErrUnverified", err)
	}
}

func TestCandidateFactValidate(t *testing.T) {
	base := testCandidateFact(t, "a")
	for name, mut := range map[string]func(*CandidateFact){
		"no id":        func(c *CandidateFact) { c.CandidateID = "" },
		"bad digest":   func(c *CandidateFact) { c.CandidateDigest = "x" },
		"no ver":       func(c *CandidateFact) { c.VerificationID = "" },
		"bad terminal": func(c *CandidateFact) { c.Terminal = "nope" },
		"no assurance": func(c *CandidateFact) { c.Assurance = "" },
		"neg wall":     func(c *CandidateFact) { c.WallTimeNS = -1 },
		"neg cpu":      func(c *CandidateFact) { c.CPUTimeNS = -1 },
		"neg mem":      func(c *CandidateFact) { c.PeakMemoryBytes = -1 },
		"neg size":     func(c *CandidateFact) { c.ArtifactSizeBytes = -1 },
		"outcome mismatch": func(c *CandidateFact) {
			c.Terminal = TerminalFailed
			// Outcome left as pass.
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
	bad := testCandidateFact(t, "c2")
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
