package verifyapi

import (
	"errors"
	"testing"
	"time"
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
	v := VerificationOutcome{
		VerificationID:   "ver-1",
		ObligationID:     "ob-1",
		CandidateDigest:  mustDigest(t, "candidate"),
		SnapshotDigest:   mustDigest(t, "snapshot"),
		ContractDigest:   mustDigest(t, "contract"),
		Outcome:          OutcomePass,
		AssuranceProfile: "uncontrolled",
		EvidenceRoot:     mustDigest(t, "evidence"),
		Resources: ResourceFacts{
			WallTimeNS:      3_000_000_000,
			CPUTimeNS:       2_000_000_000,
			PeakMemoryBytes: 1024,
			Measured:        &MeasuredResourceFacts{DurationNS: 9, WallTimeNS: 4_000_000_000},
		},
		StartedAt:   time.Now().Add(-time.Minute),
		CompletedAt: time.Now(),
	}
	complete := EvidenceCompleteness{Required: 1, Present: 1, Verified: 1}
	f := FactFromOutcome("c1", v, complete, 2048)
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
	f2 := FactFromOutcome("c1", v, missing, 0)
	if f2.Terminal != TerminalEvidenceIncomplete || f2.Outcome != OutcomePartial {
		t.Fatalf("missing-evidence fact = %s/%s", f2.Terminal, f2.Outcome)
	}

	// Reported wall time is used when no attested window exists.
	claim := v
	claim.Resources.Measured = &MeasuredResourceFacts{DurationNS: 9}
	f3 := FactFromOutcome("c1", claim, complete, 0)
	if f3.WallTimeNS != 3_000_000_000 {
		t.Fatalf("WallTimeNS = %d, want reported 3s", f3.WallTimeNS)
	}

	failed := v
	failed.Outcome = OutcomeFail
	f4 := FactFromOutcome("c1", failed, complete, 0)
	if f4.Terminal != TerminalFailed || f4.Outcome != OutcomeFail {
		t.Fatalf("failed fact = %s/%s", f4.Terminal, f4.Outcome)
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
