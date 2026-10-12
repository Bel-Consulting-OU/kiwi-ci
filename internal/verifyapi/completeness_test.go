package verifyapi

import "testing"

func TestTerminalStateVocabularyAndProjection(t *testing.T) {
	// The closed rich vocabulary, with its pinned coarse projection.
	cases := map[TerminalState]Outcome{
		TerminalPassed:             OutcomePass,
		TerminalFailed:             OutcomeFail,
		TerminalExecutionError:     OutcomePartial,
		TerminalPolicyDenied:       OutcomeFail,
		TerminalEvidenceIncomplete: OutcomePartial,
		TerminalEvidenceInvalid:    OutcomeFail,
		TerminalExpired:            OutcomeFail,
		TerminalCancelled:          OutcomePartial,
		TerminalSuperseded:         OutcomePartial,
		TerminalUnsupported:        OutcomeFail,
	}
	if len(cases) != 10 {
		t.Fatalf("expected 10 terminal states, got %d", len(cases))
	}
	for state, coarse := range cases {
		if !state.Valid() {
			t.Fatalf("%q is not valid", state)
		}
		if got := state.ProjectCoarse(); got != coarse {
			t.Fatalf("%q projects to %q, want %q", state, got, coarse)
		}
	}
	if TerminalState("nope").Valid() {
		t.Fatal("unknown state must not be valid")
	}
	// Only TerminalPassed projects to OutcomePass: the single discharge
	// state of the coarse vocabulary.
	for state := range cases {
		if state != TerminalPassed && state.ProjectCoarse() == OutcomePass {
			t.Fatalf("%q must never project to pass", state)
		}
	}
}

func TestComputeEvidenceCompleteness(t *testing.T) {
	// required {a,b,c}, cited {a,b,x}, verified {a,x}: x is outside the
	// required set and is ignored. a verifies; b is cited but unverified.
	c := ComputeEvidenceCompleteness(
		[]string{"a", "b", "c"},
		[]string{"a", "b", "x"},
		[]string{"a", "x", "a"},
	)
	if c.Required != 3 || c.Present != 2 {
		t.Fatalf("counts = %+v, want required 3 present 2", c)
	}
	if c.Missing != 1 {
		t.Fatalf("Missing = %d, want 1 (c)", c.Missing)
	}
	if c.Verified != 1 || c.Invalid != 1 {
		t.Fatalf("Verified/Invalid = %d/%d, want 1/1", c.Verified, c.Invalid)
	}
	if c.Complete() {
		t.Fatal("incomplete set must not be Complete")
	}

	full := ComputeEvidenceCompleteness([]string{"a"}, []string{"a"}, []string{"a"})
	if !full.Complete() {
		t.Fatalf("full set must be Complete: %+v", full)
	}
	empty := ComputeEvidenceCompleteness(nil, nil, nil)
	if empty.Complete() {
		t.Fatal("empty requirement is never complete")
	}
	// Extra cited-but-unrequired items do not break completeness.
	withExtra := ComputeEvidenceCompleteness([]string{"a"}, []string{"a", "extra"}, []string{"a"})
	if !withExtra.Complete() {
		t.Fatalf("required-complete set must be Complete: %+v", withExtra)
	}
}

func TestStatusFromCompleteness(t *testing.T) {
	complete := EvidenceCompleteness{Required: 1, Present: 1, Verified: 1}
	missing := EvidenceCompleteness{Required: 2, Present: 1, Verified: 1, Missing: 1}
	invalid := EvidenceCompleteness{Required: 1, Present: 1, Invalid: 1}

	cases := []struct {
		name     string
		c        EvidenceCompleteness
		derived  Outcome
		terminal TerminalState
		reason   UnverifiedReason
		coarse   Outcome
		pass     bool
	}{
		{"proven pass", complete, OutcomePass, TerminalPassed, "", OutcomePass, true},
		{"missing evidence beats claimed pass", missing, OutcomePass, TerminalEvidenceIncomplete, ReasonMissingRequiredEvidence, OutcomePartial, false},
		{"invalid evidence", invalid, OutcomePass, TerminalEvidenceInvalid, ReasonInvalidEvidence, OutcomeFail, false},
		{"job failed", complete, OutcomeFail, TerminalFailed, ReasonJobFailed, OutcomeFail, false},
		{"partial coverage", complete, OutcomePartial, TerminalEvidenceIncomplete, ReasonChecksNotCovered, OutcomePartial, false},
		{"claimed pass without accounting", EvidenceCompleteness{}, OutcomePass, TerminalEvidenceIncomplete, ReasonMissingRequiredEvidence, OutcomePartial, false},
	}
	for _, tc := range cases {
		got := StatusFromCompleteness(tc.c, tc.derived)
		if got.Terminal != tc.terminal || got.Reason != tc.reason || got.Coarse != tc.coarse || got.ProvenPass() != tc.pass {
			t.Fatalf("%s: got %+v, want terminal=%s reason=%s coarse=%s pass=%v",
				tc.name, got, tc.terminal, tc.reason, tc.coarse, tc.pass)
		}
		if tc.reason == "" && got.String() != string(tc.terminal) {
			t.Fatalf("%s String() = %q", tc.name, got)
		}
		if tc.reason != "" && got.String() != string(tc.terminal)+": "+string(tc.reason) {
			t.Fatalf("%s String() = %q", tc.name, got)
		}
		// The reason is exactly the spec example when evidence is missing.
		if tc.terminal == TerminalEvidenceIncomplete && tc.reason != ReasonMissingRequiredEvidence && tc.reason != ReasonChecksNotCovered {
			t.Fatalf("%s: unexpected reason %q", tc.name, tc.reason)
		}
	}
}

func TestUnverifiedReasonVocabulary(t *testing.T) {
	// Pin the example named in the contract.
	if ReasonMissingRequiredEvidence != UnverifiedReason("missing_required_evidence") {
		t.Fatalf("ReasonMissingRequiredEvidence = %q", ReasonMissingRequiredEvidence)
	}
	all := []UnverifiedReason{
		ReasonMissingRequiredEvidence, ReasonInvalidEvidence, ReasonChecksNotCovered,
		ReasonInsufficientAssurance, ReasonJobFailed, ReasonExecutionError,
		ReasonPolicyDenied, ReasonExpired, ReasonCancelled, ReasonSuperseded,
		ReasonUnsupported,
	}
	seen := map[UnverifiedReason]bool{}
	for _, r := range all {
		if r == "" || seen[r] {
			t.Fatalf("bad reason vocabulary entry %q", r)
		}
		seen[r] = true
	}
}
