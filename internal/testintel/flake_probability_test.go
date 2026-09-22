package testintel

// Coverage for the exported window-flakiness predicate: callers that fold
// their own bounded outcome windows (the report-derived summary) must get
// exactly the same classification History.Record applies, including the
// single-outcome and empty-window "never flaky" rules.

import (
	"math"
	"testing"
	"time"
)

// TestFlakeProbabilityWindowSemantics pins the predicate: fewer than two
// outcomes is never flaky, a single outcome class is never flaky however
// long, and a mixed window reports the minority share.
func TestFlakeProbabilityWindowSemantics(t *testing.T) {
	cases := []struct {
		name     string
		outcomes []bool
		want     float64
	}{
		{"empty", nil, 0},
		{"single pass", []bool{true}, 0},
		{"single fail", []bool{false}, 0},
		{"all pass", []bool{true, true, true, true}, 0},
		{"all fail", []bool{false, false, false}, 0},
		{"one fail in four", []bool{true, true, false, true}, 0.25},
		{"one pass in four", []bool{false, false, true, false}, 0.25},
		{"half and half", []bool{true, false}, 0.5},
		{"alternating", []bool{true, false, true, false, true, false}, 0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FlakeProbability(tc.outcomes); math.Abs(got-tc.want) > 1e-12 {
				t.Fatalf("FlakeProbability(%v) = %v, want %v", tc.outcomes, got, tc.want)
			}
		})
	}
}

// TestFlakeProbabilityMatchesRecordedHistory proves the exported predicate
// and History.Record agree on the SAME 16-outcome window, so an offloaded
// summary and the in-memory history can never disagree about flakiness.
func TestFlakeProbabilityMatchesRecordedHistory(t *testing.T) {
	outcomes := []bool{false, true, true, false, false, true, false, true, true, true, false, true, false, false, true, true}
	h := NewHistory()
	at := time.Now().UTC()
	for i, ok := range outcomes {
		h.Record("github.com/acme/repo", "build", "", "t", 1, ok, at.Add(time.Duration(i)*time.Second))
	}
	st, ok := h.stats[testKey("github.com/acme/repo", "build", "", "t")]
	if !ok {
		t.Fatalf("recorded stat missing from %v", h.stats)
	}
	if want := FlakeProbability(outcomes); st.FlakeProb != want {
		t.Fatalf("recorded FlakeProb = %v, exported predicate = %v", st.FlakeProb, want)
	}
	if st.FlakeProb <= 0 {
		t.Fatal("a mixed window must be flaky")
	}
	// The window keeps only the LAST 16 outcomes: an old failure that falls
	// out of the window stops counting even though the lifetime counters keep
	// it.
	allPass := append([]bool{false}, make([]bool, 16)...)
	for i := range allPass {
		if i > 0 {
			allPass[i] = true
		}
	}
	if got := FlakeProbability(allPass[1:]); got != 0 {
		t.Fatalf("single-outcome window reported flaky: %v", got)
	}
	// The predicate in isolation still reports the mixed window.
	if got := FlakeProbability(allPass[:16]); got <= 0 {
		t.Fatalf("mixed window inside the cap = %v, want > 0", got)
	}
}
