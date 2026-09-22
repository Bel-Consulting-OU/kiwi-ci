package testintel

import (
	"errors"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestE5CounterMatrixRejectsContradictions pins the E5-B numeric policy on the
// authoritative validator: every contradictory counter set is refused with
// ErrLimitExceeded, including the case the old per-counter checks let through
// (tests=10, failures=8, skipped=8: failures+errors <= tests and skipped <=
// tests individually, but the three outcomes sum to 16 > 10).
func TestE5CounterMatrixRejectsContradictions(t *testing.T) {
	cases := []struct {
		name string
		rep  model.TestReport
		want string
	}{
		{
			"failure and skip counters individually inside tests but summing over it",
			model.TestReport{Tests: 10, Failures: 8, Skipped: 8},
			"failures+errors+skipped (8+0+8) exceeds tests (10)",
		},
		{
			"all three outcome counters summing over tests",
			model.TestReport{Tests: 2, Failures: 1, Errors: 1, Skipped: 1},
			"failures+errors+skipped (1+1+1) exceeds tests (2)",
		},
		{
			"64-bit tests counter over the SQL int range",
			model.TestReport{Tests: 3_000_000_000},
			"tests=3000000000",
		},
		{
			"64-bit failures counter over the job budget",
			model.TestReport{Tests: 1, Failures: 3_000_000_000},
			"failures=3000000000",
		},
		{
			"errors counter over the job budget",
			model.TestReport{Tests: 1, Errors: MaxJobCases + 1},
			"errors=100001",
		},
		{
			"skipped counter over the job budget",
			model.TestReport{Tests: 1, Skipped: MaxJobCases + 1},
			"skipped=100001",
		},
		{
			"fewer declared tests than materialized cases",
			model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "a", Passed: true}, {Name: "b", Passed: true}}},
			"materialized cases exceed the declared tests counter",
		},
		{
			"failing case with no failures or errors declared",
			model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "a", Passed: false}}},
			"materialized failing cases exceed failures+errors",
		},
		{
			"skipped case with no skipped counter",
			model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "a", Skipped: true}}},
			"materialized skipped cases exceed the skipped counter",
		},
		{
			"case both passed and skipped",
			model.TestReport{Tests: 1, Skipped: 1, Cases: []model.TestResult{{Name: "a", Passed: true, Skipped: true}}},
			"both passed and skipped",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReportPayload(tc.rep)
			if !errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("err = %v, want ErrLimitExceeded", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want reason containing %q", err, tc.want)
			}
		})
	}
}

// TestE5CounterMatrixBoundariesAccepted pins the boundary-valid side of the
// same policy, at the exact limits: counters exactly at MaxJobCases, the three
// outcome counters summing to exactly Tests, and case-derived lower bounds
// satisfied by exactly the materialized cases.
func TestE5CounterMatrixBoundariesAccepted(t *testing.T) {
	valid := []struct {
		name string
		rep  model.TestReport
	}{
		{
			"counters at the job budget",
			model.TestReport{Tests: MaxJobCases, Failures: MaxJobCases},
		},
		{
			"outcome counters summing to exactly tests",
			model.TestReport{
				Tests: 2, Failures: 1, Errors: 1,
				Cases: []model.TestResult{{Name: "fail", Passed: false}, {Name: "err", Passed: false}},
			},
		},
		{
			"skipped counter exactly explained by skipped cases",
			model.TestReport{
				Tests: 2, Skipped: 2,
				Cases: []model.TestResult{{Name: "a", Skipped: true}, {Name: "b", Skipped: true}},
			},
		},
		{
			"declared tests above the materialized cases",
			model.TestReport{Tests: 1000, Cases: []model.TestResult{{Name: "a", Passed: true}}},
		},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateReportPayload(tc.rep); err != nil {
				t.Fatalf("boundary-valid report rejected: %v", err)
			}
		})
	}
}

// TestE5ParserAndValidatorAgreeOnDerivedCounters proves the parser's own
// derivation satisfies the validator's case-derived lower bounds without
// special-casing: a suite that declares no failures/errors/skipped at all but
// carries a failure, an error and a skipped case is derived up to exactly the
// case counts, and the aggregate validator accepts the result.
func TestE5ParserAndValidatorAgreeOnDerivedCounters(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "derived.xml", `<testsuite name="s" tests="1" failures="0" errors="0" skipped="0">
		<testcase name="pass"/>
		<testcase name="fail"><failure message="boom">trace</failure></testcase>
		<testcase name="err"><error message="err">trace</error></testcase>
		<testcase name="skip"><skipped message="not today"/></testcase>
	</testsuite>`)
	agg, err := Aggregate(ws, []string{"derived.xml"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if agg.Tests != 4 || agg.Failures != 1 || agg.Errors != 1 || agg.Skipped != 1 {
		t.Fatalf("derived counters = tests %d failures %d errors %d skipped %d, want 4/1/1/1",
			agg.Tests, agg.Failures, agg.Errors, agg.Skipped)
	}
	if err := ValidateReportPayload(agg); err != nil {
		t.Fatalf("parser output rejected by the shared validator: %v", err)
	}
}

// foldObservedCases folds a report's cases exactly the way the persisted test
// history does (internal/server's foldReportCases): a skipped case is not a
// pass/fail observation, every other case is recorded with its Passed flag.
// The reconciliation tests use it to prove the reconciled counters agree with
// the case classification the fold observes.
func foldObservedCases(rep model.TestReport) *History {
	h := NewHistory()
	for _, c := range rep.Cases {
		if c.Skipped {
			continue
		}
		h.Record(rep.JobKey, rep.JobKey, c.Class, c.Name, c.Duration, c.Passed, rep.CreatedAt)
	}
	return h
}

// TestE5CounterReconciliationSkipWinsWithDeclaredFailure pins the K7-A
// doubles case: the producer declares tests=1 failures=1 while its single
// <testcase> carries BOTH a failure and a skipped element. Skip wins in the
// model, so the case is folded as a skip and the declared failure claim must
// be reconciled away: the parser's output has failures+errors+skipped <=
// tests, the shared validator accepts it, and the folded history observes the
// reclassified skip (no pass/fail observation at all).
func TestE5CounterReconciliationSkipWinsWithDeclaredFailure(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "both-declared.xml", `<testsuite name="s" tests="1" failures="1">
		<testcase name="t" classname="pkg.T"><failure message="boom"/><skipped message="quarantined"/></testcase>
	</testsuite>`)
	agg, err := Aggregate(ws, []string{"both-declared.xml"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if err := ValidateReportPayload(agg); err != nil {
		t.Fatalf("parser output rejected by the shared validator: %v", err)
	}
	if agg.Tests != 1 || agg.Failures != 0 || agg.Errors != 0 || agg.Skipped != 1 {
		t.Fatalf("reconciled counters = tests %d failures %d errors %d skipped %d, want 1/0/0/1", agg.Tests, agg.Failures, agg.Errors, agg.Skipped)
	}
	if len(agg.Cases) != 1 || !agg.Cases[0].Skipped || agg.Cases[0].Passed {
		t.Fatalf("materialized case is not a skip: %+v", agg.Cases)
	}
	if h := foldObservedCases(agg); len(h.stats) != 0 {
		t.Fatalf("folded history = %+v, want no pass/fail observation for a skipped case", h.stats)
	}
}

// TestE5CounterReconciliationDoubleCountedFailure pins the second K7-A
// disagreement: a producer counts ONE failing case in BOTH failures and
// errors (tests=1, failures=1, errors=1). The model collapses <failure> and
// <error> into one non-passing observation, so the parser keeps the case's
// own classification (the failure) and concedes the unsupported errors claim
// rather than emitting a sum over tests the validator would reject.
func TestE5CounterReconciliationDoubleCountedFailure(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "double.xml", `<testsuite name="s" tests="1" failures="1" errors="1">
		<testcase name="t" classname="pkg.T"><failure message="boom"/></testcase>
	</testsuite>`)
	agg, err := Aggregate(ws, []string{"double.xml"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if err := ValidateReportPayload(agg); err != nil {
		t.Fatalf("parser output rejected by the shared validator: %v", err)
	}
	if agg.Tests != 1 || agg.Failures != 1 || agg.Errors != 0 || agg.Skipped != 0 {
		t.Fatalf("reconciled counters = tests %d failures %d errors %d skipped %d, want 1/1/0/0", agg.Tests, agg.Failures, agg.Errors, agg.Skipped)
	}
	if len(agg.Cases) != 1 || agg.Cases[0].Passed || agg.Cases[0].Skipped {
		t.Fatalf("materialized case classification wrong: %+v", agg.Cases)
	}
	h := foldObservedCases(agg)
	if len(h.stats) != 1 {
		t.Fatalf("folded history = %+v, want exactly one failing observation", h.stats)
	}
	for key, st := range h.stats {
		if st.Runs != 1 || st.Fails != 1 || st.Passes != 0 {
			t.Fatalf("folded %s = %+v, want one failing outcome", key, st)
		}
	}
}

// TestE5CounterReconciliationKeepsConsistentCounters pins the normal path:
// a producer whose declared counters already agree with its cases is
// untouched by the reconciliation, still validates, and folds to exactly the
// case observations (two failures and one pass; the skipped case contributes
// nothing).
func TestE5CounterReconciliationKeepsConsistentCounters(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "normal.xml", `<testsuite name="normal" tests="4" failures="1" errors="1" skipped="1" time="1.5">
		<testcase name="ok" classname="pkg.T"/>
		<testcase name="bad" classname="pkg.T"><failure message="boom"/></testcase>
		<testcase name="err" classname="pkg.T"><error message="oops"/></testcase>
		<testcase name="skip" classname="pkg.T"><skipped/></testcase>
	</testsuite>`)
	agg, err := Aggregate(ws, []string{"normal.xml"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if err := ValidateReportPayload(agg); err != nil {
		t.Fatalf("parser output rejected by the shared validator: %v", err)
	}
	if agg.Tests != 4 || agg.Failures != 1 || agg.Errors != 1 || agg.Skipped != 1 || agg.Duration != 1.5 {
		t.Fatalf("consistent counters changed: tests %d failures %d errors %d skipped %d duration %v", agg.Tests, agg.Failures, agg.Errors, agg.Skipped, agg.Duration)
	}
	h := foldObservedCases(agg)
	if len(h.stats) != 3 {
		t.Fatalf("folded history = %+v, want three pass/fail observations", h.stats)
	}
	var runs, passes, fails int
	for _, st := range h.stats {
		runs += st.Runs
		passes += st.Passes
		fails += st.Fails
	}
	if runs != 3 || passes != 1 || fails != 2 {
		t.Fatalf("folded totals = runs %d passes %d fails %d, want 3/1/2", runs, passes, fails)
	}
}

// TestE5FinalizeSuiteReconciliationIsIdempotent pins the fixed point:
// appendSuite finalizes a suite a second time (once when the element closes,
// once when it merges into the report), so running the reconciliation again
// must not shrink an already-reconciled counter. It also checks the
// validator's counter relation and case-derived bounds directly on each
// reconciled suite.
func TestE5FinalizeSuiteReconciliationIsIdempotent(t *testing.T) {
	suites := []Suite{
		{Name: "doubles", Tests: 1, Failures: 1, Cases: []Case{{Name: "t", Failure: &Failure{}, Skipped: &Skipped{}}}},
		{Name: "double-count", Tests: 1, Failures: 1, Errors: 1, Cases: []Case{{Name: "t", Failure: &Failure{}}}},
		{Name: "both-elements", Tests: 1, Failures: 1, Errors: 1, Cases: []Case{{Name: "t", Failure: &Failure{}, Error: &Failure{}}}},
		{Name: "over-declared", Failures: 5, Skipped: 4, Cases: []Case{{Name: "t", Failure: &Failure{}}}},
	}
	for _, in := range suites {
		s := in
		finalizeSuite(&s)
		once := [4]int{s.Tests, s.Failures, s.Errors, s.Skipped}
		finalizeSuite(&s)
		if twice := [4]int{s.Tests, s.Failures, s.Errors, s.Skipped}; twice != once {
			t.Fatalf("%s: finalize not idempotent: %v then %v", in.Name, once, twice)
		}
		var failing, skipped int
		for _, c := range s.Cases {
			switch {
			case c.Skipped != nil:
				skipped++
			case c.Failure != nil || c.Error != nil:
				failing++
			}
		}
		if s.Tests < len(s.Cases) || s.Failures+s.Errors+s.Skipped > s.Tests {
			t.Fatalf("%s: reconciled relation violated: tests %d failures %d errors %d skipped %d", in.Name, s.Tests, s.Failures, s.Errors, s.Skipped)
		}
		if s.Failures+s.Errors < failing || s.Skipped < skipped {
			t.Fatalf("%s: reconciled floors violated: failures %d errors %d skipped %d for failing %d skipped %d", in.Name, s.Failures, s.Errors, s.Skipped, failing, skipped)
		}
	}
}

// TestE5ParserValidatorAgreeOnSkippedWithFailure pins the pathological
// producer case: a <testcase> carrying BOTH a failure and a skipped element is
// modeled as SKIPPED (that is what the historical fold sees), so the parser's
// declared counters must classify it as a skip too — otherwise the parser's
// own output would violate the validator's case-derived skipped bound.
func TestE5ParserValidatorAgreeOnSkippedWithFailure(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "both.xml", `<testsuite name="s" tests="1">
		<testcase name="t"><failure message="boom"/><skipped message="quarantined"/></testcase>
	</testsuite>`)
	agg, err := Aggregate(ws, []string{"both.xml"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if agg.Skipped != 1 || agg.Failures != 0 || agg.Errors != 0 || agg.Tests != 1 {
		t.Fatalf("counters = tests %d failures %d errors %d skipped %d, want 1/0/0/1", agg.Tests, agg.Failures, agg.Errors, agg.Skipped)
	}
	if len(agg.Cases) != 1 || !agg.Cases[0].Skipped {
		t.Fatalf("materialized case is not a skip: %+v", agg.Cases)
	}
	if err := ValidateReportPayload(agg); err != nil {
		t.Fatalf("parser output rejected by the shared validator: %v", err)
	}
}
