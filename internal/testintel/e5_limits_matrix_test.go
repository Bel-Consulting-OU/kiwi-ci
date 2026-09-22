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
