package testintel

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// budgetAbsurd is a producer-declared counter far above MaxJobCases — the
// "tests=1e7" shape from the counter-reconciliation residual. The clamp
// policy treats it as producer garbage exactly like a negative counter or an
// oversized failure message: the parser clamps it into the shared budget
// instead of emitting a report ValidateReportPayload would reject, which made
// the runner warn-only discard the WHOLE aggregated report set.
const budgetAbsurd = 10_000_000

// TestBudgetClampProducerCountersAboveJobBudget proves the counter half of
// the sanitize-not-reject policy end to end: a producer declaring tests,
// failures, errors and skipped far above MaxJobCases still parses, the
// aggregate passes the shared validator, every counter is clamped into the
// job budget, the case-derived floors survive the clamp, and the folded
// history observes exactly the materialized cases.
func TestBudgetClampProducerCountersAboveJobBudget(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "absurd.xml", `<testsuite name="absurd" tests="10000000" failures="10000000" errors="10000000" skipped="10000000">
  <testcase name="pass" classname="pkg.T"/>
  <testcase name="fail" classname="pkg.T"><failure message="boom"/></testcase>
  <testcase name="skip" classname="pkg.T"><skipped message="quarantined"/></testcase>
</testsuite>`)
	agg, err := Aggregate(ws, []string{"absurd.xml"})
	if err != nil {
		t.Fatalf("over-declared counters must be clamped, not rejected: %v", err)
	}
	if err := ValidateReportPayload(agg); err != nil {
		t.Fatalf("clamped aggregate rejected by the shared validator: %v", err)
	}
	for _, c := range []struct {
		name  string
		value int
	}{
		{"tests", agg.Tests}, {"failures", agg.Failures}, {"errors", agg.Errors}, {"skipped", agg.Skipped},
	} {
		if c.value < 0 || c.value > MaxJobCases {
			t.Fatalf("%s = %d, outside the job budget [0, %d]", c.name, c.value, MaxJobCases)
		}
	}
	if agg.Tests != MaxJobCases {
		t.Fatalf("declared tests clamped to %d, want the budget ceiling %d", agg.Tests, MaxJobCases)
	}
	// The floors are materialized evidence: the one failing case still keeps
	// a failure, the skipped case still keeps a skip, and the relation holds.
	if agg.Failures+agg.Errors < 1 || agg.Skipped < 1 {
		t.Fatalf("case-derived floors lost in the clamp: failures+errors=%d skipped=%d", agg.Failures+agg.Errors, agg.Skipped)
	}
	if agg.Failures+agg.Errors+agg.Skipped > agg.Tests {
		t.Fatalf("clamped counters contradict tests: tests %d failures %d errors %d skipped %d", agg.Tests, agg.Failures, agg.Errors, agg.Skipped)
	}
	h := foldObservedCases(agg)
	var runs, passes, fails int
	for _, st := range h.stats {
		runs += st.Runs
		passes += st.Passes
		fails += st.Fails
	}
	if runs != 2 || passes != 1 || fails != 1 {
		t.Fatalf("folded history = runs %d passes %d fails %d, want 2/1/1 for the pass+fail cases (the skip is no observation)", runs, passes, fails)
	}

	// A job sums many files, so the clamp must also hold at the job-level
	// aggregation point: two files whose suites each declare tests=1e7.
	writeFixture(t, ws, "absurd-a.xml", `<testsuite name="a" tests="10000000"><testcase name="a"/></testsuite>`)
	writeFixture(t, ws, "absurd-b.xml", `<testsuite name="b" tests="10000000"><testcase name="b"/></testsuite>`)
	multi, err := Aggregate(ws, []string{"absurd-a.xml", "absurd-b.xml"})
	if err != nil {
		t.Fatalf("job-level sum of absurd counters must be clamped, not rejected: %v", err)
	}
	if multi.Tests != MaxJobCases {
		t.Fatalf("job-level clamped tests = %d, want %d", multi.Tests, MaxJobCases)
	}
	if err := ValidateReportPayload(multi); err != nil {
		t.Fatalf("job-level clamped aggregate rejected: %v", err)
	}

	// The single-file Parse path is an aggregation point of its own: one file
	// merging two absurd suites must not return an over-budget report total.
	rep, err := Parse(writeFixture(t, ws, "two-suites.xml", `<testsuites>
  <testsuite name="c" tests="10000000"><testcase name="c"/></testsuite>
  <testsuite name="d" tests="10000000"><testcase name="d"/></testsuite>
</testsuites>`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rep.Tests != MaxJobCases {
		t.Fatalf("file-level clamped tests = %d, want %d", rep.Tests, MaxJobCases)
	}
	for _, s := range rep.Suites {
		if s.Tests != MaxJobCases {
			t.Fatalf("suite %q tests = %d, want the per-suite clamp %d", s.Name, s.Tests, MaxJobCases)
		}
	}
}

// TestBudgetClampSummedDurationsAtSharedMaximum proves the duration half:
// each suite/case time is individually valid (exactly maxReportDuration), but
// their SUM is over it. The parser clamps the aggregated total to the shared
// maximum instead of letting the aggregate fail ValidateReportPayload, and
// the individually valid case durations are retained unchanged.
func TestBudgetClampSummedDurationsAtSharedMaximum(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "a.xml", `<testsuite name="a" time="1000000000"><testcase name="a" classname="pkg.T" time="1000000000"/></testsuite>`)
	writeFixture(t, ws, "b.xml", `<testsuite name="b" time="1000000000"><testcase name="b" classname="pkg.T" time="1000000000"/></testsuite>`)
	agg, err := Aggregate(ws, []string{"*.xml"})
	if err != nil {
		t.Fatalf("a summed duration over the shared maximum must be clamped, not rejected: %v", err)
	}
	if err := ValidateReportPayload(agg); err != nil {
		t.Fatalf("clamped duration aggregate rejected by the shared validator: %v", err)
	}
	if agg.Duration != maxReportDuration {
		t.Fatalf("aggregate duration = %v, want the clamped %v", agg.Duration, float64(maxReportDuration))
	}
	for _, c := range agg.Cases {
		if c.Duration != maxReportDuration {
			t.Fatalf("case %q duration = %v, want the individually valid %v retained", c.Name, c.Duration, float64(maxReportDuration))
		}
	}

	// The file-level aggregation point clamps too: two max-time suites in one
	// file.
	rep, err := Parse(writeFixture(t, ws, "one-file.xml", `<testsuites>
  <testsuite name="c" time="1000000000"><testcase name="c" classname="pkg.T"/></testsuite>
  <testsuite name="d" time="1000000000"><testcase name="d" classname="pkg.T"/></testsuite>
</testsuites>`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rep.Duration != maxReportDuration {
		t.Fatalf("file-level duration = %v, want the clamped %v", rep.Duration, float64(maxReportDuration))
	}
}

// TestBudgetClampKeepsCaseDerivedFloors pins the ordering contract: the
// clamp runs AFTER the floors, so a declared counter far above the budget can
// never cut a floor below the materialized evidence. A failure-only and an
// error-only case each keep their exclusive classification counter, the pair
// floor and the skipped floor survive, and the fold observes exactly the two
// failing cases.
func TestBudgetClampKeepsCaseDerivedFloors(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "floors.xml", `<testsuite name="floors" tests="10000000" failures="10000000" errors="10000000" skipped="10000000">
  <testcase name="f" classname="pkg.T"><failure message="f"/></testcase>
  <testcase name="e" classname="pkg.T"><error message="e"/></testcase>
  <testcase name="s" classname="pkg.T"><skipped/></testcase>
</testsuite>`)
	agg, err := Aggregate(ws, []string{"floors.xml"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if err := ValidateReportPayload(agg); err != nil {
		t.Fatalf("clamped aggregate rejected by the shared validator: %v", err)
	}
	var failing, skipped int
	for _, c := range agg.Cases {
		switch {
		case c.Skipped:
			skipped++
		case !c.Passed:
			failing++
		}
	}
	if agg.Tests < len(agg.Cases) || agg.Tests > MaxJobCases {
		t.Fatalf("tests = %d, want [%d, %d]", agg.Tests, len(agg.Cases), MaxJobCases)
	}
	if agg.Failures+agg.Errors < failing {
		t.Fatalf("pair floor lost: failures+errors = %d, want >= %d failing cases", agg.Failures+agg.Errors, failing)
	}
	if agg.Skipped < skipped {
		t.Fatalf("skipped floor lost: skipped = %d, want >= %d skipped cases", agg.Skipped, skipped)
	}
	if agg.Failures+agg.Errors+agg.Skipped > agg.Tests {
		t.Fatalf("clamped counters contradict tests: tests %d failures %d errors %d skipped %d", agg.Tests, agg.Failures, agg.Errors, agg.Skipped)
	}
	// The exclusive classification floors are what the clamp must never eat:
	// the failure-only case keeps a Failure and the error-only case keeps an
	// Error even though the unsupported excess was conceded.
	if agg.Failures < 1 || agg.Errors < 1 {
		t.Fatalf("classification floors lost: failures = %d, errors = %d", agg.Failures, agg.Errors)
	}
	h := foldObservedCases(agg)
	var runs, passes, fails int
	for _, st := range h.stats {
		runs += st.Runs
		passes += st.Passes
		fails += st.Fails
	}
	if runs != 2 || passes != 0 || fails != 2 {
		t.Fatalf("folded history = runs %d passes %d fails %d, want 2/0/2 for the two failing cases", runs, passes, fails)
	}
}

// TestBudgetClampFinalizeSuiteIsIdempotent pins the fixed point under the
// budget clamp: appendSuite finalizes every suite a second time, so an
// absurd declared counter must reach the same clamped values on the second
// pass. The expected values pin both the clamp ceiling and the floors the
// reconciliation keeps.
func TestBudgetClampFinalizeSuiteIsIdempotent(t *testing.T) {
	suites := []struct {
		in   Suite
		want [4]int
	}{
		{Suite{Name: "tests", Tests: budgetAbsurd, Cases: []Case{{Name: "t"}}},
			[4]int{MaxJobCases, 0, 0, 0}},
		{Suite{Name: "failures", Tests: budgetAbsurd, Failures: budgetAbsurd, Cases: []Case{{Name: "t", Failure: &Failure{}}}},
			[4]int{MaxJobCases, MaxJobCases, 0, 0}},
		{Suite{Name: "errors", Tests: budgetAbsurd, Errors: budgetAbsurd, Cases: []Case{{Name: "t", Error: &Failure{}}}},
			[4]int{MaxJobCases, 0, MaxJobCases, 0}},
		{Suite{Name: "skipped", Tests: budgetAbsurd, Skipped: budgetAbsurd, Cases: []Case{{Name: "t", Skipped: &Skipped{}}}},
			[4]int{MaxJobCases, 0, 0, MaxJobCases}},
		{Suite{Name: "all", Tests: budgetAbsurd, Failures: budgetAbsurd, Errors: budgetAbsurd, Skipped: budgetAbsurd,
			Cases: []Case{{Name: "f", Failure: &Failure{}}, {Name: "s", Skipped: &Skipped{}}}},
			[4]int{MaxJobCases, 1, 0, MaxJobCases - 1}},
	}
	for _, tc := range suites {
		s := tc.in
		finalizeSuite(&s)
		once := [4]int{s.Tests, s.Failures, s.Errors, s.Skipped}
		finalizeSuite(&s)
		if twice := [4]int{s.Tests, s.Failures, s.Errors, s.Skipped}; twice != once {
			t.Fatalf("%s: finalize not idempotent: %v then %v", tc.in.Name, once, twice)
		}
		if once != tc.want {
			t.Fatalf("%s: clamped counters = %v, want %v", tc.in.Name, once, tc.want)
		}
	}
}

// TestBudgetClampMaxIntCountersDoNotOverflow pins the same sanitize-not-
// reject policy at the extreme Atoi can produce (math.MaxInt in every
// counter): the pair-floor arithmetic must not overflow an int and leave a
// negative counter that makes the aggregate reject its own parse.
func TestBudgetClampMaxIntCountersDoNotOverflow(t *testing.T) {
	maxInt := strconv.Itoa(math.MaxInt)
	ws := t.TempDir()
	writeFixture(t, ws, "maxint.xml", `<testsuite name="maxint" tests="`+maxInt+`" failures="`+maxInt+`" errors="`+maxInt+`" skipped="`+maxInt+`">
  <testcase name="f" classname="pkg.T"><failure message="boom"/></testcase>
</testsuite>`)
	agg, err := Aggregate(ws, []string{"maxint.xml"})
	if err != nil {
		t.Fatalf("MaxInt counters must be clamped, not overflow into a rejection: %v", err)
	}
	if err := ValidateReportPayload(agg); err != nil {
		t.Fatalf("MaxInt-clamped aggregate rejected by the shared validator: %v", err)
	}
	for _, c := range []struct {
		name  string
		value int
	}{
		{"tests", agg.Tests}, {"failures", agg.Failures}, {"errors", agg.Errors}, {"skipped", agg.Skipped},
	} {
		if c.value < 0 || c.value > MaxJobCases {
			t.Fatalf("%s = %d, outside the job budget [0, %d]", c.name, c.value, MaxJobCases)
		}
	}
	if agg.Failures+agg.Errors < 1 {
		t.Fatalf("failing case floor lost: failures+errors = %d", agg.Failures+agg.Errors)
	}
	// The per-suite reconciliation is idempotent even for the extreme
	// values: the second finalize (appendSuite) must not change the result,
	// and it must never leave an out-of-budget counter behind.
	s := Suite{
		Name: "maxint", Tests: math.MaxInt, Failures: math.MaxInt, Errors: math.MaxInt, Skipped: math.MaxInt,
		Cases: []Case{{Name: "f", Failure: &Failure{}}},
	}
	finalizeSuite(&s)
	once := [4]int{s.Tests, s.Failures, s.Errors, s.Skipped}
	finalizeSuite(&s)
	if twice := [4]int{s.Tests, s.Failures, s.Errors, s.Skipped}; twice != once {
		t.Fatalf("finalize not idempotent for MaxInt counters: %v then %v", once, twice)
	}
	for _, v := range once {
		if v < 0 || v > MaxJobCases {
			t.Fatalf("MaxInt suite counters = %v, outside the job budget [0, %d]", once, MaxJobCases)
		}
	}
}

// TestBudgetClampValidatorStaysStrictForDirectSubmission pins the other side
// of the policy boundary: ValidateReportPayload is unchanged and still
// rejects the SAME absurd values when they arrive directly at /tests,
// without the parser's clamp, because there the declared values are the
// payload and no materialized evidence exists to salvage.
func TestBudgetClampValidatorStaysStrictForDirectSubmission(t *testing.T) {
	over := []struct {
		name string
		rep  model.TestReport
		want string
	}{
		{"tests above the job budget", model.TestReport{Tests: budgetAbsurd}, "tests=10000000"},
		{"failures above the job budget", model.TestReport{Tests: 1, Failures: budgetAbsurd}, "failures=10000000"},
		{"errors above the job budget", model.TestReport{Tests: 1, Errors: MaxJobCases + 1}, "errors=100001"},
		{"skipped above the job budget", model.TestReport{Tests: 1, Skipped: MaxJobCases + 1}, "skipped=100001"},
		{"report duration above the shared maximum", model.TestReport{Duration: 2 * maxReportDuration}, "report duration"},
		{"case duration above the shared maximum", model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Passed: true, Duration: 2 * maxReportDuration}}}, "case 0 duration"},
	}
	for _, tc := range over {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReportPayload(tc.rep)
			if !errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("err = %v, want ErrLimitExceeded", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want reason %q", err, tc.want)
			}
		})
	}
}
