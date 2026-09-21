package testintel

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestDurationNumericPolicy pins attrFloat's duration policy: finite
// non-negative values (including exponent forms and zero) are kept, and
// NaN, ±Inf, negatives and values above maxReportDuration are dropped to 0
// and reported as absent so no invalid duration enters a sum.
func TestDurationNumericPolicy(t *testing.T) {
	cases := []struct {
		attr   string
		want   float64
		wantOK bool
	}{
		{"1.5", 1.5, true},
		{"1e3", 1000, true},
		{"1E-3", 0.001, true},
		{" 2.5 ", 2.5, true},
		{"0", 0, true},
		{"0.0", 0, true},
		{"NaN", 0, false},
		{"nan", 0, false},
		{"+Inf", 0, false},
		{"-Inf", 0, false},
		{"Inf", 0, false},
		{"-1", 0, false},
		{"-0.5", 0, false},
		{"1e308", 0, false},
		{"1e309", 0, false},
		{"-1e309", 0, false},
		{"9223372036854775807", 0, false},
		{"", 0, false},
		{"soon", 0, false},
	}
	for _, tc := range cases {
		got, ok := attrFloat(xmlStart(t, `<testsuite time="`+tc.attr+`"/>`), "time")
		if math.IsNaN(got) || math.IsInf(got, 0) {
			t.Errorf("attrFloat(time=%q) returned a non-finite %v", tc.attr, got)
		}
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("attrFloat(time=%q) = %v,%v, want %v,%v", tc.attr, got, ok, tc.want, tc.wantOK)
		}
	}
}

// c3DurationReport mixes invalid durations from both attribute paths: suite
// time goes through attrFloat and case times are decoded through caseXML, so
// both must apply the same policy. "1e309" overflows float64 and "soon" is
// not numeric: neither may fail the report.
const c3DurationReport = `<testsuite name="s" time="NaN">
  <testcase name="nan" time="NaN"/>
  <testcase name="pinf" time="+Inf"/>
  <testcase name="ninf" time="-Inf"/>
  <testcase name="neg" time="-2"/>
  <testcase name="huge" time="1e308"/>
  <testcase name="overflow" time="1e309"/>
  <testcase name="junk" time="soon"/>
  <testcase name="exp" time="1e-3"/>
</testsuite>`

// TestParseDropsInvalidDurations proves end-to-end ingestion never retains a
// non-finite, negative or huge duration and that totals stay finite.
func TestParseDropsInvalidDurations(t *testing.T) {
	p := writeReport(t, "durations.xml", c3DurationReport)
	rep, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Duration != 0 || math.IsNaN(rep.Duration) || math.IsInf(rep.Duration, 0) {
		t.Fatalf("suite duration = %v, want a finite 0", rep.Duration)
	}
	want := []float64{0, 0, 0, 0, 0, 0, 0, 1e-3}
	if len(rep.Cases) != len(want) {
		t.Fatalf("cases = %d, want %d", len(rep.Cases), len(want))
	}
	for i, w := range want {
		if got := rep.Cases[i].Time; got != w {
			t.Errorf("case %q time = %v, want %v", rep.Cases[i].Name, got, w)
		}
	}
}

// TestValidateReportPayloadNumericPolicy pins the D4-C numeric trust
// boundary: counters are non-negative, failures+errors and skipped never
// exceed tests, and report/case durations obey the same finite,
// non-negative, maxReportDuration bound the parser applies. Every violation
// is rejected with a clear reason, and boundary-valid payloads are accepted.
func TestValidateReportPayloadNumericPolicy(t *testing.T) {
	bad := []struct {
		name   string
		rep    model.TestReport
		reason string
	}{
		{"negative tests", model.TestReport{Tests: -1}, "negative tests counter"},
		{"negative failures", model.TestReport{Tests: 2, Failures: -1}, "negative failures counter"},
		{"negative errors", model.TestReport{Tests: 2, Errors: -1}, "negative errors counter"},
		{"negative skipped", model.TestReport{Tests: 2, Skipped: -1}, "negative skipped counter"},
		{"failures+errors over tests", model.TestReport{Tests: 1, Failures: 1, Errors: 1}, "failures+errors (1+1) exceeds tests (1)"},
		{"skipped over tests", model.TestReport{Tests: 1, Skipped: 2}, "skipped (2) exceeds tests (1)"},
		{"negative report duration", model.TestReport{Duration: -1}, "report duration"},
		{"NaN report duration", model.TestReport{Duration: math.NaN()}, "report duration"},
		{"infinite report duration", model.TestReport{Duration: math.Inf(1)}, "report duration"},
		{"huge report duration", model.TestReport{Duration: maxReportDuration * 2}, "report duration"},
		{"negative case duration", model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Duration: -1}}}, "case 0 duration"},
		{"infinite case duration", model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Duration: math.Inf(1)}}}, "case 0 duration"},
		{"huge case duration", model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Duration: maxReportDuration * 2}}}, "case 0 duration"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReportPayload(tc.rep)
			if !errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("err = %v, want ErrLimitExceeded", err)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err = %v, want reason %q", err, tc.reason)
			}
		})
	}

	// Boundary-valid payload: counters exactly on the relation limits and
	// durations exactly at maxReportDuration.
	at := model.TestReport{
		Tests: 2, Failures: 1, Errors: 1, Skipped: 2, Duration: maxReportDuration,
		Cases: []model.TestResult{{Name: "t", Duration: maxReportDuration, Passed: false}},
	}
	if err := ValidateReportPayload(at); err != nil {
		t.Fatalf("boundary-valid payload rejected: %v", err)
	}
}

// TestAggregateAndValidatorAgreeOnNumbers pins the D4-C "parser and
// validator agree" contract on the aggregate path: the parser sanitizes
// producer durations to zero (so its output always passes the duration
// policy), while an impossible producer counter relation is rejected by the
// shared validator that AggregateMasked invokes, never silently written to
// the model.
func TestAggregateAndValidatorAgreeOnNumbers(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "sanitized.xml", c3DurationReport)
	agg, err := Aggregate(ws, []string{"sanitized.xml"})
	if err != nil {
		t.Fatalf("sanitized aggregate: %v", err)
	}
	if err := ValidateReportPayload(agg); err != nil {
		t.Fatalf("parser output rejected by the shared validator: %v", err)
	}

	writeFixture(t, ws, "impossible.xml",
		`<testsuite name="s" tests="1" failures="1" errors="1"><testcase name="t"/></testsuite>`)
	_, err = Aggregate(ws, []string{"impossible.xml"})
	if !errors.Is(err, ErrLimitExceeded) || !strings.Contains(err.Error(), "failures+errors") {
		t.Fatalf("impossible counter relation = %v, want the shared validator's rejection", err)
	}

	// The parser's own numeric sanitizing: a negative declared counter is
	// dropped to zero instead of leaving a negative count in the model.
	rep, err := Parse(writeReport(t, "negative.xml", `<testsuite name="s" tests="-5" failures="-2"/>`))
	if err != nil {
		t.Fatalf("negative counters must not fail the parse: %v", err)
	}
	if rep.Tests != 0 || rep.Failures != 0 {
		t.Fatalf("negative counters = tests %d failures %d, want 0/0", rep.Tests, rep.Failures)
	}
}

// TestAggregateDropsInvalidDurations is the same contract on the aggregate
// path, whose totals feed flaky-history duration balancing.
func TestAggregateDropsInvalidDurations(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "durations.xml", c3DurationReport)
	agg, err := Aggregate(ws, []string{"*.xml"})
	if err != nil {
		t.Fatal(err)
	}
	if math.IsNaN(agg.Duration) || math.IsInf(agg.Duration, 0) || agg.Duration != 0 {
		t.Fatalf("aggregate duration = %v, want a finite 0", agg.Duration)
	}
	for _, c := range agg.Cases {
		if math.IsNaN(c.Duration) || math.IsInf(c.Duration, 0) || c.Duration < 0 {
			t.Fatalf("case %q duration = %v", c.Name, c.Duration)
		}
	}
	if agg.Cases[7].Duration != 1e-3 {
		t.Fatalf("valid exponent duration = %v, want 1e-3", agg.Cases[7].Duration)
	}
}
