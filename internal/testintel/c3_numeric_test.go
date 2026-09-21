package testintel

import (
	"math"
	"testing"
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
