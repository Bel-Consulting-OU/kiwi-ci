package testintel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParsePlainSuite(t *testing.T) {
	dir := t.TempDir()
	p := writeFixture(t, dir, "a.xml", `<testsuite name="unit" tests="3" failures="1" errors="1" skipped="1" time="2.5">
  <testcase name="ok" classname="pkg.T" time="0.1"/>
  <testcase name="bad" classname="pkg.T" time="0.2"><failure message="boom">trace</failure></testcase>
  <testcase name="err" classname="pkg.T" time="0.3"><error message="oops">details</error></testcase>
  <testcase name="skip" classname="pkg.T" time="0.0"><skipped message="slow"/></testcase>
</testsuite>`)
	rep, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Suites) != 1 || rep.Suites[0].Name != "unit" {
		t.Fatalf("suites: %+v", rep.Suites)
	}
	if rep.Tests != 4 || rep.Failures != 1 || rep.Errors != 1 || rep.Skipped != 1 {
		t.Fatalf("totals: tests=%d failures=%d errors=%d skipped=%d", rep.Tests, rep.Failures, rep.Errors, rep.Skipped)
	}
	if rep.Duration != 2.5 {
		t.Fatalf("duration: %v", rep.Duration)
	}
	if len(rep.Cases) != 4 {
		t.Fatalf("cases: %d", len(rep.Cases))
	}
	if rep.Cases[1].Failure == nil || rep.Cases[1].Failure.Message != "boom" || !strings.Contains(rep.Cases[1].Failure.Body, "trace") {
		t.Fatalf("failure case: %+v", rep.Cases[1])
	}
	if rep.Cases[2].Error == nil {
		t.Fatalf("error case: %+v", rep.Cases[2])
	}
	if rep.Cases[3].Skipped == nil {
		t.Fatalf("skipped case: %+v", rep.Cases[3])
	}
}

func TestParseTestsuitesWrapperAndNested(t *testing.T) {
	dir := t.TempDir()
	p := writeFixture(t, dir, "b.xml", `<testsuites>
  <testsuite name="outer" tests="1">
    <testcase name="outer-case" time="0.1"/>
    <testsuite name="inner" tests="1">
      <testcase name="inner-case" time="0.4"/>
    </testsuite>
  </testsuite>
  <testsuite name="second" tests="1" failures="1">
    <testcase name="second-case" time="0.2"><failure message="x"/></testcase>
  </testsuite>
</testsuites>`)
	rep, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Suites) != 3 {
		t.Fatalf("want 3 flattened suites, got %d: %+v", len(rep.Suites), rep.Suites)
	}
	names := []string{}
	for _, s := range rep.Suites {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "outer,inner,second" {
		t.Fatalf("suite order: %v", names)
	}
	if rep.Tests != 3 || rep.Failures != 1 {
		t.Fatalf("totals: %+v", rep)
	}
}

func TestParseCountersRecomputedFromCases(t *testing.T) {
	dir := t.TempDir()
	p := writeFixture(t, dir, "c.xml", `<testsuite name="no-attrs">
  <testcase name="a"/>
  <testcase name="b"><failure message="f"/></testcase>
</testsuite>`)
	rep, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tests != 2 || rep.Failures != 1 {
		t.Fatalf("recomputed totals: tests=%d failures=%d", rep.Tests, rep.Failures)
	}
}

func TestParseMasked(t *testing.T) {
	dir := t.TempDir()
	p := writeFixture(t, dir, "m.xml", `<testsuite name="s" tests="1" failures="1">
  <testcase name="t"><failure message="token secret-value">secret-value in body</failure><system-err>leaked secret-value</system-err></testcase>
</testsuite>`)
	rep, err := ParseMasked(p, func(s string) string {
		return strings.ReplaceAll(s, "secret-value", "[REDACTED]")
	})
	if err != nil {
		t.Fatal(err)
	}
	c := rep.Cases[0]
	if strings.Contains(c.Failure.Message, "secret-value") || strings.Contains(c.Failure.Body, "secret-value") || strings.Contains(c.SystemErr, "secret-value") {
		t.Fatalf("mask not applied: %+v", c)
	}
	if !strings.Contains(c.Failure.Message, "[REDACTED]") {
		t.Fatalf("expected redaction: %+v", c.Failure)
	}
}

func TestParseRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := writeFixture(t, dir, "real.xml", `<testsuite name="s" tests="1"><testcase name="a"/></testsuite>`)
	link := filepath.Join(dir, "link.xml")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unsupported")
	}
	if _, err := Parse(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("want symlink rejection, got %v", err)
	}
}

func TestParseRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.xml")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxReportFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Parse(p); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("want ErrLimitExceeded, got %v", err)
	}
}

func TestParseRejectsTooManyCases(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString(`<testsuite name="s" tests="100001">`)
	for i := 0; i < MaxReportCases+1; i++ {
		b.WriteString(`<testcase name="t"/>`)
	}
	b.WriteString(`</testsuite>`)
	p := writeFixture(t, dir, "many.xml", b.String())
	if _, err := Parse(p); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("want ErrLimitExceeded, got %v", err)
	}
}

func TestParseRejectsNonXML(t *testing.T) {
	dir := t.TempDir()
	p := writeFixture(t, dir, "junk.xml", "not xml at all")
	if _, err := Parse(p); err == nil {
		t.Fatal("want parse error")
	}
}

func TestWithin(t *testing.T) {
	cases := []struct {
		ws, path string
		want     bool
	}{
		{"/ws", "/ws/a.xml", true},
		{"/ws", "/ws/sub/a.xml", true},
		{"/ws", "/ws/../outside.xml", false},
		{"/ws", "/other/a.xml", false},
		{"/ws", "/ws", false},
	}
	for _, c := range cases {
		if got := Within(c.ws, c.path); got != c.want {
			t.Errorf("Within(%q, %q) = %v, want %v", c.ws, c.path, got, c.want)
		}
	}
}

func TestAggregateMasked(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "u1.xml", `<testsuite name="u1" tests="1" failures="1"><testcase name="a"><failure message="secret-x"/></testcase></testsuite>`)
	writeFixture(t, dir, "u2.xml", `<testsuite name="u2" tests="2" skipped="1"><testcase name="b"/><testcase name="c"><skipped/></testcase></testsuite>`)
	rep, err := AggregateMasked(dir, []string{"*.xml"}, func(s string) string { return strings.ReplaceAll(s, "secret-x", "REDACTED") })
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tests != 3 || rep.Failures != 1 || rep.Skipped != 1 {
		t.Fatalf("totals: %+v", rep)
	}
	if len(rep.Cases) != 3 {
		t.Fatalf("cases: %d", len(rep.Cases))
	}
	if strings.Contains(rep.Cases[0].Message, "secret-x") {
		t.Fatalf("mask not applied in aggregate: %q", rep.Cases[0].Message)
	}
	if !rep.Cases[2].Skipped || rep.Cases[2].Passed {
		t.Fatalf("skipped result wrong: %+v", rep.Cases[2])
	}
}

func TestAggregateRejectsOutsideWorkspace(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, ws, "ok.xml", `<testsuite name="s" tests="1"><testcase name="a"/></testsuite>`)
	if _, err := Aggregate(ws, []string{"*.xml"}); err != nil {
		t.Fatal(err)
	}
	// A glob that escapes the workspace must be rejected even when the
	// files exist.
	writeFixture(t, root, "escape.xml", `<testsuite name="s" tests="1"><testcase name="a"/></testsuite>`)
	if _, err := Aggregate(ws, []string{"../escape.xml"}); err == nil {
		t.Fatal("want outside-workspace rejection")
	}
}
