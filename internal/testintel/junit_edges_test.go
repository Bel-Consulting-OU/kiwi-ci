package testintel

import (
	"encoding/xml"
	"errors"
	"fmt"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func xmlStart(t *testing.T, src string) xml.StartElement {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(src))
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se
		}
	}
}

func writeReport(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseIOErrors(t *testing.T) {
	testutil.UnixChmod(t)
	if _, err := Parse(filepath.Join(t.TempDir(), "missing.xml")); err == nil {
		t.Fatal("missing report must fail")
	}

	dir := t.TempDir()
	// A directory passes Lstat but is not a regular file after open.
	if _, err := Parse(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory = %v", err)
	}

	// An unreadable file fails at open.
	locked := filepath.Join(dir, "locked.xml")
	if err := os.WriteFile(locked, []byte("<testsuite/>"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(locked); err == nil {
		t.Fatal("unreadable report must fail")
	}
	if err := os.Chmod(locked, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Parse(writeReport(t, "empty.xml", "")); err == nil || !strings.Contains(err.Error(), "not a JUnit report") {
		t.Fatalf("empty report = %v", err)
	}
	if _, err := Parse(writeReport(t, "malformed.xml", "<testsuites><testsuite></testsuites>")); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("malformed report = %v", err)
	}
}

func TestParseBareTestcaseRoots(t *testing.T) {
	cases := map[string]string{
		"pass.xml":    `<testcase name="p" classname="c" time="0.5"/>`,
		"failure.xml": `<testcase name="f"><failure message="m">body</failure></testcase>`,
		"error.xml":   `<testcase name="e"><error message="m">body</error></testcase>`,
		"skipped.xml": `<testcase name="s"><skipped message="why"/></testcase>`,
	}
	for name, content := range cases {
		rep, err := Parse(writeReport(t, name, content))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Tests != 1 || len(rep.Suites) != 1 {
			t.Fatalf("%s: report = %+v", name, rep)
		}
		if len(rep.Cases) != 1 {
			t.Fatalf("%s: cases = %+v", name, rep.Cases)
		}
	}
	rep, err := Parse(writeReport(t, "failure.xml", `<testcase name="f"><failure message="m">body</failure></testcase>`))
	if err != nil || rep.Failures != 1 {
		t.Fatalf("failure counters = %+v (err %v)", rep, err)
	}
	rep, err = Parse(writeReport(t, "error.xml", `<testcase name="e"><error message="m">body</error></testcase>`))
	if err != nil || rep.Errors != 1 {
		t.Fatalf("error counters = %+v (err %v)", rep, err)
	}
	rep, err = Parse(writeReport(t, "skipped.xml", `<testcase name="s"><skipped message="why"/></testcase>`))
	if err != nil || rep.Skipped != 1 {
		t.Fatalf("skipped counters = %+v (err %v)", rep, err)
	}
}

func TestParseTestsuitesWrapperEdges(t *testing.T) {
	// Bare testcases inside a testsuites wrapper.
	rep, err := Parse(writeReport(t, "wrapper.xml", `<testsuites>
		<testcase name="ok"/>
		<testcase name="bad"><failure message="f"/></testcase>
		<testcase name="err"><error message="e"/></testcase>
		<testcase name="skip"><skipped/></testcase>
		<properties/>
	</testsuites>`))
	if err != nil {
		t.Fatalf("wrapper: %v", err)
	}
	if rep.Tests != 4 || rep.Failures != 1 || rep.Errors != 1 || rep.Skipped != 1 {
		t.Fatalf("wrapper report = %+v", rep)
	}

	// A nested testsuite inside the wrapper contributes its own suites.
	rep, err = Parse(writeReport(t, "nested.xml", `<testsuites><testsuite name="outer"><testcase name="a"/><testsuite name="inner"><testcase name="b"/></testsuite></testsuite></testsuites>`))
	if err != nil {
		t.Fatalf("nested: %v", err)
	}
	if len(rep.Suites) != 2 || rep.Tests != 2 {
		t.Fatalf("nested report = %+v", rep)
	}

	// Truncated wrapper, suite and nested suite are unexpected-EOF errors.
	if _, err := Parse(writeReport(t, "truncated.xml", `<testsuites>`)); err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("truncated wrapper = %v", err)
	}
	if _, err := Parse(writeReport(t, "truncated2.xml", `<testsuite name="x">`)); err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("truncated suite = %v", err)
	}
	if _, err := Parse(writeReport(t, "truncated3.xml", `<testsuite name="outer"><testsuite name="inner">`)); err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("truncated nested suite = %v", err)
	}
	if _, err := Parse(writeReport(t, "truncated4.xml", `<testsuites><testsuite name="a"/>`)); err == nil {
		t.Fatal("truncated wrapper tail must fail")
	}
	// Tokenizer errors at the document level, after a complete root.
	if _, err := Parse(writeReport(t, "tail.xml", `<testsuite name="s"/><`)); err == nil {
		t.Fatal("malformed document tail must fail")
	}
	if _, err := Parse(writeReport(t, "skiptail.xml", `<other><inner>`)); err == nil {
		t.Fatal("unterminated unknown element must fail")
	}
	// A bare testcase with a truncated child fails inside the wrapper.
	if _, err := Parse(writeReport(t, "wrapperbad.xml", `<testsuites><testcase name="a"><failure></testsuites>`)); err == nil {
		t.Fatal("truncated wrapped testcase must fail")
	}
	// A root testcase with a truncated child fails.
	if _, err := Parse(writeReport(t, "rootbad.xml", `<testcase name="a"><failure>`)); err == nil {
		t.Fatal("truncated root testcase must fail")
	}
	// An unknown element left open until EOF fails inside Skip.
	if _, err := Parse(writeReport(t, "skipfail.xml", `<testsuite name="x"><weird>`)); err == nil {
		t.Fatal("unterminated unknown element must fail")
	}
	if _, err := Parse(writeReport(t, "skipfail2.xml", `<testsuites><weird>`)); err == nil {
		t.Fatal("unterminated unknown wrapper element must fail")
	}
	// Malformed nested testcase content fails the decode.
	if _, err := Parse(writeReport(t, "badtc.xml", `<testsuite name="x"><testcase name="a"><failure>`)); err == nil {
		t.Fatal("truncated failure body must fail")
	}
}

func TestParseRecomputesCountersFromCases(t *testing.T) {
	rep, err := Parse(writeReport(t, "counters.xml", `<testsuite name="s" tests="1" failures="0" errors="0" skipped="0" time="1.5">
		<testcase name="f"><failure message="m"/></testcase>
		<testcase name="e"><error message="m"/></testcase>
		<testcase name="s"><skipped/></testcase>
	</testsuite>`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rep.Failures != 1 || rep.Errors != 1 || rep.Skipped != 1 || rep.Tests != 3 {
		t.Fatalf("recomputed report = %+v", rep)
	}
	if rep.Duration != 1.5 {
		t.Fatalf("duration = %v", rep.Duration)
	}
}

func TestParseMaskedErrorAndSystemErr(t *testing.T) {
	mask := func(s string) string { return strings.ReplaceAll(s, "secret", "***") }
	rep, err := ParseMasked(writeReport(t, "masked.xml", `<testsuite name="s">
		<testcase name="e"><error message="secret msg">secret body</error><system-err>leaked secret</system-err></testcase>
	</testsuite>`), mask)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c := rep.Cases[0]
	if strings.Contains(c.Error.Message, "secret") || strings.Contains(c.Error.Body, "secret") {
		t.Fatalf("error not masked: %+v", c.Error)
	}
	if strings.Contains(c.SystemErr, "secret") {
		t.Fatalf("system-err not masked: %q", c.SystemErr)
	}
}

func TestTruncateFailureLimits(t *testing.T) {
	big := strings.Repeat("m", maxMessageLen+100)
	f := &Failure{Message: big, Body: big}
	truncateFailure(f)
	if len(f.Message) != maxMessageLen {
		t.Fatalf("message len = %d", len(f.Message))
	}
	if len(f.Body) != 0 {
		t.Fatalf("body len = %d, want 0 after the combined cap", len(f.Body))
	}

	f = &Failure{Message: "short", Body: strings.Repeat("b", maxMessageLen)}
	truncateFailure(f)
	if len(f.Message)+len(f.Body) != maxMessageLen {
		t.Fatalf("combined len = %d, want %d", len(f.Message)+len(f.Body), maxMessageLen)
	}

	// A nil failure and a small failure are left alone.
	truncateFailure(nil)
	small := &Failure{Message: "m", Body: "b"}
	truncateFailure(small)
	if small.Message != "m" || small.Body != "b" {
		t.Fatalf("small failure changed: %+v", small)
	}
}

func TestAttrParsingEdges(t *testing.T) {
	if v, ok := attrInt(xmlStart(t, `<testsuite tests=" 7 "/>`), "tests"); !ok || v != 7 {
		t.Fatalf("attrInt = %d,%v", v, ok)
	}
	if _, ok := attrInt(xmlStart(t, `<testsuite tests="seven"/>`), "tests"); ok {
		t.Fatal("non-numeric attrInt must fail")
	}
	if _, ok := attrInt(xmlStart(t, `<testsuite/>`), "tests"); ok {
		t.Fatal("missing attrInt must fail")
	}
	if v, ok := attrFloat(xmlStart(t, `<testsuite time=" 2.5 "/>`), "time"); !ok || v != 2.5 {
		t.Fatalf("attrFloat = %v,%v", v, ok)
	}
	if _, ok := attrFloat(xmlStart(t, `<testsuite time="soon"/>`), "time"); ok {
		t.Fatal("non-numeric attrFloat must fail")
	}
	if _, ok := attrFloat(xmlStart(t, `<testsuite/>`), "time"); ok {
		t.Fatal("missing attrFloat must fail")
	}
	if got := attrValue(xmlStart(t, `<testsuite name="x"/>`), "other"); got != "" {
		t.Fatalf("attrValue = %q", got)
	}
}

func TestWithinRejectsSiblingsAndSelf(t *testing.T) {
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if Within(ws, ws) {
		t.Fatal("the workspace itself must not count as within")
	}
	if Within(ws, filepath.Join(ws, "..", "elsewhere.xml")) {
		t.Fatal("a sibling path must not count as within")
	}
	if !Within(ws, filepath.Join(ws, "reports", "a.xml")) {
		t.Fatal("a nested path must count as within")
	}
}

func TestAggregateEdges(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "reports", "a.xml"),
		[]byte(`<testsuite name="a"><testcase name="one"><failure message="boom">trace</failure></testcase><testcase name="two"><error message="err">trace</error></testcase><testcase name="three"/></testsuite>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "reports", "b.xml"),
		[]byte(`<testsuite name="b"><testcase name="four" classname="cls" time="0.25"><skipped/></testcase></testsuite>`), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := Aggregate(ws, []string{"reports/*.xml"})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if rep.Tests != 4 || rep.Failures != 1 || rep.Errors != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if !strings.Contains(rep.Path, ", ") {
		t.Fatalf("multi-file path = %q", rep.Path)
	}
	var failure, errored, passed, skipped bool
	for _, c := range rep.Cases {
		switch c.Name {
		case "one":
			failure = strings.Contains(c.Message, "boom") && !c.Passed
		case "two":
			errored = strings.Contains(c.Message, "err") && !c.Passed
		case "three":
			passed = c.Passed && c.Message == ""
		case "four":
			skipped = c.Skipped && !c.Passed
		}
	}
	if !failure || !errored || !passed || !skipped {
		t.Fatalf("case mapping wrong: failure=%v errored=%v passed=%v skipped=%v (%+v)", failure, errored, passed, skipped, rep.Cases)
	}

	if _, err := Aggregate(ws, []string{"reports/["}); err == nil {
		t.Fatal("invalid glob must fail")
	}
	if _, err := Aggregate(ws, []string{"reports/missing.xml"}); err != nil {
		t.Fatalf("no matches must succeed: %v", err)
	}
	broken := filepath.Join(ws, "reports", "broken.xml")
	if err := os.WriteFile(broken, []byte("<testsuite><oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Aggregate(ws, []string{"reports/broken.xml"}); err == nil {
		t.Fatal("malformed member must fail the aggregate")
	}
}

func TestFlakeProbabilityWindow(t *testing.T) {
	if got := flakeProbability(nil); got != 0 {
		t.Fatalf("empty = %v", got)
	}
	if got := flakeProbability([]bool{true}); got != 0 {
		t.Fatalf("single = %v", got)
	}
	if got := flakeProbability([]bool{true, false}); got != 0.5 {
		t.Fatalf("even split = %v", got)
	}
	if got := flakeProbability([]bool{true, true, true, false}); math.Abs(got-0.25) > 1e-9 {
		t.Fatalf("minority share = %v", got)
	}
	if got := flakeProbability([]bool{false, false, false}); got != 0 {
		t.Fatalf("all-fail = %v", got)
	}
}

// TestAggregateRejectsMoreThanMaxJobCases exercises the per-job case cap. It
// needs more than maxJobCases (500k) cases spread across files, since each
// file is separately capped at maxReportCases (100k).
func TestAggregateRejectsMoreThanMaxJobCases(t *testing.T) {
	ws := t.TempDir()
	var sb strings.Builder
	sb.WriteString(`<testsuite name="s">`)
	for i := 0; i < maxReportCases; i++ {
		sb.WriteString(`<testcase name="t"/>`)
	}
	sb.WriteString(`</testsuite>`)
	body := sb.String()
	files := maxJobCases/maxReportCases + 1
	for i := 0; i < files; i++ {
		if err := os.WriteFile(filepath.Join(ws, fmt.Sprintf("f%d.xml", i)), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Aggregate(ws, []string{"*.xml"})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want ErrLimitExceeded", err)
	}
}
