package testintel

// G1-C/D/F/G/H regressions: parser/validator/memory agreement on control
// bytes, directory-safe glob expansion, a bounded glob budget, duplicate
// attribute rejection, and rendered-name de-duplication in History.Flaky.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// TestValidateReportPayloadRejectsControlBytes pins G1-C: the authoritative
// validator refuses NUL and other XML-illegal control bytes in every identity
// field and in the retained message, so a direct /tests submission can no
// longer reach SQL with a NUL (22P05) or store a byte the parser rejects.
func TestValidateReportPayloadRejectsControlBytes(t *testing.T) {
	bad := []struct {
		name string
		rep  model.TestReport
	}{
		{"job key NUL", model.TestReport{Tests: 1, JobKey: "suite\x00A", Cases: []model.TestResult{{Name: "t", Passed: true}}}},
		{"case name NUL", model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t\x00x", Passed: true}}}},
		{"case class NUL", model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Class: "C\x00", Passed: true}}}},
		{"case message NUL", model.TestReport{Tests: 1, Failures: 1, Cases: []model.TestResult{{Name: "t", Passed: false, Message: "boom\x00"}}}},
		{"case name vertical tab", model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t\x0b", Passed: true}}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateReportPayload(tc.rep)
			if !errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("err = %v, want ErrLimitExceeded", err)
			}
			if !strings.Contains(err.Error(), "control byte") {
				t.Fatalf("err = %v, want a control-byte reason", err)
			}
		})
	}
	// Tab, newline and carriage return stay legal, including inside a message.
	good := model.TestReport{Tests: 1, Failures: 1, Cases: []model.TestResult{{Name: "t", Passed: false, Message: "line1\nline2\tend\r\n"}}}
	if err := ValidateReportPayload(good); err != nil {
		t.Fatalf("whitespace control bytes rejected: %v", err)
	}
}

// TestParserRejectsControlBytesInIdentity pins the parser half of G1-C: the
// same NUL byte the validator refuses makes encoding/xml reject the file, so
// parser and validator agree on what a valid identity is.
func TestParserRejectsControlBytesInIdentity(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "nul.xml", "<testsuite name=\"s\" tests=\"1\"><testcase name=\"a\x00b\"/></testsuite>")
	if _, err := Parse(filepath.Join(dir, "nul.xml")); err == nil {
		t.Fatal("parser accepted a NUL byte in a testcase name")
	}
}

// TestParseRejectsDuplicateAttributes pins G1-G: duplicate attributes are
// refused on BOTH suites (which used first-wins) and testcases (which used
// last-wins), so the two decode paths can never resolve the same malformed
// input differently.
func TestParseRejectsDuplicateAttributes(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"suite":    `<testsuite name="a" name="b" tests="1"><testcase name="x"/></testsuite>`,
		"testcase": `<testsuite name="a" tests="1"><testcase name="x" name="y"/></testsuite>`,
		"class":    `<testsuite name="a" tests="1"><testcase name="x" classname="C" classname="D"/></testsuite>`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			writeFixture(t, dir, name+".xml", body)
			_, err := Parse(filepath.Join(dir, name+".xml"))
			if err == nil || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("err = %v, want a duplicate-attribute rejection", err)
			}
		})
	}
}

// TestReportCandidatesSkipsDirectoriesAtLastComponent pins G1-D: a glob whose
// last component matches a directory must not emit it as a report candidate,
// and the aggregation must keep every regular-file report.
func TestReportCandidatesSkipsDirectoriesAtLastComponent(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "reports", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(ws, "reports"), "unit.xml",
		`<testsuite name="unit" tests="1"><testcase name="only" classname="C"/></testsuite>`)
	writeFixture(t, filepath.Join(ws, "reports"), "other.xml",
		`<testsuite name="other" tests="1"><testcase name="other"/></testsuite>`)

	root, err := safefs.OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := reportCandidates(root, "reports/*", map[string]bool{}, MaxReportFiles)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	for _, c := range got {
		if c == "reports/sub" {
			t.Fatalf("directory emitted as a report candidate: %v", got)
		}
	}
	// The whole aggregation must survive the directory match.
	rep, err := Aggregate(ws, []string{"reports/*"})
	if err != nil {
		t.Fatalf("aggregate with a directory match: %v", err)
	}
	if rep.Tests != 2 || len(rep.Cases) != 2 {
		t.Fatalf("aggregated tests/cases = %d/%d, want 2/2 (pre-fix the directory aborted everything)", rep.Tests, len(rep.Cases))
	}
}

// TestReportCandidatesHonorsRemainingBudget pins G1-H: expansion stops with
// ErrLimitExceeded as soon as it finds more than the remaining budget, so a
// directory with thousands of matches is never fully materialized or sorted.
func TestReportCandidatesHonorsRemainingBudget(t *testing.T) {
	ws := t.TempDir()
	const files = 3000
	for i := 0; i < files; i++ {
		writeFixture(t, ws, fmt.Sprintf("f%04d.xml", i), c3JUnit)
	}
	root, err := safefs.OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// Over-budget: stop at the first over-limit match instead of materializing
	// and sorting all 3000 files.
	if _, err := reportCandidates(root, "*.xml", map[string]bool{}, 10); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("budget 10 over %d matches = %v, want ErrLimitExceeded", files, err)
	}
	if _, err := reportCandidates(root, "*.xml", map[string]bool{}, MaxReportFiles); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("budget %d over %d matches = %v, want ErrLimitExceeded", MaxReportFiles, files, err)
	}
	// Within budget: every match is returned.
	got, err := reportCandidates(root, "*.xml", map[string]bool{}, files)
	if err != nil {
		t.Fatalf("budget %d over %d matches: %v", files, files, err)
	}
	if len(got) != files {
		t.Fatalf("candidates = %d, want %d", len(got), files)
	}
	// Already-seen candidates do not consume the budget.
	seen := map[string]bool{}
	for _, c := range got {
		seen[c] = true
	}
	if _, err := reportCandidates(root, "*.xml", seen, 0); err != nil {
		t.Fatalf("re-expanding entirely-seen matches errored: %v", err)
	}
}

// TestHistoryFlakyDeduplicatesRenderedNames pins G1-F: the same class.name in
// two suites is two independent windows but ONE rendered flaky name, matching
// the SQL (DISTINCT) and in-memory flaky queries.
func TestHistoryFlakyDeduplicatesRenderedNames(t *testing.T) {
	h := NewHistory()
	now := time.Now().UTC()
	for _, suite := range []string{"suite-a", "suite-b"} {
		h.Record("github.com/o/r", suite, "C", "TestX", 1, true, now)
		h.Record("github.com/o/r", suite, "C", "TestX", 1, false, now)
	}
	got := h.Flaky("github.com/o/r")
	if len(got) != 1 || got[0] != "C.TestX" {
		t.Fatalf("flaky = %v, want exactly one deduplicated C.TestX", got)
	}
}
