package testintel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAggregateEnforcesMatchedFileCap pins the per-job matched-file cap:
// one pattern matching more files than MaxReportFiles fails with
// ErrLimitExceeded before any content is parsed.
func TestAggregateEnforcesMatchedFileCap(t *testing.T) {
	ws := t.TempDir()
	body := []byte(c3JUnit)
	for i := 0; i < MaxReportFiles+1; i++ {
		if err := os.WriteFile(filepath.Join(ws, fmt.Sprintf("f%05d.xml", i)), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Aggregate(ws, []string{"*.xml"})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}

// TestAggregateEnforcesTotalByteCap uses sparse files of exactly the
// per-file cap so only the total-byte cap can trip. The cap is enforced
// while sizing the matches, before any file content is parsed, so the
// zero-filled files below are never decoded.
func TestAggregateEnforcesTotalByteCap(t *testing.T) {
	ws := t.TempDir()
	files := int(MaxJobReportBytes/MaxReportFileBytes) + 1
	for i := 0; i < files; i++ {
		f, err := os.Create(filepath.Join(ws, fmt.Sprintf("big%d.xml", i)))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(MaxReportFileBytes); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Aggregate(ws, []string{"*.xml"})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}

// TestAggregateDeduplicatesOverlappingPatterns pins the overlapping-glob
// contract: a file matched by an exact pattern AND by a glob that covers it
// is parsed exactly once, so its counters, cases and byte accounting cannot
// double (the D4-A defect). The duplicate pattern is repeated too, because
// nothing in a job declaration prevents it.
func TestAggregateDeduplicatesOverlappingPatterns(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(ws, "reports"), "unit.xml",
		`<testsuite name="unit" tests="1"><testcase name="only" classname="C"><failure message="boom">trace</failure></testcase></testsuite>`)
	writeFixture(t, filepath.Join(ws, "reports"), "other.xml",
		`<testsuite name="other" tests="1"><testcase name="other"/></testsuite>`)

	rep, err := Aggregate(ws, []string{"reports/*.xml", "reports/unit.xml", "reports/unit.xml"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if rep.Tests != 2 || rep.Failures != 1 {
		t.Fatalf("counters = tests %d failures %d, want 2/1 (unit.xml must be parsed once)", rep.Tests, rep.Failures)
	}
	if len(rep.Cases) != 2 {
		t.Fatalf("cases = %d, want 2", len(rep.Cases))
	}
	if got := strings.Count(rep.Path, "reports/unit.xml"); got != 1 {
		t.Fatalf("path list names unit.xml %d times: %q", got, rep.Path)
	}
	if got := strings.Count(rep.Path, "reports/other.xml"); got != 1 {
		t.Fatalf("path list names other.xml %d times: %q", got, rep.Path)
	}
}

// TestAggregateDedupesBeforeByteAccounting proves the dedup happens BEFORE
// the per-job total-byte cap and the per-file cap are summed: two files at
// exactly the per-file cap match four pattern instances (glob + two exact
// patterns each), so double counting would trip the total budget while the
// unique set sits exactly at it. The remaining parse error is the XML
// decoder's, never a limit error.
func TestAggregateDedupesBeforeByteAccounting(t *testing.T) {
	ws := t.TempDir()
	for _, name := range []string{"a.xml", "b.xml"} {
		f, err := os.Create(filepath.Join(ws, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(MaxReportFileBytes); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Aggregate(ws, []string{"*.xml", "a.xml", "b.xml"})
	if errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("deduplicated byte accounting tripped the limit: %v", err)
	}
	if err == nil {
		t.Fatal("zero-filled files must still fail the XML decode")
	}
}

// TestAggregateRejectsOversizedMember keeps the per-file byte cap on the
// root-anchored open path.
func TestAggregateRejectsOversizedMember(t *testing.T) {
	ws := t.TempDir()
	f, err := os.Create(filepath.Join(ws, "big.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxReportFileBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Aggregate(ws, []string{"*.xml"}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}
