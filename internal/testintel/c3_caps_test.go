package testintel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
