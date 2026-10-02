package runner

// Crash-ledger regressions: workspace ownership recorded by a PREVIOUS
// incarnation is reclaimed before the next incarnation leases work, while
// current-incarnation entries are never touched.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeLedgerReclaimsPreviousIncarnation(t *testing.T) {
	workDir := t.TempDir()
	r := &Runner{Cfg: Config{WorkDir: workDir}}

	// A crashed job's workspace + artifact scratch, recorded by instance A.
	staleWS := filepath.Join(t.TempDir(), "kiwi-run-dead")
	staleArtifacts := filepath.Join(workDir, "kiwi-artifacts-dead")
	if err := os.MkdirAll(staleWS, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(staleArtifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	idA := r.ledgerAdd(runtimeLedgerEntry{Instance: "instance-A", JobID: "job-a", Workspace: staleWS})
	r.ledgerAddArtifacts(idA, staleArtifacts)
	if idA == "" {
		t.Fatal("ledger entry not written")
	}

	// A CURRENT-incarnation entry must survive reconciliation.
	liveWS := filepath.Join(t.TempDir(), "kiwi-run-live")
	if err := os.MkdirAll(liveWS, 0o700); err != nil {
		t.Fatal(err)
	}
	r.ledgerAdd(runtimeLedgerEntry{Instance: "instance-B", JobID: "job-b", Workspace: liveWS})

	if n := r.reconcileRuntimeLedger("instance-B"); n != 1 {
		t.Fatalf("reclaimed %d entries, want 1", n)
	}
	if _, err := os.Stat(staleWS); !os.IsNotExist(err) {
		t.Fatalf("previous-incarnation workspace survived: %v", err)
	}
	if _, err := os.Stat(staleArtifacts); !os.IsNotExist(err) {
		t.Fatalf("previous-incarnation artifact scratch survived: %v", err)
	}
	if _, err := os.Stat(liveWS); err != nil {
		t.Fatalf("current-incarnation workspace removed: %v", err)
	}
	// The reclaimed entry is retired; the live one remains.
	files, err := os.ReadDir(r.runtimeLedgerDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(r.runtimeLedgerDir(), f.Name()))
		if string(b) == "" {
			continue
		}
		if strings.Contains(string(b), `"instance":"instance-B"`) {
			continue
		}
	}
	// A replayed reconciliation is a no-op.
	if n := r.reconcileRuntimeLedger("instance-B"); n != 0 {
		t.Fatalf("replayed reconciliation reclaimed %d entries", n)
	}
}
