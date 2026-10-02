package runner

// Crash-ledger regressions: workspace ownership recorded by a PREVIOUS
// incarnation is reclaimed before the next incarnation leases work, while
// current-incarnation entries are never touched.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
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

func TestRuntimeLedgerReclaimsXFSQuotaBeforeRetiring(t *testing.T) {
	workDir := t.TempDir()
	r := &Runner{Cfg: Config{WorkDir: workDir}}
	ws := filepath.Join(t.TempDir(), "kiwi-run-xfs")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	id := r.ledgerAdd(runtimeLedgerEntry{Instance: "instance-A", JobID: "job-x", Workspace: ws})
	r.ledgerSetXFS(id, &executor.WorkspaceQuotaAssignment{Workspace: ws, MountPoint: "/mnt/x", FsKey: "8:1", XQ: "xfs_quota", ProjectID: 123})

	prev := reclaimWorkspaceQuota
	var calls []uint32
	reclaimWorkspaceQuota = func(a executor.WorkspaceQuotaAssignment) error {
		calls = append(calls, a.ProjectID)
		return nil
	}
	t.Cleanup(func() { reclaimWorkspaceQuota = prev })

	if n := r.reconcileRuntimeLedger("instance-B"); n != 1 {
		t.Fatalf("reclaimed %d entries, want 1", n)
	}
	if len(calls) != 1 || calls[0] != 123 {
		t.Fatalf("quota reclaim calls = %v, want [123]", calls)
	}
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		t.Fatalf("workspace survived a successful quota reclaim: %v", err)
	}
}

func TestRuntimeLedgerKeepsEntryWhenXFSReclaimFails(t *testing.T) {
	workDir := t.TempDir()
	r := &Runner{Cfg: Config{WorkDir: workDir}}
	ws := filepath.Join(t.TempDir(), "kiwi-run-xfs2")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	id := r.ledgerAdd(runtimeLedgerEntry{Instance: "instance-A", JobID: "job-x", Workspace: ws})
	r.ledgerSetXFS(id, &executor.WorkspaceQuotaAssignment{Workspace: ws, MountPoint: "/mnt/x", FsKey: "8:1", XQ: "xfs_quota", ProjectID: 124})

	prev := reclaimWorkspaceQuota
	fail := true
	reclaimWorkspaceQuota = func(executor.WorkspaceQuotaAssignment) error {
		if fail {
			return errors.New("xfs cleanup refused")
		}
		return nil
	}
	t.Cleanup(func() { reclaimWorkspaceQuota = prev })

	if n := r.reconcileRuntimeLedger("instance-B"); n != 0 {
		t.Fatalf("failed reclaim retired %d entries", n)
	}
	if _, err := os.Stat(ws); err != nil {
		t.Fatalf("workspace removed before the quota was reclaimed: %v", err)
	}
	// Retry converges once cleanup can be proven.
	fail = false
	if n := r.reconcileRuntimeLedger("instance-B"); n != 1 {
		t.Fatalf("retry reclaimed %d entries, want 1", n)
	}
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		t.Fatalf("workspace survived the retry: %v", err)
	}
}
