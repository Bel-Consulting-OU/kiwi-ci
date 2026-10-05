package runner

// Quota-ambiguity retention: when an XFS command fails ambiguously and its
// cleanup cannot be proven, the runtime ledger entry and the workspace must
// survive so the NEXT incarnation retries the reclaim. The old behavior
// returned a soft status, deleted the ledger entry and the workspace, and
// permanently lost the only durable coordinates of a possibly-live
// assignment.

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// retainQuotaStub installs a quota stub that reports an ambiguous side effect
// whose cleanup is pending, and returns the pending coordinates.
func retainQuotaStub(t *testing.T) executor.QuotaCleanupPendingError {
	t.Helper()
	pending := executor.QuotaCleanupPendingError{
		Assignment: executor.WorkspaceQuotaAssignment{
			MountPoint: "/mnt/xfs", FsKey: "8:70", XQ: "/usr/sbin/xfs_quota", ProjectID: 424242,
		},
		Cause: errors.New("xfs_quota assign: simulated timeout"),
	}
	orig := installWorkspaceDiskQuota
	installWorkspaceDiskQuota = func(workspace string, limit int64, onAllocated func(executor.WorkspaceQuotaAssignment) error) (executor.DiskQuotaStatus, func() error, error) {
		// Mirror the real order: coordinates are recorded BEFORE the
		// assignment command, then the command fails ambiguously and cleanup
		// cannot be proven.
		pending.Assignment.Workspace = workspace
		if onAllocated != nil {
			if hookErr := onAllocated(pending.Assignment); hookErr != nil {
				return executor.DiskQuotaStatus{Detail: "record failed"}, nil, hookErr
			}
		}
		return executor.DiskQuotaStatus{Detail: "assign failed; cleanup also failed"}, nil, &pending
	}
	t.Cleanup(func() { installWorkspaceDiskQuota = orig })
	return pending
}

func runAmbiguousQuotaTask(t *testing.T, r *Runner, fsrv *fakeRunnerServer, tmpDir string) (server.Complete, bool, string) {
	t.Helper()
	task := basicTask(payloadPipeline)
	task.Job.Trusted = false
	task.Job.DiskRequest = 1 << 20
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error {
		t.Error("checkout ran for a job whose quota side effect is ambiguous")
		return nil
	}
	r.execute(context.Background(), task)
	c, ok := fsrv.lastComplete()
	workspaces, _ := filepath.Glob(filepath.Join(tmpDir, "kiwi-run-*"))
	ws := ""
	if len(workspaces) > 0 {
		ws = workspaces[0]
	}
	return c, ok, ws
}

func ledgerEntryCount(t *testing.T, r *Runner) int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(r.runtimeLedgerDir(), "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return len(files)
}

// TestXFSAssignFailureCleanupFailureKeepsLedger pins the durable-ownership
// invariant: the failed job leaves its ledger entry (carrying the assignment
// coordinates) in place for the next incarnation.
func TestXFSAssignFailureCleanupFailureKeepsLedger(t *testing.T) {
	pending := retainQuotaStub(t)
	_ = pending
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{WorkDir: t.TempDir(), IdentityDir: t.TempDir()})
	c, ok, ws := runAmbiguousQuotaTask(t, r, fsrv, tmpDir)
	if !ok || c.Status != model.StatusFailure || !strings.Contains(c.Error, "cleanup pending") {
		t.Fatalf("complete = %+v ok=%v, want a cleanup-pending failure", c, ok)
	}
	if ws == "" {
		t.Fatal("workspace removed despite unproven quota cleanup")
	}
	if n := ledgerEntryCount(t, r); n != 1 {
		t.Fatalf("ledger entries = %d, want the retained entry", n)
	}
}

// TestQuotaAmbiguityDoesNotRemoveWorkspace is the workspace-focused variant
// of the same invariant.
func TestQuotaAmbiguityDoesNotRemoveWorkspace(t *testing.T) {
	retainQuotaStub(t)
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{WorkDir: t.TempDir(), IdentityDir: t.TempDir()})
	_, _, ws := runAmbiguousQuotaTask(t, r, fsrv, tmpDir)
	if ws == "" {
		t.Fatal("workspace removed despite unproven quota cleanup")
	}
}

// TestQuotaAmbiguitySurvivesRunnerRestart: a fresh Runner instance (same
// stable identity and WorkDir) still sees the retained entry.
func TestQuotaAmbiguitySurvivesRunnerRestart(t *testing.T) {
	retainQuotaStub(t)
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	workDir := t.TempDir()
	r := testRunnerFor(t, ts, Config{WorkDir: workDir, IdentityDir: t.TempDir()})
	runAmbiguousQuotaTask(t, r, fsrv, tmpDir)
	if n := ledgerEntryCount(t, r); n != 1 {
		t.Fatalf("ledger entries after failure = %d, want 1", n)
	}
	// "Restart": same configuration, new object; the entry is still there.
	restarted := &Runner{ID: r.ID, Cfg: r.Cfg}
	if n := ledgerEntryCount(t, restarted); n != 1 {
		t.Fatalf("ledger entries after restart = %d, want 1", n)
	}
}

// TestRestartReclaimsAmbiguousXFSAssignment: the replacement incarnation's
// reconciliation retries the pending reclaim with the recorded coordinates
// and then removes the retained workspace.
func TestRestartReclaimsAmbiguousXFSAssignment(t *testing.T) {
	pending := retainQuotaStub(t)
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	workDir := t.TempDir()
	r := testRunnerFor(t, ts, Config{WorkDir: workDir, IdentityDir: t.TempDir()})
	_, _, ws := runAmbiguousQuotaTask(t, r, fsrv, tmpDir)
	if ws == "" {
		t.Fatal("setup: no retained workspace")
	}

	var reclaimed []executor.WorkspaceQuotaAssignment
	origXFS, origCG := reclaimWorkspaceQuota, reclaimJobCgroup
	reclaimWorkspaceQuota = func(a executor.WorkspaceQuotaAssignment) error {
		reclaimed = append(reclaimed, a)
		return nil
	}
	reclaimJobCgroup = func(string) error { return nil }
	t.Cleanup(func() { reclaimWorkspaceQuota, reclaimJobCgroup = origXFS, origCG })

	restarted := &Runner{ID: r.ID, Cfg: r.Cfg}
	res, err := restarted.reconcileRuntimeLedger("instance-after-restart")
	if err != nil {
		t.Fatalf("restart reconcile: %v", err)
	}
	if res.Reclaimed != 1 {
		t.Fatalf("reclaimed = %d, want 1", res.Reclaimed)
	}
	if len(reclaimed) != 1 || reclaimed[0].ProjectID != pending.Assignment.ProjectID || reclaimed[0].MountPoint != pending.Assignment.MountPoint {
		t.Fatalf("reclaimed coordinates = %+v, want the pending assignment", reclaimed)
	}
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		t.Fatalf("retained workspace survived the successful reclaim: %v", err)
	}
}
