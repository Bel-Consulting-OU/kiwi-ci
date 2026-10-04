package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
)

// newLedgerRunner builds a runner whose only relevant configuration is the
// stable id and a shared WorkDir.
func newLedgerRunner(id, workDir string) *Runner {
	return &Runner{ID: id, Cfg: Config{WorkDir: workDir}}
}

// TestRuntimeLedgerNamespaceIncludesStableRunner: the ledger directory is
// keyed by the hash of the stable runner id, so runners sharing a WorkDir
// are physically separated.
func TestRuntimeLedgerNamespaceIncludesStableRunner(t *testing.T) {
	workDir := t.TempDir()
	a := newLedgerRunner("runner-A", workDir)
	b := newLedgerRunner("runner-B", workDir)
	dirA, dirB := a.runtimeLedgerDir(), b.runtimeLedgerDir()
	if dirA == dirB {
		t.Fatal("runners share a ledger directory")
	}
	sumA := sha256.Sum256([]byte("runner-A"))
	wantA := filepath.Join(workDir, ".kiwi-runtime", hex.EncodeToString(sumA[:]), "ledger")
	if dirA != wantA {
		t.Fatalf("ledger dir = %s, want %s", dirA, wantA)
	}
	if !strings.HasPrefix(dirA, workDir) {
		t.Fatalf("ledger dir escapes WorkDir: %s", dirA)
	}
}

// ledgerFixture records one crashed job for runner A (workspace + artifact
// scratch + fake XFS/cgroup coordinates) and returns the workspace paths.
func ledgerFixture(t *testing.T, a *Runner) (liveWS, artifacts, entryID string) {
	t.Helper()
	liveWS = filepath.Join(t.TempDir(), "kiwi-run-A-live")
	artifacts = filepath.Join(a.Cfg.WorkDir, "kiwi-artifacts-A-live")
	for _, d := range []string{liveWS, artifacts} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	id, err := a.ledgerAdd(runtimeLedgerEntry{Instance: "instance-A", JobID: "job-a", Workspace: liveWS})
	if err != nil {
		t.Fatalf("ledgerAdd: %v", err)
	}
	if err := a.ledgerAddArtifacts(id, artifacts); err != nil {
		t.Fatalf("ledgerAddArtifacts: %v", err)
	}
	if err := a.ledgerSetXFS(id, &executor.WorkspaceQuotaAssignment{Workspace: liveWS, MountPoint: "/mnt/xfs", FsKey: "8:70", XQ: "/usr/sbin/xfs_quota", ProjectID: 100123}); err != nil {
		t.Fatalf("ledgerSetXFS: %v", err)
	}
	if err := a.ledgerSetCgroup(id, "/sys/fs/cgroup/kiwi/job-a"); err != nil {
		t.Fatalf("ledgerSetCgroup: %v", err)
	}
	return liveWS, artifacts, id
}

type reclaimCalls struct {
	xfs    []uint32
	cgroup []string
}

func stubReclaimSeams(t *testing.T, calls *reclaimCalls) {
	t.Helper()
	origXFS, origCG := reclaimWorkspaceQuota, reclaimJobCgroup
	reclaimWorkspaceQuota = func(a executor.WorkspaceQuotaAssignment) error {
		calls.xfs = append(calls.xfs, a.ProjectID)
		return nil
	}
	reclaimJobCgroup = func(path string) error {
		calls.cgroup = append(calls.cgroup, path)
		return nil
	}
	t.Cleanup(func() { reclaimWorkspaceQuota, reclaimJobCgroup = origXFS, origCG })
}

// TestRunnerBCannotReclaimRunnerALiveWorkspace is the P1 isolation test: B's
// reconciliation must not touch A's crashed-state artifacts, XFS quota or
// cgroup while A is a DIFFERENT runner (even though A is not currently live:
// B never reclaims another runner's namespace).
func TestRunnerBCannotReclaimRunnerALiveWorkspace(t *testing.T) {
	workDir := t.TempDir()
	a := newLedgerRunner("runner-A", workDir)
	b := newLedgerRunner("runner-B", workDir)
	liveWS, artifacts, _ := ledgerFixture(t, a)
	calls := &reclaimCalls{}
	stubReclaimSeams(t, calls)

	res, err := b.reconcileRuntimeLedger("instance-B")
	if err != nil {
		t.Fatalf("B reconcile: %v", err)
	}
	if res.Reclaimed != 0 {
		t.Fatalf("B reclaimed %d entries from A", res.Reclaimed)
	}
	if len(calls.xfs) != 0 || len(calls.cgroup) != 0 {
		t.Fatalf("B reclaimed A's quotas/cgroups: %+v", calls)
	}
	if _, err := os.Stat(liveWS); err != nil {
		t.Fatalf("B removed A's workspace: %v", err)
	}
	if _, err := os.Stat(artifacts); err != nil {
		t.Fatalf("B removed A's artifact scratch: %v", err)
	}
}

// TestRunnerBCannotClearRunnerAXFSQuota and CannotRemoveRunnerACgroup are
// covered by the seam assertions above; this focused variant proves A's own
// restart DOES reclaim its coordinates.
func TestCorrectRunnerRestartReclaimsItsOwnPreviousState(t *testing.T) {
	workDir := t.TempDir()
	a := newLedgerRunner("runner-A", workDir)
	liveWS, artifacts, _ := ledgerFixture(t, a)
	calls := &reclaimCalls{}
	stubReclaimSeams(t, calls)

	res, err := a.reconcileRuntimeLedger("instance-A-next")
	if err != nil {
		t.Fatalf("A restart reconcile: %v", err)
	}
	if res.Reclaimed != 1 {
		t.Fatalf("reclaimed %d, want 1", res.Reclaimed)
	}
	if len(calls.xfs) != 1 || calls.xfs[0] != 100123 {
		t.Fatalf("XFS reclaim = %v", calls.xfs)
	}
	if len(calls.cgroup) != 1 || calls.cgroup[0] != "/sys/fs/cgroup/kiwi/job-a" {
		t.Fatalf("cgroup reclaim = %v", calls.cgroup)
	}
	if _, err := os.Stat(liveWS); !os.IsNotExist(err) {
		t.Fatalf("own crashed workspace survived: %v", err)
	}
	if _, err := os.Stat(artifacts); !os.IsNotExist(err) {
		t.Fatalf("own crashed artifact scratch survived: %v", err)
	}
}

// TestRuntimeLedgerCurrentInstanceEntriesSurvive: a live instance's entries
// are never reclaimed.
func TestRuntimeLedgerCurrentInstanceEntriesSurvive(t *testing.T) {
	workDir := t.TempDir()
	a := newLedgerRunner("runner-A", workDir)
	liveWS, _, _ := ledgerFixture(t, a)
	calls := &reclaimCalls{}
	stubReclaimSeams(t, calls)
	res, err := a.reconcileRuntimeLedger("instance-A")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Reclaimed != 0 || len(calls.xfs) != 0 {
		t.Fatalf("current instance entries were reclaimed: %+v", res)
	}
	if _, err := os.Stat(liveWS); err != nil {
		t.Fatal("current instance workspace removed")
	}
}

// TestRuntimeLedgerPublishFailuresAreFatal: every publication point must
// surface a durable-write failure so the caller can refuse to create the
// external state the entry exists for.
func TestRuntimeLedgerPublishFailuresAreFatal(t *testing.T) {
	workDir := t.TempDir()
	r := newLedgerRunner("runner-A", workDir)
	orig := atomicWriteFile
	fail := true
	atomicWriteFile = func(path string, data []byte, mode os.FileMode) error {
		if fail {
			return errors.New("disk full")
		}
		return orig(path, data, mode)
	}
	t.Cleanup(func() { atomicWriteFile = orig })

	if _, err := r.ledgerAdd(runtimeLedgerEntry{Instance: "i1", JobID: "j1", Workspace: "/tmp/kiwi-run-x"}); err == nil {
		t.Fatal("ledgerAdd ignored a durable-write failure")
	}
	fail = false
	id, err := r.ledgerAdd(runtimeLedgerEntry{Instance: "i1", JobID: "j1", Workspace: "/tmp/kiwi-run-x"})
	if err != nil {
		t.Fatalf("ledgerAdd: %v", err)
	}
	fail = true
	if err := r.ledgerAddArtifacts(id, "/tmp/kiwi-artifacts-x"); err == nil {
		t.Fatal("ledgerAddArtifacts ignored a durable-write failure")
	}
	if err := r.ledgerSetXFS(id, &executor.WorkspaceQuotaAssignment{ProjectID: 1}); err == nil {
		t.Fatal("ledgerSetXFS ignored a durable-write failure")
	}
	if err := r.ledgerSetCgroup(id, "/cg"); err == nil {
		t.Fatal("ledgerSetCgroup ignored a durable-write failure")
	}
}

// TestRuntimeLedgerUnresolvedDebtFailsReconcile: corrupt entries and reclaim
// failures inside THIS runner's namespace are unresolved recovery debt and
// must be reported (the caller refuses to lease), unlike the old
// silently-ignored behavior.
func TestRuntimeLedgerUnresolvedDebtFailsReconcile(t *testing.T) {
	workDir := t.TempDir()
	a := newLedgerRunner("runner-A", workDir)
	dir := a.runtimeLedgerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// corrupt JSON
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.reconcileRuntimeLedger("instance-new"); err == nil {
		t.Fatal("corrupt entry did not surface as debt")
	}
	// foreign runner id inside our namespace
	if err := os.Remove(filepath.Join(dir, "broken.json")); err != nil {
		t.Fatal(err)
	}
	writeLedgerEntry(t, dir, "foreign.json", runtimeLedgerEntry{RunnerID: "runner-B", Instance: "ib", JobID: "j"})
	if _, err := a.reconcileRuntimeLedger("instance-new"); err == nil {
		t.Fatal("foreign runner entry did not surface as debt")
	}
	// reclaim failure on our own entry
	if err := os.Remove(filepath.Join(dir, "foreign.json")); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(t.TempDir(), "kiwi-run-A")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLedgerEntry(t, dir, "a.json", runtimeLedgerEntry{RunnerID: "runner-A", Instance: "ia", JobID: "j", Workspace: ws, Cgroup: "/cg"})
	orig := reclaimJobCgroup
	reclaimJobCgroup = func(string) error { return errors.New("cgroup busy") }
	t.Cleanup(func() { reclaimJobCgroup = orig })
	res, err := a.reconcileRuntimeLedger("instance-new")
	if err == nil {
		t.Fatal("reclaim failure did not surface as debt")
	}
	if res.Pending != 1 {
		t.Fatalf("pending = %d, want 1", res.Pending)
	}
}

func writeLedgerEntry(t *testing.T, dir, name string, entry runtimeLedgerEntry) {
	t.Helper()
	b, err := jsonMarshalEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func jsonMarshalEntry(e runtimeLedgerEntry) ([]byte, error) {
	return json.Marshal(e)
}
