package runner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

type entropyFailReader struct{ err error }

func (r entropyFailReader) Read([]byte) (int, error) { return 0, r.err }

// TestLedgerAddGuardArms covers the empty-identity, entropy-failure and
// directory-creation failures: each must refuse before any externally visible
// state exists.
func TestLedgerAddGuardArms(t *testing.T) {
	workDir := t.TempDir()
	empty := newLedgerRunner("", workDir)
	if _, err := empty.ledgerAdd(runtimeLedgerEntry{}); err == nil || !strings.Contains(err.Error(), "identity is empty") {
		t.Fatalf("empty runner id = %v", err)
	}

	r := newLedgerRunner("runner-A", workDir)
	origRand := randReader
	randReader = entropyFailReader{err: errors.New("no entropy")}
	_, err := r.ledgerAdd(runtimeLedgerEntry{})
	randReader = origRand
	if err == nil || !strings.Contains(err.Error(), "randomness unavailable") {
		t.Fatalf("entropy failure = %v", err)
	}

	// WorkDir is a regular file: the ledger directory cannot be created.
	file := filepath.Join(t.TempDir(), "workdir-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := newLedgerRunner("runner-A", file)
	if _, err := bad.ledgerAdd(runtimeLedgerEntry{}); err == nil || !strings.Contains(err.Error(), "create") {
		t.Fatalf("uncreatable ledger dir = %v", err)
	}
	if _, err := bad.reconcileRuntimeLedger("instance"); err == nil {
		t.Fatal("reconcile through an untrusted path succeeded")
	}
}

// TestLedgerUpdateAndMutatorGuards covers the empty-id and missing-entry
// refusals, the undecodable entry, and the no-op mutator doors.
func TestLedgerUpdateAndMutatorGuards(t *testing.T) {
	r := newLedgerRunner("runner-A", t.TempDir())
	if err := r.ledgerUpdate("", func(*runtimeLedgerEntry) {}); err == nil || !strings.Contains(err.Error(), "missing entry id") {
		t.Fatalf("empty id update = %v", err)
	}
	if err := r.ledgerUpdate("absent", func(*runtimeLedgerEntry) {}); err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("missing entry update = %v", err)
	}

	dir := r.runtimeLedgerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.ledgerUpdate("broken", func(*runtimeLedgerEntry) {}); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("undecodable entry update = %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "broken.json")); err != nil {
		t.Fatal(err)
	}

	id, err := r.ledgerAdd(runtimeLedgerEntry{Instance: "i1", JobID: "j1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ledgerAddArtifacts(id, ""); err != nil {
		t.Fatalf("empty artifact dir = %v, want nil", err)
	}
	if err := r.ledgerAddArtifacts(id, "/tmp/kiwi-artifacts-dup"); err != nil {
		t.Fatal(err)
	}
	if err := r.ledgerAddArtifacts(id, "/tmp/kiwi-artifacts-dup"); err != nil {
		t.Fatalf("duplicate artifact dir = %v, want nil", err)
	}
	if err := r.ledgerSetXFS(id, nil); err != nil {
		t.Fatalf("nil XFS assignment = %v, want nil", err)
	}
	if err := r.ledgerSetCgroup(id, ""); err != nil {
		t.Fatalf("empty cgroup = %v, want nil", err)
	}
	r.ledgerRemove("")
	if err := r.ledgerSetCgroup(id, "/cg/job"); err != nil {
		t.Fatal(err)
	}
}

// TestLedgerPathIsRunnerOwned pins the deletion gate: only kiwi-run- and
// kiwi-artifacts- basenames are ever removable.
func TestLedgerPathIsRunnerOwned(t *testing.T) {
	cases := map[string]bool{
		"":                            false,
		"   ":                         false,
		"/tmp/kiwi-run-abc":           true,
		"/tmp/kiwi-artifacts-abc":     true,
		"/tmp/kiwi-run-abc/nested":    false,
		"/tmp/kiwi-cache-abc":         false,
		"kiwi-run-abc":                true,
		"/tmp/prefix-kiwi-run-abc":    false,
		"/tmp/kiwi-artifacts-abc/../": false,
	}
	for p, want := range cases {
		if got := ledgerPathIsRunnerOwned(p); got != want {
			t.Errorf("ledgerPathIsRunnerOwned(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestReconcileRefusesUntrustedLedgerDir proves a ledger path that is not a
// private directory is refused instead of reclaimed through.
func TestReconcileRefusesUntrustedLedgerDir(t *testing.T) {
	r := newLedgerRunner("runner-A", t.TempDir())
	dir := r.runtimeLedgerDir()
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcileRuntimeLedger("instance"); err == nil || !strings.Contains(err.Error(), "untrusted ledger directory") {
		t.Fatalf("regular-file ledger dir = %v", err)
	}
}

// TestReconcileCorruptAndUnreadableEntries covers the per-entry trust gate:
// writable-by-others entries and unreadable entries are debt, never removed.
func TestReconcileCorruptAndUnreadableEntries(t *testing.T) {
	testutil.UnixChmod(t)
	workDir := t.TempDir()
	r := newLedgerRunner("runner-A", workDir)
	dir := r.runtimeLedgerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLedgerEntry(t, dir, "writable.json", runtimeLedgerEntry{RunnerID: "runner-A", Instance: "old", JobID: "j"})
	if err := os.Chmod(filepath.Join(dir, "writable.json"), 0o666); err != nil {
		t.Fatal(err)
	}
	res, err := r.reconcileRuntimeLedger("instance")
	if err == nil || res.Corrupt != 1 {
		t.Fatalf("writable entry = res %+v err %v, want corrupt debt", res, err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "writable.json")); serr != nil {
		t.Fatalf("corrupt entry was removed: %v", serr)
	}

	if os.Geteuid() != 0 {
		if err := os.Chmod(filepath.Join(dir, "writable.json"), 0o000); err != nil {
			t.Fatal(err)
		}
		res, err = r.reconcileRuntimeLedger("instance")
		if err == nil || res.Corrupt != 1 {
			t.Fatalf("unreadable entry = res %+v err %v, want corrupt debt", res, err)
		}
	}
}

// TestReconcileReadDirFailure covers an unreadable ledger directory after the
// trust checks: the failure is surfaced as recovery debt.
func TestReconcileReadDirFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection does not apply to root")
	}
	r := newLedgerRunner("runner-A", t.TempDir())
	dir := r.runtimeLedgerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Execute+write only: no group/other bits (so no tightening) and no read.
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := r.reconcileRuntimeLedger("instance"); err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("unreadable ledger dir = %v", err)
	}
}

// TestReconcileReclaimMarkerFailureKeepsEntry proves a failure writing the
// reclaim marker leaves the entry pending and retryable rather than dropping
// ownership evidence.
func TestReconcileReclaimMarkerFailureKeepsEntry(t *testing.T) {
	r := newLedgerRunner("runner-A", t.TempDir())
	dir := r.runtimeLedgerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLedgerEntry(t, dir, "a.json", runtimeLedgerEntry{
		RunnerID: "runner-A", Instance: "old", JobID: "j",
		Workspace: "/tmp/kiwi-run-reclaim-marker",
	})
	orig := atomicWriteFile
	atomicWriteFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	t.Cleanup(func() { atomicWriteFile = orig })

	res, err := r.reconcileRuntimeLedger("instance")
	if err == nil || res.Pending != 1 {
		t.Fatalf("marker failure = res %+v err %v, want pending debt", res, err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "a.json")); serr != nil {
		t.Fatalf("entry was retired despite the marker failure: %v", serr)
	}
	if !strings.Contains(err.Error(), "reclaim marker") {
		t.Fatalf("error = %v, want the marker failure", err)
	}
}
