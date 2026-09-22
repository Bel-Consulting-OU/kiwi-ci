package staging

// Ownership (O3-A) and per-replica (O3-B) tests: the staging directory is
// single-writer, so a restart reclaims everything a dead owner stranded and a
// second live owner is refused. Several proofs need two real processes (the
// in-process registry deliberately shares one ledger per directory), so they
// re-execute this test binary as a child through the helper env vars below.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	crashChildEnv   = "KIWI_STAGING_TEST_CRASH_CHILD"
	ownerChildEnv   = "KIWI_STAGING_TEST_OWNER_CHILD"
	replicaChildEnv = "KIWI_STAGING_TEST_REPLICA_CHILD"
)

// runStagingChild re-executes this test binary with the named test and env
// var set, so the work happens in a separate process with its own ownership
// lock. It returns the combined output and whether the child exited 0.
func runStagingChild(t *testing.T, testName, envName, envValue string) (string, bool) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), envName+"="+envValue)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// TestBudgetCrashRestartReclaimsStrandedFilesAndStartsFromZero is the O3-A
// regression: a process that staged bytes and died without cleanup leaves
// files and a full ledger behind on disk. The restart must delete EVERY
// pre-existing spool file (they are provably a dead owner's: the live owner
// lock was taken first) and start from Used() == 0, so the disk bound is real
// again. The numbers are small stand-ins for the reported 30 GiB scenario.
func TestBudgetCrashRestartReclaimsStrandedFilesAndStartsFromZero(t *testing.T) {
	const (
		maxBytes = 64 << 20
		staged   = 30 << 20
		files    = 3
	)
	if dir := os.Getenv(crashChildEnv); dir != "" {
		b, err := NewBudget(dir, maxBytes)
		if err != nil {
			fmt.Fprintln(os.Stderr, "child NewBudget:", err)
			os.Exit(2)
		}
		if _, err := b.Acquire(context.Background(), staged); err != nil {
			fmt.Fprintln(os.Stderr, "child Acquire:", err)
			os.Exit(3)
		}
		for i := 0; i < files; i++ {
			name := fmt.Sprintf("%sstaged-%d", FilePrefix, i)
			if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte("x"), staged/files), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "child write spool:", err)
				os.Exit(4)
			}
		}
		// Crash: no Release, no Close, no file removal. The OS drops the
		// ownership lock at process exit.
		os.Exit(0)
	}
	dir := t.TempDir()
	foreign := filepath.Join(dir, "unrelated.dat")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, ok := runStagingChild(t, "TestBudgetCrashRestartReclaimsStrandedFilesAndStartsFromZero", crashChildEnv, dir)
	if !ok {
		t.Fatalf("crashing child failed: %s", out)
	}
	// The crashed owner is dead; every prefixed file it left is garbage.
	b, err := NewBudget(dir, maxBytes)
	if err != nil {
		t.Fatalf("restart NewBudget: %v", err)
	}
	defer func() { _ = b.Close() }()
	if got := b.Used(); got != 0 {
		t.Fatalf("restart Used() = %d, want 0 (the restart must not inherit the dead owner's ledger)", got)
	}
	if got := b.StaleFilesRemoved(); got != files {
		t.Fatalf("StaleFilesRemoved() = %d, want %d", got, files)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), FilePrefix) {
			t.Fatalf("stranded spool file %q survived the restart (disk still holds unaccounted bytes)", e.Name())
		}
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("restart removed a foreign file: %v", err)
	}
	// The reclaimed ledger admits a full budget again.
	res, err := b.Acquire(context.Background(), maxBytes)
	if err != nil {
		t.Fatalf("reclaimed budget refused a full reservation: %v", err)
	}
	res.Release()
}

// TestBudgetRefusesSecondLiveOwner proves the other half of O3-A: while an
// owner is alive, neither a second lock acquisition in this process nor a
// second process may take the directory — each would admit another maxBytes
// over the same disk.
func TestBudgetRefusesSecondLiveOwner(t *testing.T) {
	if dir := os.Getenv(ownerChildEnv); dir != "" {
		_, err := NewBudget(dir, 1<<20)
		if err == nil {
			fmt.Println("child acquired a directory a live owner already holds")
			os.Exit(1)
		}
		if !errors.Is(err, ErrStagingDirOwned) {
			fmt.Fprintln(os.Stderr, "child refusal is not ErrStagingDirOwned:", err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	dir := t.TempDir()
	b, err := NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatalf("first owner: %v", err)
	}
	defer func() { _ = b.Close() }()
	// The process registry makes NewBudget idempotent in-process; the raw
	// lock must still refuse a second holder, which is what refuses a second
	// live PROCESS too.
	if _, err := acquireDirLock(dir); !errors.Is(err, ErrStagingDirOwned) {
		t.Fatalf("second lock acquisition = %v, want ErrStagingDirOwned", err)
	}
	out, ok := runStagingChild(t, "TestBudgetRefusesSecondLiveOwner", ownerChildEnv, dir)
	if !ok {
		t.Fatalf("second live owner was not refused: %s", out)
	}
}

// TestBudgetCloseReleasesOwnershipAndHandsTheDirectoryOver: Close is the
// orderly hand-off / simulated crash. A successor then owns the directory,
// starts from zero, and reclaims what the predecessor left.
func TestBudgetCloseReleasesOwnershipAndHandsTheDirectoryOver(t *testing.T) {
	dir := t.TempDir()
	first, err := NewBudget(dir, 1000)
	if err != nil {
		t.Fatal(err)
	}
	res, err := first.Acquire(context.Background(), 900)
	if err != nil {
		t.Fatal(err)
	}
	res.Release()
	stranded := filepath.Join(dir, FilePrefix+"stranded")
	if err := os.WriteFile(stranded, []byte("dead owner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	var nilBudget *Budget
	if err := nilBudget.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
	if _, err := first.Acquire(context.Background(), 1); !errors.Is(err, ErrClosed) {
		t.Fatalf("Acquire on a closed budget = %v, want ErrClosed", err)
	}
	second, err := NewBudget(dir, 1000)
	if err != nil {
		t.Fatalf("successor NewBudget: %v", err)
	}
	defer func() { _ = second.Close() }()
	if second == first {
		t.Fatal("successor reused the closed budget")
	}
	if got := second.Used(); got != 0 {
		t.Fatalf("successor Used() = %d, want 0", got)
	}
	if _, err := os.Stat(stranded); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successor did not reclaim the predecessor's spool file: %v", err)
	}
	if got := second.StaleFilesRemoved(); got != 1 {
		t.Fatalf("successor StaleFilesRemoved() = %d, want 1", got)
	}
}

// TestBudgetSameDirectorySharesOneLedgerInProcess: a process is one
// accounting authority. Two constructions for one directory return the same
// Budget (so the bound stays exact), and a conflicting bound is refused
// instead of silently resizing the ledger.
func TestBudgetSameDirectorySharesOneLedgerInProcess(t *testing.T) {
	dir := t.TempDir()
	first, err := NewBudget(dir, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := NewBudget(dir, 1000)
	if err != nil {
		t.Fatalf("second construction for the same directory: %v", err)
	}
	if second != first {
		t.Fatal("same directory produced two independent ledgers in one process")
	}
	res, err := first.Acquire(context.Background(), 400)
	if err != nil {
		t.Fatal(err)
	}
	if got := second.Used(); got != 400 {
		t.Fatalf("shared ledger Used() = %d, want 400", got)
	}
	res.Release()
	if _, err := NewBudget(dir, 2000); err == nil || !strings.Contains(err.Error(), "already owned by this process") {
		t.Fatalf("conflicting bound for an owned directory = %v, want an explicit refusal", err)
	}
}

// TestReplicaDirDerivesPrivateInstanceDirectory (O3-B): the configured root
// is never the staging directory; each replica gets <root>/<instance-id>.
func TestReplicaDirDerivesPrivateInstanceDirectory(t *testing.T) {
	root := t.TempDir()
	dir, id, err := ReplicaDir(root, "replica-explicit")
	if err != nil {
		t.Fatalf("ReplicaDir explicit: %v", err)
	}
	if id != "replica-explicit" || dir != filepath.Join(root, "replica-explicit") {
		t.Fatalf("explicit derivation = (%q, %q)", dir, id)
	}
	if _, err := os.Stat(filepath.Join(root, InstanceIDFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit instance id must not create the persisted id file: %v", err)
	}
	// Without an explicit id the process generates one and persists it, so
	// every later start (and every other replica) resolves to the same id.
	dir1, id1, err := ReplicaDir(root, "")
	if err != nil {
		t.Fatalf("ReplicaDir generated: %v", err)
	}
	dir2, id2, err := ReplicaDir(root, "")
	if err != nil {
		t.Fatalf("ReplicaDir generated (second): %v", err)
	}
	if id1 == "" || id1 != id2 || dir1 != dir2 || dir1 != filepath.Join(root, id1) {
		t.Fatalf("generated derivation not stable: (%q,%q) then (%q,%q)", dir1, id1, dir2, id2)
	}
	if !strings.HasPrefix(id1, generatedInstanceIDPrefix) {
		t.Fatalf("generated id %q lacks the %q marker", id1, generatedInstanceIDPrefix)
	}
	published, err := os.ReadFile(filepath.Join(root, InstanceIDFileName))
	if err != nil {
		t.Fatalf("persisted instance id: %v", err)
	}
	if strings.TrimSpace(string(published)) != id1 {
		t.Fatalf("persisted id = %q, want %q", strings.TrimSpace(string(published)), id1)
	}
	// The id becomes a directory name: traversal, hidden and empty ids are
	// refused.
	for _, bad := range []string{"..", ".", "../escape", "a/b", `a\b`, "a b", ".hidden", strings.Repeat("x", MaxInstanceIDLen+1), "bad\x00id"} {
		if _, _, err := ReplicaDir(root, bad); err == nil {
			t.Fatalf("ReplicaDir accepted unsafe instance id %q", bad)
		}
	}
	// An id without a root has no directory to name.
	if _, _, err := ReplicaDir("", "replica-a"); !errors.Is(err, ErrNoBound) {
		t.Fatalf("ReplicaDir without a root = %v, want ErrNoBound", err)
	}
}

// TestReplicaBudgetIsolatesReplicasSharingARoot (O3-B): under the chosen
// per-replica contract, distinct instance ids under one root are fully
// independent directories and ledgers, so one replica exhausting its budget
// never blocks another.
func TestReplicaBudgetIsolatesReplicasSharingARoot(t *testing.T) {
	root := t.TempDir()
	a, err := NewReplicaBudget(root, "replica-a", 100)
	if err != nil {
		t.Fatalf("replica a: %v", err)
	}
	defer func() { _ = a.Close() }()
	b, err := NewReplicaBudget(root, "replica-b", 100)
	if err != nil {
		t.Fatalf("replica b: %v", err)
	}
	defer func() { _ = b.Close() }()
	if a.Dir() == b.Dir() {
		t.Fatalf("two replicas share the directory %s", a.Dir())
	}
	if a.Dir() != filepath.Join(root, "replica-a") || b.Dir() != filepath.Join(root, "replica-b") {
		t.Fatalf("replica dirs = %q, %q", a.Dir(), b.Dir())
	}
	held, err := a.Acquire(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("replica b ledger moved to %d while replica a filled its own budget", got)
	}
	other, err := b.Acquire(context.Background(), 100)
	if err != nil {
		t.Fatalf("replica b refused a full reservation because replica a was full: %v", err)
	}
	held.Release()
	other.Release()
}

// TestReplicaBudgetSharedRootWithoutDistinctIDIsRefused (O3-B): without
// explicit ids, two live replicas resolve to the same persisted id and the
// second startup is refused — never silently multiplied. With distinct ids
// the same root is safe.
func TestReplicaBudgetSharedRootWithoutDistinctIDIsRefused(t *testing.T) {
	if root := os.Getenv(replicaChildEnv); root != "" {
		_, err := NewReplicaBudget(root, "", 1<<20)
		if err == nil {
			fmt.Println("child acquired a shared root a live replica already owns")
			os.Exit(1)
		}
		if !errors.Is(err, ErrStagingDirOwned) {
			fmt.Fprintln(os.Stderr, "child refusal is not ErrStagingDirOwned:", err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	root := t.TempDir()
	owner, err := NewReplicaBudget(root, "", 1<<20)
	if err != nil {
		t.Fatalf("first replica: %v", err)
	}
	defer func() { _ = owner.Close() }()
	if out, ok := runStagingChild(t, "TestReplicaBudgetSharedRootWithoutDistinctIDIsRefused", replicaChildEnv, root); !ok {
		t.Fatalf("second replica on the same root was not refused: %s", out)
	}
	// The same root with a distinct explicit id is isolated and admitted.
	other, err := NewReplicaBudget(root, "replica-second", 1<<20)
	if err != nil {
		t.Fatalf("replica with a distinct id: %v", err)
	}
	defer func() { _ = other.Close() }()
	if other.Dir() == owner.Dir() {
		t.Fatal("distinct id resolved to the owner's directory")
	}
}

// TestReplicaBudgetReclaimsLegacyBareRootSpoolFiles: pre-contract processes
// spooled directly into the configured directory. Those bare files are
// reclaimed when the root is adopted, while replica subdirectories (each with
// its own lock) are never entered.
func TestReplicaBudgetReclaimsLegacyBareRootSpoolFiles(t *testing.T) {
	root := t.TempDir()
	bare := filepath.Join(root, FilePrefix+"legacy")
	if err := os.WriteFile(bare, []byte("old layout"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "unrelated.dat")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	otherReplica := filepath.Join(root, "replica-other")
	if err := os.MkdirAll(otherReplica, 0o700); err != nil {
		t.Fatal(err)
	}
	otherSpool := filepath.Join(otherReplica, FilePrefix+"live-elsewhere")
	if err := os.WriteFile(otherSpool, []byte("another replica's bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := NewReplicaBudget(root, "", 1<<20)
	if err != nil {
		t.Fatalf("NewReplicaBudget: %v", err)
	}
	defer func() { _ = b.Close() }()
	if got := b.StaleFilesRemoved(); got != 1 {
		t.Fatalf("StaleFilesRemoved() = %d, want 1 (only the legacy bare file)", got)
	}
	if _, err := os.Stat(bare); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy bare spool file survived: %v", err)
	}
	if _, err := os.Stat(otherSpool); err != nil {
		t.Fatalf("another replica's spool file was reclaimed: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign file was reclaimed: %v", err)
	}
	// The ledger is zero and the budget admits its full bound.
	if got := b.Used(); got != 0 {
		t.Fatalf("Used() = %d, want 0", got)
	}
	res, err := b.Acquire(context.Background(), 1<<20)
	if err != nil {
		t.Fatalf("reclaimed replica budget refused its full bound: %v", err)
	}
	res.Release()
	// A missing root and a non-positive bound are still bound errors.
	if _, err := NewReplicaBudget(filepath.Join(root, "missing", "deep"), "", 1024); err != nil {
		t.Fatalf("NewReplicaBudget should create a missing root: %v", err)
	}
	if _, err := NewReplicaBudget(root, "replica-x", 0); !errors.Is(err, ErrNoBound) {
		t.Fatalf("non-positive replica bound = %v, want ErrNoBound", err)
	}
}

// TestReplicaBudgetPersistedIDSurvivesRestart: the generated id is durable,
// so a restart reclaims the same replica directory instead of orphaning it.
func TestReplicaBudgetPersistedIDSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	first, err := NewReplicaBudget(root, "", 4096)
	if err != nil {
		t.Fatal(err)
	}
	dir := first.Dir()
	spool := filepath.Join(dir, FilePrefix+"snapshot-partial")
	if err := os.WriteFile(spool, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewReplicaBudget(root, "", 4096)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer func() { _ = second.Close() }()
	if second.Dir() != dir {
		t.Fatalf("restart resolved %q, want the persisted replica directory %q", second.Dir(), dir)
	}
	if _, err := os.Stat(spool); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restart left the previous owner's spool file behind: %v", err)
	}
	if got := second.Used(); got != 0 {
		t.Fatalf("restart Used() = %d, want 0", got)
	}
}
