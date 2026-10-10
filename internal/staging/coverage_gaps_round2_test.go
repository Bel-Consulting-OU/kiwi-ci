package staging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestAcquireDirLockWritableLockFile proves a pre-existing lock file that any
// non-owner could rewrite (group/world-writable) is refused before flock: the
// file is part of the ownership proof, not scratch space.
func TestAcquireDirLockWritableLockFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, LockFileName)
	if err := os.WriteFile(path, []byte("stale"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireDirLock(dir); err == nil || !strings.Contains(err.Error(), "trustworthy") {
		t.Fatalf("acquireDirLock(writable lock) = %v, want the trust refusal", err)
	}
}

// TestDirLockReleaseUnlockFailure proves a release whose underlying descriptor
// was already closed reports the unlock failure instead of acknowledging
// ownership release.
func TestDirLockReleaseUnlockFailure(t *testing.T) {
	dir := t.TempDir()
	lock, err := acquireDirLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.file.Close(); err != nil {
		t.Fatal(err)
	}
	err = lock.release()
	if err == nil || !strings.Contains(err.Error(), "unlock") {
		t.Fatalf("release after close = %v, want the unlock failure", err)
	}
}

// TestReplicaDirMkdirFailure covers a configured root that cannot be created
// because a parent is a regular file.
func TestReplicaDirMkdirFailure(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReplicaDir(filepath.Join(parent, "root"), ""); err == nil {
		t.Fatal("ReplicaDir under a regular file succeeded")
	}
}

// TestNewReplicaBudgetRegistryArms covers the validation failure, the
// one-ledger-per-directory conflict, and the same-construction reuse of an
// already registered replica directory.
func TestNewReplicaBudgetRegistryArms(t *testing.T) {
	root := t.TempDir()
	if _, err := NewReplicaBudget(root, "bad id!", 1024); err == nil {
		t.Fatal("NewReplicaBudget accepted an invalid instance id")
	}

	dir, _, err := ReplicaDir(root, "replica-a")
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewBudget(dir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })

	if _, err := NewReplicaBudget(root, "replica-a", 2048); err == nil || !strings.Contains(err.Error(), "exactly one ledger") {
		t.Fatalf("conflicting bound = %v, want the one-ledger error", err)
	}
	again, err := NewReplicaBudget(root, "replica-a", 1024)
	if err != nil {
		t.Fatalf("re-registering the same bound: %v", err)
	}
	if again != first {
		t.Fatal("NewReplicaBudget did not return the existing ledger")
	}
}

// TestInstanceIDConcurrentPublishConverges drives many concurrent first starts
// on one fresh root: exactly one publishes, the losers adopt the winner (the
// create-if-absent race), and every caller observes the same id.
func TestInstanceIDConcurrentPublishConverges(t *testing.T) {
	root := t.TempDir()
	const workers = 32
	start := make(chan struct{})
	ids := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ids[i], errs[i] = loadOrCreateInstanceID(root)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		if ids[i] != ids[0] {
			t.Fatalf("worker %d id %q, first %q", i, ids[i], ids[0])
		}
	}
	published, err := readPublishedInstanceID(filepath.Join(root, InstanceIDFileName))
	if err != nil || published != ids[0] {
		t.Fatalf("published id = %q/%v, want %q", published, err, ids[0])
	}
}

// TestNewBudgetProbeFailure proves the writability probe fails construction
// after the ownership lock and reclaim: a directory that exists (with an
// existing lock file to open) but refuses new files is unusable.
func TestNewBudgetProbeFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection does not apply to root")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LockFileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := NewBudget(dir, 1024); err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Fatalf("NewBudget on an unwritable directory = %v, want the probe failure", err)
	}
}

// TestBudgetCloseStructLiteralArms pins the state machine arms of
// CloseWithContext that a normal constructed budget cannot enter: a nil done
// channel, a finalized wait, a concurrent-release wait, and a non-empty
// ledger with a cancelled context.
func TestBudgetCloseStructLiteralArms(t *testing.T) {
	// A zero-value budget with no done channel: Close creates it and the
	// nil ownership lock releases as a no-op.
	b := &Budget{notify: make(chan struct{})}
	if err := b.CloseWithContext(context.Background()); err != nil {
		t.Fatalf("CloseWithContext on a bare budget: %v", err)
	}
	if !b.finalized {
		t.Fatal("bare budget was not finalized")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// finalized with a never-closed done channel: the caller's ctx wins.
	final := &Budget{finalized: true, done: make(chan struct{}), notify: make(chan struct{})}
	if err := final.CloseWithContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("finalized close = %v, want context.Canceled", err)
	}

	// Another caller mid-release: this caller waits and its ctx wins.
	releasing := &Budget{releasing: true, done: make(chan struct{}), notify: make(chan struct{})}
	if err := releasing.CloseWithContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("releasing close = %v, want context.Canceled", err)
	}

	// Outstanding bytes with a cancelled ctx: ownership stays, ctx is
	// reported, and the budget is retryable.
	held := &Budget{used: 1, done: make(chan struct{}), notify: make(chan struct{})}
	if err := held.CloseWithContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("held close = %v, want context.Canceled", err)
	}
}

// TestReservationNilAndClampArms covers the defensive nil receivers and the
// negative-ledger clamps of Release/consumeLocked, plus the empty-path
// ReleaseSpool no-op.
func TestReservationNilAndClampArms(t *testing.T) {
	(&Reservation{}).Release()

	r := &Reservation{budget: &Budget{notify: make(chan struct{})}, n: 5}
	r.Release()
	if r.budget.used != 0 {
		t.Fatalf("used = %d, want the clamp to zero", r.budget.used)
	}

	var nilRes *Reservation
	if got := nilRes.consumeLocked(); got != 0 {
		t.Fatalf("nil consumeLocked = %d, want 0", got)
	}
	if got := (&Reservation{n: 5}).consumeLocked(); got != 5 {
		t.Fatalf("budgetless consumeLocked = %d, want 5", got)
	}
	clamp := &Reservation{budget: &Budget{}, n: 5}
	if got := clamp.consumeLocked(); got != 5 {
		t.Fatalf("consumeLocked = %d, want 5", got)
	}
	if clamp.budget.used != 0 {
		t.Fatalf("used = %d, want the clamp to zero", clamp.budget.used)
	}

	(&Budget{}).ReleaseSpool("")
}

// TestForgetMissingSpoolsDebtClamp proves a vanished active spool settles its
// cleanup debt and the pending ledger never goes negative.
func TestForgetMissingSpoolsDebtClamp(t *testing.T) {
	missing := filepath.Join(t.TempDir(), FilePrefix+"gone")
	b := &Budget{
		activeSpools:   map[string]struct{}{missing: {}},
		pendingCleanup: map[string]int64{missing: 5},
		pendingBytes:   2,
	}
	b.forgetMissingSpoolsLocked()
	if _, ok := b.activeSpools[missing]; ok {
		t.Fatal("missing spool still active")
	}
	if _, ok := b.pendingCleanup[missing]; ok {
		t.Fatal("missing spool still charged")
	}
	if b.pendingBytes != 0 {
		t.Fatalf("pendingBytes = %d, want 0", b.pendingBytes)
	}
}

// TestPruneNilAndReadDirFailure covers the nil-receiver no-op and a directory
// that is not a directory: Prune reports the real error, never a silent zero.
func TestPruneNilAndReadDirFailure(t *testing.T) {
	var b *Budget
	if n, err := b.Prune(context.Background()); n != 0 || err != nil {
		t.Fatalf("nil Prune = %d/%v", n, err)
	}

	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Budget{dir: file}).Prune(context.Background()); err == nil {
		t.Fatal("Prune on a regular file succeeded")
	}
}

// TestCanonicalDirFallbackWhenGetwdFails covers the unnormalizable-path
// fallback: with the working directory gone, filepath.Abs fails and the path
// is still cleaned rather than left as-is.
func TestCanonicalDirFallbackWhenGetwdFails(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := os.Chdir(orig); cerr != nil {
			t.Fatalf("restore working directory: %v", cerr)
		}
	}()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if got, want := canonicalDir("rel/../staging"), filepath.Clean("rel/../staging"); got != want {
		t.Fatalf("canonicalDir fallback = %q, want %q", got, want)
	}
}

// TestSpoolCopyZeroLimitAndReaderErrors covers the zero-limit no-progress
// refusal, a non-EOF reader error at the zero limit, and a non-EOF reader
// error after a partial copy.
func TestSpoolCopyZeroLimitAndReaderErrors(t *testing.T) {
	if _, err := spoolCopy(&strings.Builder{}, zeroNilReader{}, 0); err == nil || !strings.Contains(err.Error(), "no progress") {
		t.Fatalf("zero-limit no-progress = %v, want the fail-closed error", err)
	}
	boom := errors.New("reader exploded")
	if _, err := spoolCopy(&strings.Builder{}, eofAfterErrorReader{err: boom}, 0); !errors.Is(err, boom) {
		t.Fatalf("zero-limit reader error = %v, want the reader error", err)
	}

	var dst strings.Builder
	if n, err := spoolCopy(&dst, &tailErrorReader{data: "ab", err: boom}, 10); n != 2 || !errors.Is(err, boom) {
		t.Fatalf("partial copy = %d/%v, want 2/%v", n, err, boom)
	}
}

type zeroNilReader struct{}

func (zeroNilReader) Read([]byte) (int, error) { return 0, nil }

type eofAfterErrorReader struct{ err error }

func (r eofAfterErrorReader) Read([]byte) (int, error) { return 0, r.err }

type tailErrorReader struct {
	data string
	err  error
	done bool
}

func (r *tailErrorReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, r.err
	}
	r.done = true
	return copy(p, r.data), nil
}
