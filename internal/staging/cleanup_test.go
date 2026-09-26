package staging

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

// injectRemoveFailure installs a failing removeSpoolFile for the duration of
// one test and returns a restore function. It models EPERM (a filesystem that
// refuses deletion) without depending on directory permissions, which root
// and some CI sandboxes ignore.
func injectRemoveFailure(t *testing.T, err error) func() {
	t.Helper()
	prev := removeSpoolFile
	removeSpoolFile = func(string) error { return err }
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		removeSpoolFile = prev
	}
	t.Cleanup(restore)
	return restore
}

// TestCleanupSpoolFailureKeepsChargeAndRetryReleases is the X1-B regression:
// when the budget-owned cleanup cannot remove a no-longer-needed spool, it
// must KEEP the bytes charged and the spool registered (Used() still reflects
// physical occupancy, PendingCleanup reports the degraded condition) instead
// of dropping the reservation on the floor. A later RetryCleanup with the
// filesystem healthy reclaims the file, unregisters it and releases the
// charge.
func TestCleanupSpoolFailureKeepsChargeAndRetryReleases(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = b.CloseWithContext(ctx)
	})

	res, err := b.Acquire(context.Background(), 16)
	if err != nil {
		t.Fatal(err)
	}
	path, n, err := b.SpoolFile(bytes.NewReader([]byte("0123456789abcdef")), 16)
	if err != nil || n != 16 {
		t.Fatalf("SpoolFile = (%q, %d, %v)", path, n, err)
	}
	if used := b.Used(); used != 16 {
		t.Fatalf("Used() after staging = %d, want 16", used)
	}

	restore := injectRemoveFailure(t, os.ErrPermission)
	if ok := b.CleanupSpool(path, res); ok {
		t.Fatal("CleanupSpool reported success while removal was failing")
	}
	if used := b.Used(); used != 16 {
		t.Fatalf("Used() after failed cleanup = %d, want the 16 charged bytes kept", used)
	}
	if got := b.PendingCleanup(); got != 1 {
		t.Fatalf("PendingCleanup() = %d, want 1", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("failed cleanup must leave the file on disk: %v", err)
	}
	// The spool stays REGISTERED: Prune must not treat the cleanup-required
	// file as abandoned even after its age exceeds any threshold.
	b.PruneMinAge = time.Nanosecond
	time.Sleep(2 * time.Millisecond)
	if removed, err := b.Prune(context.Background()); err != nil || removed != 0 {
		t.Fatalf("Prune removed a cleanup-required spool: removed=%d err=%v", removed, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Prune unlinked a cleanup-required spool: %v", err)
	}

	// A healthy retry reclaims the file and releases the charge.
	restore()
	removed, err := b.RetryCleanup(context.Background())
	if err != nil || removed != 1 {
		t.Fatalf("RetryCleanup = (%d, %v), want (1, nil)", removed, err)
	}
	if used := b.Used(); used != 0 {
		t.Fatalf("Used() after retry = %d, want 0", used)
	}
	if got := b.PendingCleanup(); got != 0 {
		t.Fatalf("PendingCleanup() after retry = %d, want 0", got)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retry did not remove the spool: stat err = %v", err)
	}
}

// TestSpoolFileFailedCopyKeepsDebtWhenRemovalFails pins the other cleanup
// site: when a failed copy's partial file cannot be removed, SpoolFile must
// not silently drop the spool registration. The partial bytes stay charged
// (the caller releases its reservation, the budget keeps the physical bytes)
// and RetryCleanup reclaims them once the filesystem allows it.
func TestSpoolFileFailedCopyKeepsDebtWhenRemovalFails(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = b.CloseWithContext(ctx)
	})

	res, err := b.Acquire(context.Background(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("client disconnected")
	restore := injectRemoveFailure(t, os.ErrPermission)
	_, n, err := b.SpoolFile(io.MultiReader(bytes.NewReader([]byte("partial-bytes")), failingReader{err: boom}), 1024)
	if !errors.Is(err, boom) {
		t.Fatalf("SpoolFile = %v, want %v", err, boom)
	}
	res.Release()
	if got := b.PendingCleanup(); got != 1 {
		t.Fatalf("PendingCleanup() after failed copy = %d, want 1", got)
	}
	if used := b.Used(); used != int64(n) {
		t.Fatalf("Used() = %d, want the %d staged partial bytes kept", used, n)
	}
	if removed, perr := b.Prune(context.Background()); perr != nil || removed != 0 {
		t.Fatalf("Prune removed a cleanup-required partial spool: removed=%d err=%v", removed, perr)
	}

	restore()
	removed, err := b.RetryCleanup(context.Background())
	if err != nil || removed != 1 {
		t.Fatalf("RetryCleanup = (%d, %v), want (1, nil)", removed, err)
	}
	if used := b.Used(); used != 0 || b.PendingCleanup() != 0 {
		t.Fatalf("debt not released: Used()=%d PendingCleanup()=%d", used, b.PendingCleanup())
	}
	if entries := spoolEntries(t, dir); len(entries) != 0 {
		t.Fatalf("retry left spool entries behind: %v", entries)
	}
}

// TestCleanupSpoolAlreadyGoneReleases pins the os.ErrNotExist half of the
// contract: a file that already vanished (another process, a previous
// successful removal) counts as removed, so the reservation is released and
// no cleanup debt is armed.
func TestCleanupSpoolAlreadyGoneReleases(t *testing.T) {
	b, err := NewBudget(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	res, err := b.Acquire(context.Background(), 8)
	if err != nil {
		t.Fatal(err)
	}
	path, _, err := b.SpoolFile(bytes.NewReader([]byte("gone")), 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if ok := b.CleanupSpool(path, res); !ok {
		t.Fatal("CleanupSpool on an already-gone file reported failure")
	}
	if used := b.Used(); used != 0 {
		t.Fatalf("Used() = %d, want 0", used)
	}
	if got := b.PendingCleanup(); got != 0 {
		t.Fatalf("PendingCleanup() = %d, want 0", got)
	}
}
