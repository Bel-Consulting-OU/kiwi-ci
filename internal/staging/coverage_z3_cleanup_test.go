package staging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestRetryCleanupErrorCancelClampAndNilReceiver pins the cleanup-debt
// convergence edges: a nil receiver is a no-op, cancellation stops the pass
// with the context error, an unremovable file keeps its debt charged and
// reports the removal error, and a successful reclaim clamps the debt ledger
// instead of going negative.
func TestRetryCleanupErrorCancelClampAndNilReceiver(t *testing.T) {
	ctx := context.Background()

	var nilB *Budget
	if n, err := nilB.RetryCleanup(ctx); n != 0 || err != nil {
		t.Fatalf("nil RetryCleanup = (%d, %v), want (0, nil)", n, err)
	}
	if n := nilB.PendingCleanup(); n != 0 {
		t.Fatalf("nil PendingCleanup = %d", n)
	}

	b, err := NewBudget(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	res, err := b.Acquire(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !nilB.CleanupSpool("nonexistent", res) {
		t.Fatal("nil-receiver CleanupSpool did not release the reservation")
	}
	if b.Used() != 0 {
		t.Fatalf("nil-receiver cleanup left %d bytes charged", b.Used())
	}

	// An unremovable "spool" (a non-empty directory is root-proof) keeps its
	// charge and is reported, and cancellation stops the pass with ctx.Err.
	blocked := filepath.Join(t.TempDir(), "blocked-spool")
	if err := os.MkdirAll(filepath.Join(blocked, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	if b.pendingCleanup == nil {
		b.pendingCleanup = map[string]int64{}
	}
	if b.activeSpools == nil {
		b.activeSpools = map[string]struct{}{}
	}
	b.pendingCleanup[blocked] = 9
	b.pendingBytes = 4 // deliberately less than the debt: the reclaim must clamp
	b.activeSpools[blocked] = struct{}{}
	b.mu.Unlock()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if n, cerr := b.RetryCleanup(canceled); n != 0 || !errors.Is(cerr, context.Canceled) {
		t.Fatalf("canceled RetryCleanup = (%d, %v), want (0, context.Canceled)", n, cerr)
	}
	if n, rerr := b.RetryCleanup(ctx); n != 0 || rerr == nil {
		t.Fatalf("unremovable spool retry = (%d, %v), want an error and no reclaim", n, rerr)
	}
	if b.PendingCleanup() != 1 {
		t.Fatalf("debt after a failed retry = %d, want 1", b.PendingCleanup())
	}
	if err := os.RemoveAll(blocked); err != nil {
		t.Fatal(err)
	}
	if n, rerr := b.RetryCleanup(ctx); n != 1 || rerr != nil {
		t.Fatalf("recovery retry = (%d, %v), want (1, nil)", n, rerr)
	}
	b.mu.Lock()
	debt := b.pendingBytes
	b.mu.Unlock()
	if debt != 0 {
		t.Fatalf("pending bytes = %d, want the clamp at 0", debt)
	}
}

// TestForgetMissingSpoolsSweepSettlesDebt covers the periodic reconcile: once
// the spool-registration counter crosses its sweep interval, active entries
// whose file vanished are dropped together with any cleanup debt charged for
// them.
func TestForgetMissingSpoolsSweepSettlesDebt(t *testing.T) {
	b, err := NewBudget(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	missing := filepath.Join(b.Dir(), FilePrefix+"vanished")
	b.mu.Lock()
	if b.pendingCleanup == nil {
		b.pendingCleanup = map[string]int64{}
	}
	if b.activeSpools == nil {
		b.activeSpools = map[string]struct{}{}
	}
	b.activeSpools[missing] = struct{}{}
	b.pendingCleanup[missing] = 12
	b.pendingBytes = 12
	b.spoolTracked = spoolSweepEvery - 1
	b.mu.Unlock()

	f, _, err := b.beginSpool()
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(name)

	b.mu.Lock()
	_, stillActive := b.activeSpools[missing]
	_, stillCharged := b.pendingCleanup[missing]
	debt := b.pendingBytes
	b.mu.Unlock()
	if stillActive || stillCharged {
		t.Fatalf("vanished spool survived the sweep: active=%v charged=%v", stillActive, stillCharged)
	}
	if debt != 0 {
		t.Fatalf("cleanup debt after the sweep = %d, want 0", debt)
	}
}
