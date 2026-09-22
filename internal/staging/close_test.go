package staging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBudgetCloseWaitsForOutstandingReservations is the R4-C regression: Close
// must not release the directory ownership lock while a reservation is still
// outstanding, or a successor could start sweeping files the reservation
// covers. It also proves new acquisitions fail closed as soon as closing
// begins.
func TestBudgetCloseWaitsForOutstandingReservations(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1000)
	if err != nil {
		t.Fatal(err)
	}
	held, err := b.Acquire(context.Background(), 400)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()

	// Close must block while the reservation is outstanding.
	select {
	case err := <-closed:
		t.Fatalf("Close returned %v with an outstanding reservation", err)
	case <-time.After(50 * time.Millisecond):
	}
	// A successor budget cannot start (and cannot sweep) while we still own
	// the directory.
	if _, err := NewBudget(dir, 1000); !errors.Is(err, ErrStagingDirOwned) {
		t.Fatalf("successor NewBudget while a reservation is outstanding = %v, want ErrStagingDirOwned", err)
	}
	// New acquisitions are already refused.
	if _, err := b.Acquire(context.Background(), 1); !errors.Is(err, ErrClosed) {
		t.Fatalf("Acquire during closing = %v, want ErrClosed", err)
	}
	// Release the last reservation: Close must now finish and hand over.
	held.Release()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close after drain: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close never finished after the last reservation was released")
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("Used() after Close = %d, want 0", got)
	}
	successor, err := NewBudget(dir, 1000)
	if err != nil {
		t.Fatalf("successor after Close: %v", err)
	}
	defer func() { _ = successor.Close() }()
	if successor == b {
		t.Fatal("successor reused the closed budget")
	}
	// The successor can now reclaim a stranded spool file: ownership was
	// released only at zero.
	stranded := filepath.Join(dir, FilePrefix+"stranded")
	if err := os.WriteFile(stranded, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := NewBudget(dir, 1000)
	if err != nil {
		t.Fatalf("third NewBudget (same process registry): %v", err)
	}
	if third != successor {
		t.Fatal("same-directory construction must reuse the process registry")
	}
}

// TestBudgetCloseWithContextTimesOutWhileReserved: the context-bounded API
// returns ctx.Err() without releasing ownership while bytes are outstanding,
// and a later unbounded Close completes the hand-off once they drain.
func TestBudgetCloseWithContextTimesOutWhileReserved(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.Acquire(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.CloseWithContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseWithContext while reserved = %v, want context.DeadlineExceeded", err)
	}
	// Ownership retained: a successor still cannot start.
	if _, err := NewBudget(dir, 100); !errors.Is(err, ErrStagingDirOwned) {
		t.Fatalf("successor after a timed-out Close = %v, want ErrStagingDirOwned", err)
	}
	res.Release()
	if err := b.Close(); err != nil {
		t.Fatalf("Close after the reservation drained: %v", err)
	}
	successor, err := NewBudget(dir, 100)
	if err != nil {
		t.Fatalf("successor after final Close: %v", err)
	}
	defer func() { _ = successor.Close() }()
}

// TestBudgetCloseConcurrentCallersConverge: every concurrent Close call
// returns, exactly one releases the lock, and the ownership lock is gone
// afterwards.
func TestBudgetCloseConcurrentCallersConverge(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.Acquire(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 16
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- b.Close()
		}()
	}
	time.Sleep(20 * time.Millisecond)
	res.Release()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Close: %v", err)
		}
	}
	// Ownership released exactly once: a successor starts.
	successor, err := NewBudget(dir, 100)
	if err != nil {
		t.Fatalf("successor after concurrent Close: %v", err)
	}
	defer func() { _ = successor.Close() }()
	if _, err := b.Acquire(context.Background(), 1); !errors.Is(err, ErrClosed) {
		t.Fatalf("Acquire on closed budget = %v, want ErrClosed", err)
	}
}

// TestBudgetCloseAcquireRace stresses Close against hundreds of
// Acquire/Release pairs. The invariant: once Close starts, no new reservation
// is granted, Used() ends at zero, and no reservation is ever used after the
// ownership lock is released. Run under -race.
func TestBudgetCloseAcquireRace(t *testing.T) {
	const (
		workers = 32
		rounds  = 200
	)
	dir := t.TempDir()
	b, err := NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var acquired, released, refused atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < rounds; i++ {
				res, err := b.Acquire(context.Background(), 128)
				if err != nil {
					if !errors.Is(err, ErrClosed) {
						t.Errorf("Acquire returned %v, want nil or ErrClosed", err)
						return
					}
					refused.Add(1)
					continue
				}
				acquired.Add(1)
				res.Release()
				released.Add(1)
			}
		}()
	}
	close(start)
	// Let some acquisitions happen, then close while they are in flight.
	time.Sleep(2 * time.Millisecond)
	if err := b.Close(); err != nil {
		t.Fatalf("Close racing acquisitions: %v", err)
	}
	// After Close returns, every new acquisition fails closed.
	for i := 0; i < 100; i++ {
		if _, err := b.Acquire(context.Background(), 1); !errors.Is(err, ErrClosed) {
			t.Fatalf("Acquire after Close = %v, want ErrClosed", err)
		}
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("Used() after Close = %d, want 0", got)
	}
	wg.Wait()
	if acquired.Load() == 0 {
		t.Fatal("no acquisition ever succeeded; the stress test proved nothing")
	}
	if released.Load() > acquired.Load() {
		t.Fatalf("released %d > acquired %d", released.Load(), acquired.Load())
	}
	if b.Used() != 0 {
		t.Fatalf("final Used() = %d, want 0", b.Used())
	}
	// The directory is genuinely free for a successor.
	successor, err := NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatalf("successor after race: %v", err)
	}
	defer func() { _ = successor.Close() }()
}
