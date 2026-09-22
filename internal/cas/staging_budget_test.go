package cas

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// gatedSource yields the in-memory-busting first chunk immediately (so Put
// crosses the in-memory bound and enters the spool path), then blocks on
// release before yielding the remainder. It lets a test hold a fallback spool
// in flight and observe the staging budget.
type gatedSource struct {
	first   []byte
	rest    []byte
	started chan struct{}
	release chan struct{}
	stage   int32

	releaseOnce sync.Once
}

func (g *gatedSource) Read(p []byte) (int, error) {
	switch atomic.LoadInt32(&g.stage) {
	case 0:
		atomic.StoreInt32(&g.stage, 1)
		return copy(p, g.first), nil
	case 1:
		close(g.started)
		<-g.release
		atomic.StoreInt32(&g.stage, 2)
	}
	if len(g.rest) == 0 {
		return 0, io.EOF
	}
	n := copy(p, g.rest)
	g.rest = g.rest[n:]
	return n, nil
}

// Release unblocks the gated read exactly once, so a test failure can never
// leave a Put goroutine parked forever.
func (g *gatedSource) Release() { g.releaseOnce.Do(func() { close(g.release) }) }

func newGatedSource(first, rest int, b byte) *gatedSource {
	return &gatedSource{
		first:   bytes.Repeat([]byte{b}, first),
		rest:    bytes.Repeat([]byte{b}, rest),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

// stagingLeftovers lists the package's spool files still present in dir.
func stagingLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), staging.FilePrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestCASPutAccountsInFlightStagingReservation proves the fallback Put
// reserves the worst-case disk amount with the staging budget BEFORE it
// spools: an in-flight spool is visible in Budget.Used() and the reservation
// is released once the publication is done.
func TestCASPutAccountsInFlightStagingReservation(t *testing.T) {
	const limit = 4096
	b, err := staging.NewBudget(t.TempDir(), limit)
	if err != nil {
		t.Fatalf("staging budget: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	c := New(blob.NewFS(t.TempDir()))
	c.MaxBlobBytes = limit
	c.PutMemoryBytes = 16
	c.Staging = b

	src := newGatedSource(17, 100, 'a')
	t.Cleanup(src.Release)
	done := make(chan error, 1)
	go func() {
		_, perr := c.Put(context.Background(), src)
		done <- perr
	}()
	select {
	case <-src.started:
	case <-time.After(5 * time.Second):
		t.Fatal("Put never reached the spool stage")
	}
	if got := b.Used(); got != limit {
		t.Fatalf("in-flight fallback spool Used() = %d, want the reserved worst case %d", got, limit)
	}
	src.Release()
	if err := <-done; err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("reservation leaked after Put: Used() = %d", got)
	}
	if leftovers := stagingLeftovers(t, b.Dir()); len(leftovers) != 0 {
		t.Fatalf("spool files survived publication: %v", leftovers)
	}
}

// TestCASPutStagingBudgetExceededIsTyped proves a per-object bound larger than
// the whole staging budget fails closed with the documented typed error
// before any byte is spooled, and releases nothing.
func TestCASPutStagingBudgetExceededIsTyped(t *testing.T) {
	const limit = 4096
	b, err := staging.NewBudget(t.TempDir(), limit-1)
	if err != nil {
		t.Fatalf("staging budget: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	c := New(blob.NewFS(t.TempDir()))
	c.MaxBlobBytes = limit
	c.PutMemoryBytes = 16
	c.Staging = b

	if _, err := c.Put(context.Background(), bytes.NewReader(bytes.Repeat([]byte("x"), 64))); !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("oversized staging reservation = %v, want ErrBlobTooLarge", err)
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("refused Put reserved %d bytes", got)
	}
	if leftovers := stagingLeftovers(t, b.Dir()); len(leftovers) != 0 {
		t.Fatalf("refused Put staged files: %v", leftovers)
	}
}

// TestCASPutNoStagingFailsClosed proves the nil-budget path still fails closed
// with ErrNoSpool: the fallback never silently spools into an unbounded temp
// directory, with or without the new reservation logic.
func TestCASPutNoStagingFailsClosed(t *testing.T) {
	c := New(blob.NewFS(t.TempDir()))
	c.PutMemoryBytes = 16
	if _, err := c.Put(context.Background(), bytes.NewReader(bytes.Repeat([]byte("x"), 64))); !errors.Is(err, ErrNoSpool) {
		t.Fatalf("oversized Put without a budget = %v, want ErrNoSpool", err)
	}
}

// TestCASPutConcurrentFallbackRespectsBudget proves concurrent fallback Puts
// cannot exceed the staging budget: with a budget equal to the per-object
// bound only one spool can be in flight at a time, every Put still succeeds
// once the budget frees up, and the ledger returns to zero.
func TestCASPutConcurrentFallbackRespectsBudget(t *testing.T) {
	const limit = 1 << 20
	b, err := staging.NewBudget(t.TempDir(), limit)
	if err != nil {
		t.Fatalf("staging budget: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	c := New(blob.NewFS(t.TempDir()))
	c.MaxBlobBytes = limit
	c.PutMemoryBytes = 16
	c.Staging = b

	const n = 4
	srcs := make([]*gatedSource, n)
	for i := range srcs {
		srcs[i] = newGatedSource(17, 100, byte('a'+i))
		t.Cleanup(srcs[i].Release)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range srcs {
		wg.Add(1)
		go func(s *gatedSource) {
			defer wg.Done()
			_, perr := c.Put(ctx, s)
			errs <- perr
		}(srcs[i])
	}

	// Wait until one spool holds the whole budget. Because a reservation is
	// the full per-object bound and the budget is exactly that bound, the
	// other callers must be parked in Acquire.
	deadline := time.Now().Add(5 * time.Second)
	for b.Used() != limit {
		if time.Now().After(deadline) {
			t.Fatalf("no spool ever held the budget: Used() = %d, want %d", b.Used(), limit)
		}
		time.Sleep(time.Millisecond)
	}
	// The holder may not have reached its gated second read yet; wait for it
	// while it keeps the reservation (the test holds the only release).
	for {
		inFlight := 0
		for _, s := range srcs {
			select {
			case <-s.started:
				inFlight++
			default:
			}
		}
		if inFlight > 0 {
			if inFlight != 1 {
				t.Fatalf("concurrent spools in flight = %d, want exactly 1 while the budget is fully reserved", inFlight)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the budget holder never reached the spool stage")
		}
		time.Sleep(time.Millisecond)
	}
	if got := b.Used(); got > b.MaxBytes() {
		t.Fatalf("in-flight reservations %d exceed the budget %d", got, b.MaxBytes())
	}

	// Release every gate: the parked Acquires then proceed one at a time.
	for _, s := range srcs {
		s.Release()
	}
	wg.Wait()
	close(errs)
	for perr := range errs {
		if perr != nil {
			t.Fatalf("concurrent Put: %v", perr)
		}
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("reservations leaked after concurrent Puts: Used() = %d", got)
	}
}
