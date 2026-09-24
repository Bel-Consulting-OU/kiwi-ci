package staging

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestBudgetSpoolFileClosedFailsClosed is the T2-5 regression: SpoolFile is
// the budget-owned primitive, so a closed budget (ownership handed to a
// successor) must refuse to create/register a spool instead of writing into a
// directory it no longer owns.
func TestBudgetSpoolFileClosedFailsClosed(t *testing.T) {
	b, err := NewBudget(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, err := b.SpoolFile(bytes.NewReader([]byte("x")), 8); !errors.Is(err, ErrClosed) {
		t.Fatalf("SpoolFile on a closed budget = %v, want ErrClosed", err)
	}
}

// TestBudgetSequentialOwnersSpoolDiscipline is the T2-5 regression: once a
// budget closes and a successor takes the same directory, the successor owns
// new spools and the retired budget can never create one.
func TestBudgetSequentialOwnersSpoolDiscipline(t *testing.T) {
	dir := t.TempDir()
	first, err := NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	second, err := NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatalf("second NewBudget: %v", err)
	}
	defer func() { _ = second.Close() }()
	if _, _, err := first.SpoolFile(bytes.NewReader([]byte("x")), 8); !errors.Is(err, ErrClosed) {
		t.Fatalf("retired budget SpoolFile = %v, want ErrClosed", err)
	}
	path, n, err := second.SpoolFile(bytes.NewReader([]byte("owned")), 8)
	if err != nil || n != int64(len("owned")) {
		t.Fatalf("successor SpoolFile = (%q, %d, %v)", path, n, err)
	}
	if !strings.HasPrefix(path, dir+string(os.PathSeparator)) {
		t.Fatalf("successor spool %q is outside the shared directory", path)
	}
	_ = os.Remove(path)
	// A live budget is returned again for the same directory (one ledger).
	again, err := NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatalf("third NewBudget: %v", err)
	}
	if again != second {
		t.Fatal("the same directory mapped to two live budgets")
	}
}

// TestBudgetSpoolFileConcurrentClose is the -race companion: SpoolFile racing
// CloseWithContext must never panic or return an error other than ErrClosed;
// the closed check happens under the budget mutex immediately before the
// create/register.
func TestBudgetSpoolFileConcurrentClose(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				path, _, err := b.SpoolFile(bytes.NewReader([]byte("payload")), 0)
				if err == nil {
					_ = os.Remove(path)
				} else if !errors.Is(err, ErrClosed) {
					t.Errorf("SpoolFile race error = %v, want nil or ErrClosed", err)
					return
				}
			}
		}()
	}
	time.Sleep(10 * time.Millisecond)
	if err := b.CloseWithContext(context.Background()); err != nil {
		t.Fatalf("CloseWithContext: %v", err)
	}
	close(stop)
	wg.Wait()
}

// TestBudgetAcquireNoSignedOverflow is the T2-4 regression: with a large
// configured limit, the old `used+n <= maxBytes` form wrapped for a large n
// and admitted an over-budget reservation. The subtraction form must reject
// it.
func TestBudgetAcquireNoSignedOverflow(t *testing.T) {
	b, err := NewBudget(t.TempDir(), math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	// Bounded close so an overflow-induced ledger corruption fails the test
	// fast instead of hanging in Close.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = b.CloseWithContext(ctx)
	}()
	big, err := b.Acquire(context.Background(), math.MaxInt64-1)
	if err != nil {
		t.Fatalf("Acquire(MaxInt64-1): %v", err)
	}
	defer big.Release()
	// Only one byte of headroom remains: the naive used+n form would overflow
	// to a negative value and succeed. The cancelled context makes the
	// (correct) blocked wait return immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Acquire(ctx, 2); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire past the remaining headroom = %v, want context.Canceled (no overflow admission)", err)
	}
	if got := b.Used(); got != math.MaxInt64-1 {
		t.Fatalf("Used() = %d, want the over-budget request to have been refused", got)
	}
}
