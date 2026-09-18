package cas

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMemFencerMutualExclusionSurvivesEviction is the regression for the
// table-reset bug: holding digest A, pushing the key count far past the
// eviction threshold, and evicting idle entries must NEVER allow a second
// entrant for A while the first holder is inside its critical section.
func TestMemFencerMutualExclusionSurvivesEviction(t *testing.T) {
	f := NewMemFencer()
	f.maxKeys = 8 // tiny threshold so eviction runs during the test

	releaseA, err := f.Acquire(context.Background(), "digest-A")
	if err != nil {
		t.Fatal(err)
	}
	// Verify B is blocked while A is held.
	var bEntered atomic.Bool
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		rb, err := f.Acquire(context.Background(), "digest-A")
		if err != nil {
			return
		}
		bEntered.Store(true)
		rb()
	}()
	time.Sleep(50 * time.Millisecond)
	if bEntered.Load() {
		t.Fatal("second entrant acquired a held fence")
	}

	// Churn more than the threshold of other digests, forcing evictions.
	for i := 0; i < 200; i++ {
		r, err := f.Acquire(context.Background(), "other-"+string(rune('a'+i%26))+string(rune('0'+i%10))+string(rune('0'+i/10)))
		if err != nil {
			t.Fatal(err)
		}
		r()
	}
	// A is still held: B must still be blocked.
	time.Sleep(50 * time.Millisecond)
	if bEntered.Load() {
		t.Fatal("fence for a held digest was evicted and re-created concurrently")
	}
	releaseA()
	select {
	case <-bDone:
	case <-time.After(2 * time.Second):
		t.Fatal("waiter never proceeded after release")
	}
	if !bEntered.Load() {
		t.Fatal("waiter did not enter after release")
	}
}

// TestMemFencerWithinSameDigestSerializes proves the fence still excludes
// within one digest under concurrency.
func TestMemFencerWithinSameDigestSerializes(t *testing.T) {
	f := NewMemFencer()
	var inside, maxInside atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = f.WithFence(context.Background(), "d", func() error {
				cur := inside.Add(1)
				for {
					old := maxInside.Load()
					if cur <= old || maxInside.CompareAndSwap(old, cur) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				inside.Add(-1)
				return nil
			})
		}()
	}
	wg.Wait()
	if maxInside.Load() != 1 {
		t.Fatalf("max concurrent holders = %d, want 1", maxInside.Load())
	}
}

// TestMemFencerWaiterCancellationIsClean proves a cancelled waiter removes
// its reference and a later acquirer still gets the fence (no pinned entry,
// no lost wakeup).
func TestMemFencerWaiterCancellationIsClean(t *testing.T) {
	f := NewMemFencer()
	release, err := f.Acquire(context.Background(), "d")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() {
		_, werr := f.Acquire(ctx, "d")
		waiting <- werr
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case werr := <-waiting:
		if werr == nil {
			t.Fatal("cancelled waiter must not acquire")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter never returned (non-cancellable wait)")
	}
	release()
	// The entry must still be usable and acquirable after the cancellation.
	r2, err := f.Acquire(context.Background(), "d")
	if err != nil {
		t.Fatalf("post-cancel acquire: %v", err)
	}
	r2()
}
