package runner

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAsyncLogSinkNeverBlocksProducerAndFlushesAll proves the decoupling:
// a slow control plane cannot stall the pipe-side producer, and Flush
// delivers every line before completion.
func TestAsyncLogSinkNeverBlocksProducerAndFlushesAll(t *testing.T) {
	var delivered atomic.Int64
	var mu sync.Mutex
	seen := map[string]bool{}
	sink := newAsyncLogSink(nil, func(lines []logLine) error {
		time.Sleep(5 * time.Millisecond) // slow endpoint
		mu.Lock()
		for _, l := range lines {
			seen[l.Line] = true
		}
		mu.Unlock()
		delivered.Add(int64(len(lines)))
		return nil
	})
	const total = 4000
	start := time.Now()
	for i := 0; i < total; i++ {
		sink.WriteLine("job", "step", fmt.Sprintf("line-%d", i))
	}
	enqueue := time.Since(start)
	if enqueue > 2*time.Second {
		t.Fatalf("producer blocked on a slow endpoint: enqueueing %d lines took %v", total, enqueue)
	}
	if remaining := sink.Flush(30 * time.Second); remaining != 0 {
		t.Fatalf("flush left %d unsent lines", remaining)
	}
	sink.Finish(time.Second)
	if delivered.Load() != total {
		t.Fatalf("delivered = %d, want %d", delivered.Load(), total)
	}
	if sink.dropped.Load() != 0 {
		t.Fatalf("dropped = %d, want 0", sink.dropped.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < total; i++ {
		if !seen[fmt.Sprintf("line-%d", i)] {
			t.Fatalf("line %d never delivered", i)
		}
	}
}

// TestAsyncLogSinkOverflowIsCounted proves overflow is explicit: when the
// bounded spool fills because delivery is stalled, the excess is counted
// (surfaced as a failed job by the caller) instead of blocking the drain
// forever or vanishing silently.
func TestAsyncLogSinkOverflowIsCounted(t *testing.T) {
	oldLimit := asyncSpoolLimit
	asyncSpoolLimit = 16
	t.Cleanup(func() { asyncSpoolLimit = oldLimit })

	release := make(chan struct{})
	sink := newAsyncLogSink(nil, func([]logLine) error {
		<-release // stall delivery entirely
		return nil
	})
	for i := 0; i < 100; i++ {
		sink.WriteLine("job", "step", fmt.Sprintf("line-%d", i))
	}
	// The producer must not have blocked; overflow is counted, not queued.
	if got := sink.dropped.Load(); got == 0 {
		t.Fatal("overflow was not counted")
	}
	close(release)
	sink.Finish(2 * time.Second)
}

// TestAsyncLogSinkSendErrorReported proves a background delivery failure is
// surfaced (the caller fails the job) rather than swallowed.
func TestAsyncLogSinkSendErrorReported(t *testing.T) {
	sink := newAsyncLogSink(nil, func([]logLine) error { return fmt.Errorf("control plane down") })
	sink.WriteLine("job", "step", "x")
	out := sink.Finish(2 * time.Second)
	if out.Err == nil {
		t.Fatal("send error not reported")
	}
	if out.Remaining != 0 {
		t.Fatalf("remaining = %d, want 0", out.Remaining)
	}
	if !out.Stopped {
		t.Fatal("sender did not stop within the deadline")
	}
}

// TestAsyncLogSinkByteBudgetBoundsMemory proves the spool is bounded in
// BYTES, not just line count: with a tiny byte budget a handful of large
// lines must overflow and be counted instead of retaining ~100 GiB.
func TestAsyncLogSinkByteBudgetBoundsMemory(t *testing.T) {
	oldBytes, oldLines := asyncSpoolBytes, asyncSpoolLimit
	asyncSpoolBytes, asyncSpoolLimit = 4<<10, 1_000_000
	t.Cleanup(func() { asyncSpoolBytes, asyncSpoolLimit = oldBytes, oldLines })

	release := make(chan struct{})
	sink := newAsyncLogSink(nil, func([]logLine) error {
		<-release
		return nil
	})
	big := string(make([]byte, 1024)) // 1 KiB line
	for i := 0; i < 50; i++ {
		sink.WriteLine("job", "step", big)
	}
	if got := sink.dropped.Load(); got == 0 {
		t.Fatal("byte budget did not bound the spool")
	}
	close(release)
	out := sink.Finish(3 * time.Second)
	if out.Err != nil {
		t.Fatalf("unexpected sender error: %v", out.Err)
	}
}

// TestAsyncLogSinkInFlightCountsTowardFlush proves Flush does not report
// success while the final batch is still in flight and failing.
func TestAsyncLogSinkInFlightCountsTowardFlush(t *testing.T) {
	proceed := make(chan struct{})
	var calls atomic.Int64
	sink := newAsyncLogSink(nil, func([]logLine) error {
		calls.Add(1)
		<-proceed // hold the batch in flight
		return fmt.Errorf("delivery down")
	})
	sink.WriteLine("job", "step", "line-1")
	// Wait until the sender has taken the batch (in flight).
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("sender never picked up the batch")
	}
	// Flush with a short deadline must NOT claim success while in flight.
	if pending := sink.Flush(20 * time.Millisecond); pending == 0 {
		t.Fatal("flush reported success while a batch was still in flight")
	}
	close(proceed)
	out := sink.Finish(3 * time.Second)
	if out.Err == nil {
		t.Fatal("in-flight failure was not surfaced after the sender stopped")
	}
}
