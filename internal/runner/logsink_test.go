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
	sink.Close(time.Second)
	if delivered.Load() != total {
		t.Fatalf("delivered = %d, want %d", delivered.Load(), total)
	}
	if sink.Dropped() != 0 {
		t.Fatalf("dropped = %d, want 0", sink.Dropped())
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
	if got := sink.Dropped(); got == 0 {
		t.Fatal("overflow was not counted")
	}
	close(release)
	sink.Close(2 * time.Second)
}

// TestAsyncLogSinkSendErrorReported proves a background delivery failure is
// surfaced (the caller fails the job) rather than swallowed.
func TestAsyncLogSinkSendErrorReported(t *testing.T) {
	sink := newAsyncLogSink(nil, func([]logLine) error { return fmt.Errorf("control plane down") })
	sink.WriteLine("job", "step", "x")
	if remaining := sink.Flush(2 * time.Second); remaining != 0 {
		t.Fatalf("remaining = %d", remaining)
	}
	sink.Close(time.Second)
	if sink.SendError() == nil {
		t.Fatal("send error not reported")
	}
}
