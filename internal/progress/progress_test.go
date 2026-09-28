package progress

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

// TestPulseInvokesInstalledCallback pins the round trip: a pulse installed
// with WithPulse fires on every Pulse call on the same context and on any
// context derived from it.
func TestPulseInvokesInstalledCallback(t *testing.T) {
	var calls atomic.Int64
	ctx := WithPulse(context.Background(), func() { calls.Add(1) })
	Pulse(ctx)
	Pulse(ctx)
	derived, cancel := context.WithCancel(ctx)
	defer cancel()
	Pulse(derived)
	if got := calls.Load(); got != 3 {
		t.Fatalf("pulse calls = %d, want 3", got)
	}
}

// TestPulseWithoutInstallIsNoop proves a context that never went through
// WithPulse (and an untyped nil context) is safe: layers can call Pulse
// unconditionally and pay only a lookup.
func TestPulseWithoutInstallIsNoop(t *testing.T) {
	Pulse(context.Background())
	var nilCtx context.Context
	Pulse(nilCtx)
}

// TestWithPulseNilReturnsSameContext proves a nil pulse cannot install a
// callback that would panic when invoked.
func TestWithPulseNilReturnsSameContext(t *testing.T) {
	base := context.Background()
	if got := WithPulse(base, nil); got != base {
		t.Fatal("WithPulse(ctx, nil) returned a different context")
	}
}

// TestPulseConcurrent proves the callback contract is concurrency-safe from
// the package's side: concurrent Pulse calls all reach the callback (safety
// of the callback itself is the installer's responsibility).
func TestPulseConcurrent(t *testing.T) {
	var calls atomic.Int64
	ctx := WithPulse(context.Background(), func() { calls.Add(1) })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				Pulse(ctx)
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 800 {
		t.Fatalf("pulse calls = %d, want 800", got)
	}
}
