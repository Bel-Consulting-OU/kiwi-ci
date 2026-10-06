package app

import (
	"context"
	"testing"
	"time"
)

// TestServerIdleGuardStaleCallbackCannotCancelProgressedStream is the
// deterministic stale-callback regression for the server streaming guard:
// a callback that was already dispatched when progress arrived must re-arm
// instead of cancelling; only a window with no progress cancels.
func TestServerIdleGuardStaleCallbackCannotCancelProgressedStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := newIdleGuard(cancel, 50*time.Millisecond)
	defer g.release()

	g.reset()        // real progress (updates `last`)
	g.onIdle(cancel) // the stale callback resumes after losing the race
	if ctx.Err() != nil {
		t.Fatal("stale idle callback cancelled a progressed stream")
	}
	// Backdate the progress instant: a genuinely idle window still cancels.
	g.mu.Lock()
	g.last = time.Now().Add(-time.Second)
	g.mu.Unlock()
	g.onIdle(cancel)
	if ctx.Err() == nil {
		t.Fatal("guard did not cancel after a full idle window without progress")
	}
}
