package runner

import "testing"

// TestIdentityLockCreationWindowFailsClosed models the non-Unix creation
// window: process A has created runner.lock via O_EXCL but not yet published
// its PID, so competitor B reads an EMPTY (or partial/garbage) file. Doubt
// must mean LIVE — the file must never be reclaimed on that basis. The
// equivalent Windows process-level test lives in the native Windows lane.
func TestIdentityLockCreationWindowFailsClosed(t *testing.T) {
	alive := func(int) bool { return false } // nothing is alive in this model
	for _, data := range [][]byte{
		nil,              // A between O_EXCL and the PID write
		[]byte(""),       // same, zero-length
		[]byte("\n"),     // partial write
		[]byte("12"),     // partial PID (A may still be writing the rest)
		[]byte("notapi"), // garbage
		[]byte("-5"),     // malformed
	} {
		if got := classifyIdentityLock(data, alive); got != identityLockLive {
			t.Fatalf("classifyIdentityLock(%q) = stale, want LIVE (creation window / malformed)", data)
		}
	}
	// Only a positively parsed, positively dead PID is stale.
	if got := classifyIdentityLock([]byte("424242\n"), alive); got != identityLockStale {
		t.Fatalf("dead PID classified as live")
	}
	// A live PID is live.
	if got := classifyIdentityLock([]byte("7\n"), func(pid int) bool { return pid == 7 }); got != identityLockLive {
		t.Fatalf("live PID classified as stale")
	}
	// A nil liveness probe cannot prove death: doubt is LIVE.
	if got := classifyIdentityLock([]byte("7\n"), nil); got != identityLockLive {
		t.Fatalf("nil liveness probe classified as stale")
	}
}
