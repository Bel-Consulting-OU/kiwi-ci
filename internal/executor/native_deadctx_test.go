package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNativeRunRefusesAlreadyCanceledContext is the pre-spawn boundary
// oracle: NativeBackend uses exec.Command (not CommandContext), so before
// this gate an already-dead context still SPAWNED the shell — its first
// command raced the kill path. A cancelled() cleanup dispatched after
// runner shutdown must never execute user code; the single-P lifecycle
// oracle (TestRunnerShutdownDoesNotWaitCleanupTimeout under GOMAXPROCS=1)
// reproduced that race reliably and this unit pins the boundary
// deterministically on any scheduler.
func TestNativeRunRefusesAlreadyCanceledContext(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran.txt")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := &NativeBackend{}
	err := b.Run(ctx, Command{
		Shell:  "sh",
		Script: "echo ran > '" + marker + "'",
		Dir:    t.TempDir(),
		Env:    os.Environ(),
	}, func(string) {})
	if err == nil {
		t.Fatal("Run under a canceled context must fail, not succeed")
	}
	if kind := errorKind(err); kind != ErrorCancelled {
		t.Fatalf("error kind = %q, want %q (err=%v)", kind, ErrorCancelled, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error must wrap context.Canceled: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("user code executed under a canceled context — the shell was spawned before any kill")
	} else if !os.IsNotExist(statErr) {
		t.Fatalf("marker stat: %v", statErr)
	}

	// An already-EXPIRED deadline refuses the same way (kind timeout),
	// still without spawning. No explicit cancel here: the deadline alone
	// must be what the gate observes (Err() == DeadlineExceeded).
	marker2 := filepath.Join(t.TempDir(), "ran2.txt")
	dctx, dcancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dcancel()
	err = b.Run(dctx, Command{
		Shell:  "sh",
		Script: "echo ran > '" + marker2 + "'",
		Dir:    t.TempDir(),
		Env:    os.Environ(),
	}, func(string) {})
	if err == nil || errorKind(err) != ErrorTimeout {
		t.Fatalf("expired deadline: err=%v kind=%q, want ErrorTimeout", err, errorKind(err))
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error must wrap context.DeadlineExceeded: %v", err)
	}
	if _, statErr := os.Stat(marker2); statErr == nil {
		t.Fatal("user code executed under an expired deadline context")
	}
}
