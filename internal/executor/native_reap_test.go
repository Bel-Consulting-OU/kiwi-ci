//go:build !windows

package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNativeUnreapableProcessBoundedInfraAndDrains is the Y2-C core. The
// injected wait seam makes cmd.Wait block past SIGKILL (a real process wedged
// in an uninterruptible kernel wait cannot be fabricated portably): the
// backend must still return within the bounded graces with an ErrorInfra
// naming the reap failure, must mark the workspace as requiring cleanup
// before reuse, and must leave a detached reaper that drains the wait result
// once the process is finally reaped (no zombie, no blocked goroutine).
func TestNativeUnreapableProcessBoundedInfraAndDrains(t *testing.T) {
	origWait, origTerm, origKill, origDrain := nativeWait, nativeTermGrace, killGrace, reapDetached
	nativeTermGrace = 30 * time.Millisecond
	killGrace = 30 * time.Millisecond
	released := make(chan struct{})
	waitReturned := make(chan struct{})
	nativeWait = func(cmd *exec.Cmd) error {
		<-released
		err := cmd.Wait()
		close(waitReturned)
		return err
	}
	drained := make(chan error, 1)
	reapDetached = func(wait <-chan error) {
		go func() { drained <- <-wait }()
	}
	t.Cleanup(func() {
		nativeWait, nativeTermGrace, killGrace, reapDetached = origWait, origTerm, origKill, origDrain
	})

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	// The child ignores SIGTERM (and inherits the ignored disposition into
	// sleep), so only SIGKILL ends it.
	err := (&NativeBackend{}).Run(ctx, Command{Shell: "bash", Script: "trap '' TERM; sleep 30", Dir: dir}, func(string) {})
	elapsed := time.Since(start)

	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Kind != ErrorInfra {
		t.Fatalf("unreapable process error = %v, want an ErrorInfra RunError", err)
	}
	if !strings.Contains(err.Error(), "process could not be reaped after SIGKILL") {
		t.Fatalf("error does not name the reap failure: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("unreapable path took %v; the final reap was unbounded", elapsed)
	}
	if _, statErr := os.Stat(filepath.Join(dir, nativeCleanupMarker)); statErr != nil {
		t.Fatalf("workspace was not marked as requiring cleanup: %v", statErr)
	}
	// The marked workspace fails closed before another command can run in it.
	reuseErr := (&NativeBackend{}).Run(context.Background(), Command{Shell: "bash", Script: "true", Dir: dir}, func(string) {})
	if reuseErr == nil || !strings.Contains(reuseErr.Error(), "requires cleanup before reuse") {
		t.Fatalf("marked workspace reuse = %v, want a fail-closed refusal", reuseErr)
	}

	// The process is finally reaped: the detached reaper must drain the wait
	// result (proving the goroutine is not leaked with a blocked send).
	close(released)
	select {
	case werr := <-drained:
		if werr == nil {
			t.Fatal("detached reaper received a nil wait result; the SIGKILLed process should report an error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("detached reaper did not drain the wait result")
	}
	select {
	case <-waitReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("the reaper goroutine never observed the process exit")
	}
}

// TestNativeCancelledCommandReapedWithinGraces proves the normal cancellation
// path is unchanged: a command that dies on SIGTERM is reaped before any
// escalation, reports the cancelled kind, and leaves no cleanup marker.
func TestNativeCancelledCommandReapedWithinGraces(t *testing.T) {
	origTerm, origKill := nativeTermGrace, killGrace
	nativeTermGrace = 2 * time.Second
	killGrace = 2 * time.Second
	t.Cleanup(func() { nativeTermGrace, killGrace = origTerm, origKill })

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	err := (&NativeBackend{}).Run(ctx, Command{Shell: "bash", Script: "sleep 30", Dir: dir}, func(string) {})
	if err == nil || errorKind(err) != ErrorCancelled {
		t.Fatalf("gracefully terminated command = %v, want ErrorCancelled", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, nativeCleanupMarker)); !os.IsNotExist(statErr) {
		t.Fatalf("normal cancellation left a cleanup marker: %v", statErr)
	}
}
