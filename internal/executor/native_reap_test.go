//go:build !windows

package executor

import (
	"context"
	"errors"
	"io"
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

// TestNativeSupervisionFailureBoundedNotSIGTERMOnly is the W4-B regression:
// when the tree supervisor cannot be attached (real on Windows where the Job
// Object assign can fail), the branch must terminate the unsupervised child,
// SIGKILL it, and reap it within the graces. A child that ignores SIGTERM and
// keeps running must not leave Run blocked in an unbounded cmd.Wait.
func TestNativeSupervisionFailureBoundedNotSIGTERMOnly(t *testing.T) {
	origAttach, origGrace := attachChildSupervision, killGrace
	killGrace = 50 * time.Millisecond
	dir := t.TempDir()
	marker := filepath.Join(dir, "trap-ready")
	attachChildSupervision = func(*exec.Cmd, *[]string) (func(), error) {
		// Wait until the child installed its SIGTERM trap, so the SIGTERM
		// below cannot land before the handler is in place.
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(marker); err == nil {
				break
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		return nil, errors.New("AssignProcessToJobObject failed")
	}
	t.Cleanup(func() { attachChildSupervision, killGrace = origAttach, origGrace })

	script := "trap '' TERM; : > " + marker + "; i=0; while [ $i -lt 10 ]; do sleep 1; i=$((i+1)); done"
	start := time.Now()
	err := (&NativeBackend{}).Run(context.Background(), Command{Shell: "bash", Script: script, Dir: dir}, func(string) {})
	elapsed := time.Since(start)

	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Kind != ErrorInfra {
		t.Fatalf("supervision failure = %v, want an ErrorInfra RunError", err)
	}
	if !strings.Contains(err.Error(), "attach child process supervision") {
		t.Fatalf("error does not name the supervision failure: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("supervision-failure branch waited %v; the SIGTERM-ignoring child was not SIGKILLed and reaped within the bound", elapsed)
	}
}

// TestNativeSupervisionFailureUnreapableBoundedAndDrains is the deterministic
// W4-B seam test: the injected wait cannot complete within killGrace, so the
// branch must still return bounded with an ErrorInfra that joins the typed
// reap timeout, must leave a detached reaper draining the eventual result,
// and must have closed the parent's stdout/stderr ends.
func TestNativeSupervisionFailureUnreapableBoundedAndDrains(t *testing.T) {
	origAttach, origWait, origDetach, origGrace := attachChildSupervision, waitKilledReap, reapDetached, killGrace
	killGrace = 50 * time.Millisecond
	var captured *exec.Cmd
	attachChildSupervision = func(cmd *exec.Cmd, _ *[]string) (func(), error) {
		captured = cmd
		return nil, errors.New("AssignProcessToJobObject failed")
	}
	released := make(chan struct{})
	waitEntered := make(chan struct{})
	waitKilledReap = func(cmd *exec.Cmd) error {
		close(waitEntered)
		<-released
		return cmd.Wait()
	}
	drained := make(chan error, 1)
	reapDetached = func(done <-chan error) {
		go func() { drained <- <-done }()
	}
	t.Cleanup(func() {
		attachChildSupervision, waitKilledReap, reapDetached, killGrace = origAttach, origWait, origDetach, origGrace
	})

	start := time.Now()
	err := (&NativeBackend{}).Run(context.Background(), Command{Shell: "bash", Script: "sleep 30", Dir: t.TempDir()}, func(string) {})
	elapsed := time.Since(start)

	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Kind != ErrorInfra {
		t.Fatalf("un-reapable supervision failure = %v, want an ErrorInfra RunError", err)
	}
	if !strings.Contains(err.Error(), "attach child process supervision") {
		t.Fatalf("error does not name the supervision failure: %v", err)
	}
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("error does not join the typed reap timeout: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("un-reapable supervision failure took %v; the reap wait was not bounded", elapsed)
	}
	if captured == nil {
		t.Fatal("supervision seam did not receive the command")
	}
	// The parent's stdout/stderr write ends are closed after the failure, so
	// no pipe descriptor is left dangling.
	for name, w := range map[string]io.Writer{"stdout": captured.Stdout, "stderr": captured.Stderr} {
		f, ok := w.(*os.File)
		if !ok {
			t.Fatalf("%s is %T, want *os.File", name, w)
		}
		if _, werr := f.Write([]byte("x")); !errors.Is(werr, os.ErrClosed) {
			t.Fatalf("%s pipe was not closed after the supervision failure: %v", name, werr)
		}
	}
	select {
	case <-waitEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("the branch never reaped the killed child through the bounded primitive")
	}
	// The process is finally reaped: the detached reaper must drain it.
	close(released)
	select {
	case werr := <-drained:
		if werr == nil {
			t.Fatal("detached reaper received a nil wait result for a SIGKILLed child")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("detached reaper did not drain the wait result")
	}
}
