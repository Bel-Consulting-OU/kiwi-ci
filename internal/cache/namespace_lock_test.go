package cache

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestNamespaceLockRejectsSecondManager pins the ownership primitive: a
// second manager over the same namespace fails with ErrCacheDirOwned while
// the first lives, and succeeds once the first releases it. (The true
// multi-PROCESS variants are the helper-process tests below.)
func TestNamespaceLockRejectsSecondManager(t *testing.T) {
	root := t.TempDir()
	m1 := mustManager(t, root, RetentionPolicy{MaxBytes: 1000})
	if _, err := NewManager(root, RetentionPolicy{MaxBytes: 1000}); !errors.Is(err, ErrCacheDirOwned) {
		t.Fatalf("second manager = %v, want ErrCacheDirOwned", err)
	}
	if res, err := m1.Reserve(context.Background(), 100); err != nil {
		t.Fatalf("first manager unusable after refusal: %v", err)
	} else {
		res.Release()
	}
	if err := m1.Close(); err != nil {
		t.Fatal(err)
	}
	m2, err := NewManager(root, RetentionPolicy{MaxBytes: 1000})
	if err != nil {
		t.Fatalf("manager after close = %v", err)
	}
	if err := m2.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestManagerClosedRefusesOperations pins the post-Close contract: released
// ownership must not leave a live ledger behind that keeps writing.
func TestManagerClosedRefusesOperations(t *testing.T) {
	root := t.TempDir()
	m := mustManager(t, root, RetentionPolicy{MaxBytes: 1000})
	res, err := m.Reserve(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
	if _, err := m.Reserve(context.Background(), 1); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("reserve after close = %v, want ErrManagerClosed", err)
	}
	if err := m.Publish(res, func() error { return nil }); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("publish after close = %v, want ErrManagerClosed", err)
	}
	if m.RetainTempCleanup(res, "p") {
		t.Fatal("retain after close accepted")
	}
	if _, _, err := m.ReclaimAbandonedTemps(context.Background()); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("reclaim after close = %v, want ErrManagerClosed", err)
	}
	if _, err := m.Prune(context.Background()); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("prune after close = %v, want ErrManagerClosed", err)
	}
	if _, err := m.RetryTempCleanup(context.Background()); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("retry temp cleanup after close = %v, want ErrManagerClosed", err)
	}
}

// cacheHelperModeEnv selects the helper-process behavior; the helper is this
// test binary re-executed with the mode set.
const cacheHelperModeEnv = "KIWI_CACHE_LOCK_HELPER"

// cacheHelperRootEnv carries the namespace root to the helper.
const cacheHelperRootEnv = "KIWI_CACHE_LOCK_ROOT"

// TestCacheNamespaceHelperProcess is not a test: it is the helper entry point
// that exercises the namespace lock from a REAL second process.
func TestCacheNamespaceHelperProcess(t *testing.T) {
	mode := os.Getenv(cacheHelperModeEnv)
	if mode == "" {
		t.Skip("helper process entry point")
	}
	root := os.Getenv(cacheHelperRootEnv)
	switch mode {
	case "hold-live-temp":
		m, err := NewManager(root, RetentionPolicy{MaxBytes: 1 << 20})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
		_ = m
		f, err := os.CreateTemp(root, ".live.tar.gz-*.tmp")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(4)
		}
		_, _ = f.WriteString("live")
		fmt.Println("READY")
		os.Stdout.Sync()
		// Hold the lock and the live temp until killed.
		select {}
	case "try-manager":
		m, err := NewManager(root, RetentionPolicy{MaxBytes: 1 << 20})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		_ = m.Close()
		fmt.Println("ACQUIRED")
	case "leave-temp-exit":
		m, err := NewManager(root, RetentionPolicy{MaxBytes: 1 << 20})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
		_ = m
		f, err := os.CreateTemp(root, ".crash.tar.gz-*.tmp")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(4)
		}
		_, _ = f.WriteString("crash-left")
		_ = f.Close()
		// Exit WITHOUT Close: the OS drops the lock, the temp stays.
		os.Exit(0)
	}
}

// startCacheHelper starts this test binary as a real second process in mode.
func startCacheHelper(t *testing.T, root, mode string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=TestCacheNamespaceHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(), cacheHelperModeEnv+"="+mode, cacheHelperRootEnv+"="+root)
	return cmd
}

// TestCacheNamespaceSecondProcessCannotReclaimLiveTemp is the critical
// multi-process mutation test: process A holds the namespace and a live
// recognized temp; process B with the same identity must fail ownership and
// must NOT delete A's temp. After A dies, B (or a later process) may reclaim
// the temp under the newly acquired lock.
func TestCacheNamespaceSecondProcessCannotReclaimLiveTemp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-exit lock release requires flock semantics")
	}
	root := t.TempDir()
	holder := startCacheHelper(t, root, "hold-live-temp")
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	holder.Stderr = &stderr
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if holder.Process != nil {
			_ = holder.Process.Kill()
			_, _ = holder.Process.Wait()
		}
	})
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "READY" {
				ready <- scanner.Text()
				return
			}
		}
		ready <- ""
	}()
	select {
	case line := <-ready:
		if line != "READY" {
			t.Fatalf("holder never became ready (stderr: %s)", stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("holder did not start (stderr: %s)", stderr.String())
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var liveTemp string
	for _, de := range entries {
		if strings.HasPrefix(de.Name(), ".live.tar.gz-") {
			liveTemp = filepath.Join(root, de.Name())
		}
	}
	if liveTemp == "" {
		t.Fatal("holder did not create its live temp")
	}
	// Second process with the same identity: must refuse ownership.
	second := startCacheHelper(t, root, "try-manager")
	out, err := second.CombinedOutput()
	if err == nil {
		t.Fatalf("second process acquired a held namespace: %s", out)
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 2 {
		t.Fatalf("second process exit = %v (%s), want the ownership refusal", err, out)
	}
	if !strings.Contains(string(out), "owned by another live process") {
		t.Fatalf("second process stderr = %s, want the ownership refusal", out)
	}
	// The critical assertion: A's live temp survived B's startup.
	if _, err := os.Stat(liveTemp); err != nil {
		t.Fatalf("second process deleted the first process's live temp: %v", err)
	}
	// Kill A; a fresh process now acquires the namespace and reclaims the
	// abandoned temp under its own lock.
	if err := holder.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = holder.Process.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for {
		third := startCacheHelper(t, root, "try-manager")
		out, err := third.CombinedOutput()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("namespace never became acquirable after the holder died: %v (%s)", err, out)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(liveTemp); !os.IsNotExist(err) {
		t.Fatalf("abandoned temp was not reclaimed under the new lock (err=%v)", err)
	}
}

// TestAbandonedTempReclaimedAfterPriorProcessExits pins crash recovery across
// real processes: the prior process leaves without releasing anything and the
// next owner reclaims its temp.
func TestAbandonedTempReclaimedAfterPriorProcessExits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-exit lock release requires flock semantics")
	}
	root := t.TempDir()
	helper := startCacheHelper(t, root, "leave-temp-exit")
	if out, err := helper.CombinedOutput(); err != nil {
		t.Fatalf("helper = %v (%s)", err, out)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, de := range entries {
		if strings.HasPrefix(de.Name(), ".crash.tar.gz-") {
			found = true
		}
	}
	if !found {
		t.Fatal("helper did not leave its temp behind")
	}
	m, err := NewManager(root, RetentionPolicy{MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("manager after helper exit = %v", err)
	}
	defer func() { _ = m.Close() }()
	for _, de := range entries {
		if strings.HasPrefix(de.Name(), ".crash.tar.gz-") {
			if _, err := os.Stat(filepath.Join(root, de.Name())); !os.IsNotExist(err) {
				t.Fatalf("abandoned temp %s not reclaimed (err=%v)", de.Name(), err)
			}
		}
	}
	if m.PendingTempCleanup() != 0 {
		t.Fatalf("pending cleanup = %d after reclaim, want 0", m.PendingTempCleanup())
	}
}

// TestNamespaceLockErrorBranches pins the lock's checked failure paths: an
// unopenable lock path (a regular file where the directory should be), the
// release-after-close unlock error, and idempotent release.
func TestNamespaceLockErrorBranches(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireNamespaceLock(filePath); err == nil {
		t.Fatal("locking a regular file path succeeded")
	}
	dir := t.TempDir()
	l, err := acquireNamespaceLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.release(); err == nil {
		t.Fatal("release after an externally closed file reported success")
	}
	var nilLock *namespaceLock
	if err := nilLock.release(); err != nil {
		t.Fatalf("nil release = %v", err)
	}
}

// TestNamespaceLockReleaseFailureCanRetry is the P2 regression: a transient
// lock-removal failure must leave the lock retryable, and a successor must be
// able to acquire the namespace once the release finally succeeds. Without
// the fix, release marked itself un-owned and the stale file recorded the
// current pid, locking the process (and its restart) out indefinitely.
func TestNamespaceLockReleaseFailureCanRetry(t *testing.T) {
	root := t.TempDir()
	m := mustManager(t, root, RetentionPolicy{MaxBytes: 1000})
	orig := releaseNamespaceLock
	releaseNamespaceLock = func(*namespaceLock) error { return errors.New("test: transient removal failure") }
	t.Cleanup(func() { releaseNamespaceLock = orig })
	if err := m.Close(); err == nil {
		t.Fatal("Close succeeded despite the injected release failure")
	}
	if m.lock == nil {
		t.Fatal("failed Close discarded the lock handle")
	}
	releaseNamespaceLock = orig
	if err := m.Close(); err != nil {
		t.Fatalf("retried Close = %v", err)
	}
	if m.lock != nil {
		t.Fatal("successful Close retained the lock handle")
	}
	// A successor (the restart case) can now own the namespace.
	m2, err := NewManager(root, RetentionPolicy{MaxBytes: 1000})
	if err != nil {
		t.Fatalf("successor manager = %v", err)
	}
	defer func() { _ = m2.Close() }()
}

// TestManagerCloseRetainsLockHandleOnReleaseFailure pins the handle contract
// and the closed-manager refusals for every mutating entry point.
func TestManagerCloseRetainsLockHandleOnReleaseFailure(t *testing.T) {
	root := t.TempDir()
	m := mustManager(t, root, RetentionPolicy{MaxBytes: 1000})
	orig := releaseNamespaceLock
	releaseNamespaceLock = func(*namespaceLock) error { return errors.New("test: transient removal failure") }
	t.Cleanup(func() { releaseNamespaceLock = orig })
	if err := m.Close(); err == nil {
		t.Fatal("Close succeeded despite the injected release failure")
	}
	if m.lock == nil {
		t.Fatal("lock handle not retained after a failed release")
	}
	if _, err := m.Reserve(context.Background(), 1); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("Reserve after failed Close = %v, want ErrManagerClosed", err)
	}
	if _, err := m.Prune(context.Background()); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("Prune after Close = %v, want ErrManagerClosed", err)
	}
	if _, err := m.RetryTempCleanup(context.Background()); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("RetryTempCleanup after Close = %v, want ErrManagerClosed", err)
	}
}

// TestRestartAfterTransientLockReleaseFailure models the runner restart:
// shutdown's release fails, the process retries and succeeds, and only then
// does a successor acquire the namespace.
func TestRestartAfterTransientLockReleaseFailure(t *testing.T) {
	root := t.TempDir()
	m := mustManager(t, root, RetentionPolicy{MaxBytes: 1000})
	orig := releaseNamespaceLock
	releaseNamespaceLock = func(*namespaceLock) error { return errors.New("test: transient removal failure") }
	t.Cleanup(func() { releaseNamespaceLock = orig })
	if err := m.Close(); err == nil {
		t.Fatal("first shutdown Close succeeded despite the injected failure")
	}
	if _, err := NewManager(root, RetentionPolicy{MaxBytes: 1000}); !errors.Is(err, ErrCacheDirOwned) {
		t.Fatalf("restart before cleanup retry = %v, want ErrCacheDirOwned", err)
	}
	releaseNamespaceLock = orig
	if err := m.Close(); err != nil {
		t.Fatalf("retried shutdown Close = %v", err)
	}
	m2, err := NewManager(root, RetentionPolicy{MaxBytes: 1000})
	if err != nil {
		t.Fatalf("restart after cleanup retry = %v", err)
	}
	defer func() { _ = m2.Close() }()
}
