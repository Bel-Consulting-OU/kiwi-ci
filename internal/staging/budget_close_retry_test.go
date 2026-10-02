package staging

// Ownership-release state machine regressions: Budget.Close must not
// finalize, unregister or signal completion until the directory lock is
// actually released. A transient release failure leaves the budget CLOSING,
// registered and retryable, and only a successful retry hands the directory
// to a successor.

import (
	"errors"
	"testing"
)

func TestBudgetCloseLockRemovalFailureIsRetryable(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1024)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	prev := releaseOwnershipLock
	failures := 0
	releaseOwnershipLock = func(l *dirLock) error {
		if failures == 0 {
			failures++
			return errors.New("EPERM injected")
		}
		return prev(l)
	}
	t.Cleanup(func() { releaseOwnershipLock = prev })

	if err := b.Close(); err == nil {
		t.Fatal("first Close = nil, want the injected release failure")
	}
	if err := b.Close(); err != nil {
		t.Fatalf("retrying Close = %v, want success after the transient failure", err)
	}
	successor, err := NewBudget(dir, 1024)
	if err != nil {
		t.Fatalf("successor NewBudget: %v", err)
	}
	if err := successor.Close(); err != nil {
		t.Fatalf("successor Close: %v", err)
	}
}

func TestBudgetCloseFailureRetainsProcessRegistryOwnership(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1024)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	prev := releaseOwnershipLock
	releaseOwnershipLock = func(*dirLock) error { return errors.New("EPERM injected") }
	t.Cleanup(func() { releaseOwnershipLock = prev })

	if err := b.Close(); err == nil {
		t.Fatal("Close = nil, want the injected release failure")
	}
	ownedDirsMu.Lock()
	registered := ownedDirs[b.registryKey] == b
	ownedDirsMu.Unlock()
	if !registered {
		t.Fatal("failed Close unregistered the budget while the directory may still be owned")
	}
	// A same-process successor must not take the directory while the lock is
	// still held.
	if _, err := NewBudget(dir, 1024); !errors.Is(err, ErrStagingDirOwned) {
		t.Fatalf("successor NewBudget = %v, want ErrStagingDirOwned", err)
	}
	// Restore and finish the hand-off so the test leaves no global state.
	releaseOwnershipLock = prev
	if err := b.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
}

func TestBudgetCloseDoesNotSignalDoneBeforeLockRelease(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1024)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	entered := make(chan struct{})
	proceed := make(chan struct{})
	prev := releaseOwnershipLock
	releaseOwnershipLock = func(l *dirLock) error {
		close(entered)
		<-proceed
		return prev(l)
	}
	t.Cleanup(func() { releaseOwnershipLock = prev })

	done := make(chan error, 1)
	go func() { done <- b.Close() }()
	<-entered

	b.mu.Lock()
	finalized := b.finalized
	b.mu.Unlock()
	if finalized {
		t.Fatal("budget finalized before the lock release completed")
	}
	select {
	case err := <-done:
		t.Fatalf("Close returned before the lock release completed: %v", err)
	default:
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestBudgetCloseRetryHandsDirectoryToSuccessor(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1024)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	prev := releaseOwnershipLock
	failed := false
	releaseOwnershipLock = func(l *dirLock) error {
		if !failed {
			failed = true
			return errors.New("EPERM injected")
		}
		return prev(l)
	}
	t.Cleanup(func() { releaseOwnershipLock = prev })

	if err := b.Close(); err == nil {
		t.Fatal("first Close = nil, want the injected release failure")
	}
	if _, err := NewBudget(dir, 1024); !errors.Is(err, ErrStagingDirOwned) {
		t.Fatalf("successor acquired the directory while the release was failing: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	successor, err := NewBudget(dir, 1024)
	if err != nil {
		t.Fatalf("successor NewBudget after successful retry: %v", err)
	}
	if err := successor.Close(); err != nil {
		t.Fatalf("successor Close: %v", err)
	}
}
