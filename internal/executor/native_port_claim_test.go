package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestClaimNativePortCrossProcessFile: the durable lock file rejects a
// second claim of the same port even when the in-memory map is empty
// (the separate-runner-process gap).
func TestClaimNativePortCrossProcessFile(t *testing.T) {
	// Isolate the claim directory for this test.
	dir := t.TempDir()
	orig := nativePortClaimDir
	nativePortClaimDir = func() string { return dir }
	t.Cleanup(func() {
		nativePortClaimDir = orig
		releaseNativePort(64999)
	})
	// Simulate a FOREIGN live process holding the lock.
	path := filepath.Join(dir, "64999.lock")
	// Use our own PID so processAlive is true (a live foreign owner).
	if err := os.WriteFile(path, []byte(fmt.Sprintf("pid=%d\nowner=other-runner\n", os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	// Clear any in-memory claim so only the file gate can refuse.
	nativePortClaims.Lock()
	delete(nativePortClaims.byPort, 64999)
	nativePortClaims.Unlock()
	err := claimNativePort(64999, "job/redis")
	if err == nil {
		t.Fatal("second process must not claim a live foreign lock")
	}
	// Dead-owner lock is reclaimed.
	if err := os.WriteFile(path, []byte("pid=999999999\nowner=dead-runner\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := claimNativePort(64999, "job/redis"); err != nil {
		t.Fatalf("stale lock must be reclaimed: %v", err)
	}
	releaseNativePort(64999)
}

// TestClaimNativePortInProcessStillRefused: concurrent jobs in one process
// still cannot double-claim (regression for the original oracle).
func TestClaimNativePortInProcessStillRefused(t *testing.T) {
	dir := t.TempDir()
	orig := nativePortClaimDir
	nativePortClaimDir = func() string { return dir }
	t.Cleanup(func() { nativePortClaimDir = orig })
	const port = 64998
	if err := claimNativePort(port, "jobA/pg"); err != nil {
		t.Fatal(err)
	}
	if err := claimNativePort(port, "jobB/pg"); err == nil {
		t.Fatal("same-process second claim must fail")
	}
	releaseNativePort(port)
	var wg sync.WaitGroup
	wg.Wait()
}
