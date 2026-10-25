package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestClaimNativePortCrossProcessFile: an exclusive lock held by a LIVE
// foreign claimant refuses a second claim; a stale (unlocked) file is
// reclaimed. The lock, not the file content, is the ownership primitive.
func TestClaimNativePortCrossProcessFile(t *testing.T) {
	dir := t.TempDir()
	orig := nativePortClaimDir
	nativePortClaimDir = func() string { return dir }
	t.Cleanup(func() {
		nativePortClaimDir = orig
		releaseNativePort(64999)
		// Extra cleanup of any handle left by the foreign lock simulation.
		if f, ok := portClaimHandles[64999]; ok {
			_ = f.Close()
			delete(portClaimHandles, 64999)
		}
	})
	path := filepath.Join(dir, "64999.lock")

	// Foreign live claimant HOLDS the exclusive lock (simulated in-process).
	foreign, err := lockPortClaimFile(path, []byte(fmt.Sprintf("pid=%d\nowner=other-runner\n", os.Getpid())))
	if err != nil {
		t.Fatalf("foreign lock: %v", err)
	}
	// Clear any in-memory claim so only the cross-process lock can refuse.
	nativePortClaims.Lock()
	delete(nativePortClaims.byPort, 64999)
	nativePortClaims.Unlock()
	if err := claimNativePort(64999, "job/redis"); err == nil {
		_ = foreign.Close()
		t.Fatal("second claim must not succeed while a live foreign lock is held")
	}
	// Release the foreign lock: the same file becomes reclaimable.
	_ = foreign.Close()
	if err := claimNativePort(64999, "job/redis"); err != nil {
		t.Fatalf("unlocked (stale) claim must succeed: %v", err)
	}
	releaseNativePort(64999)
}

// TestClaimNativePortReleasedThenReclaimable: closing the held handle
// releases the flock, so a subsequent claim of the same port succeeds
// (no permanent stale lock).
func TestClaimNativePortReleasedThenReclaimable(t *testing.T) {
	dir := t.TempDir()
	orig := nativePortClaimDir
	nativePortClaimDir = func() string { return dir }
	t.Cleanup(func() { nativePortClaimDir = orig })
	const port = 64997
	if err := claimNativePort(port, "jobA/redis"); err != nil {
		t.Fatal(err)
	}
	if err := claimNativePort(port, "jobB/redis"); err == nil {
		t.Fatal("second claim while held must fail")
	}
	releaseNativePort(port)
	if err := claimNativePort(port, "jobC/redis"); err != nil {
		t.Fatalf("reclaim after release: %v", err)
	}
	releaseNativePort(port)
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
