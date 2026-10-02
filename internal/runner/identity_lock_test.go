//go:build unix

package runner

// Duplicate-running-identity regressions: one stable runner identity may have
// at most one live process. Without the lifetime lock a copied identity
// directory would let a second process classify the first (LIVE) process's
// containers as a crashed predecessor's and kill them.

import (
	"os"
	"strings"
	"testing"
)

func TestDuplicateRunnerIdentityCannotStartSecondLocalProcess(t *testing.T) {
	dir := t.TempDir()
	release, err := acquireRunnerIdentityLock(dir)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := acquireRunnerIdentityLock(dir); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("second lock = %v, want an already-active refusal", err)
	}
	release()
	// After release the identity can be re-acquired (restart).
	release2, err := acquireRunnerIdentityLock(dir)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	release2()
	// The lock file is left behind on purpose (the flock is the lock).
	if _, err := os.Stat(dir + "/runner.lock"); err != nil {
		t.Fatalf("lock file missing: %v", err)
	}
}
