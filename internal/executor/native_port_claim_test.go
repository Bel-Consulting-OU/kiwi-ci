package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestClaimNativePortCrossProcessFile: an exclusive lock held by a LIVE
// foreign claimant refuses a second claim; an unlocked (stale) file is
// reclaimed. The lock, not the file content, is the ownership primitive.
func TestClaimNativePortCrossProcessFile(t *testing.T) {
	dir := t.TempDir()
	orig := nativePortClaimDir
	nativePortClaimDir = func() string { return dir }
	t.Cleanup(func() {
		nativePortClaimDir = orig
		releaseNativePort(64999)
	})
	path := filepath.Join(dir, "64999.lock")

	// Foreign live claimant HOLDS the exclusive lock (two independent fds
	// in one process contend under Linux flock).
	foreign, err := openPortClaimFileNoFollow(path)
	if err != nil {
		t.Fatalf("foreign open: %v", err)
	}
	payload := []byte(fmt.Sprintf("pid=%d\nowner=other-runner\n", os.Getpid()))
	if err := lockPortClaimFile(foreign, payload); err != nil {
		_ = foreign.Close()
		t.Fatalf("foreign lock: %v", err)
	}
	nativePortClaims.Lock()
	delete(nativePortClaims.byPort, 64999)
	nativePortClaims.Unlock()
	if err := claimNativePort(64999, "job/redis"); err == nil {
		_ = foreign.Close()
		t.Fatal("second claim must not succeed while a live foreign lock is held")
	}
	_ = foreign.Close()
	if err := claimNativePort(64999, "job/redis"); err != nil {
		t.Fatalf("unlocked (stale) claim must succeed: %v", err)
	}
	releaseNativePort(64999)
}

// TestPortClaimDirTightenedAndSymlinkRefused: a world-writable claim
// directory the runner owns is tightened to 0700; a pre-planted symlink
// lock path is refused (never followed/truncated).
func TestPortClaimDirTightenedAndSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	orig := nativePortClaimDir
	nativePortClaimDir = func() string { return dir }
	t.Cleanup(func() {
		nativePortClaimDir = orig
		releaseNativePort(64001)
	})
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := claimNativePort(64001, "job/a"); err != nil {
		t.Fatalf("claim after dir tighten: %v", err)
	}
	releaseNativePort(64001)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("claim dir perms = %v, want 0700 after ensure", info.Mode().Perm())
	}

	link := filepath.Join(dir, "64002.lock")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := claimNativePortFile(64002, "job/b"); err == nil {
		t.Fatal("symlink lock path must be refused")
	} else if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error = %v, want not-a-regular-file", err)
	}
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

// TestPortClaimForeignOwnedFileRefused: even inside the trusted 0700 claim
// directory, a pre-planted lock file owned by ANOTHER local user must never
// be truncated and rewritten through — that was the audit's /tmp symlink /
// pre-plant escalation (open → truncate → write runs with the runner's
// privileges on the attacker's target).
//
// The trust gate is proven without privilege by forcing the untrusted
// verdict (the check is wired BEFORE any truncate); a privileged chown
// sub-check additionally exercises the real uid comparison where the host
// allows it.
func TestPortClaimForeignOwnedFileRefused(t *testing.T) {
	dir := t.TempDir()
	orig := nativePortClaimDir
	nativePortClaimDir = func() string { return dir }
	t.Cleanup(func() { nativePortClaimDir = orig })
	path := filepath.Join(dir, "64003.lock")
	if err := os.WriteFile(path, []byte("planted\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1) Wiring: an untrusted verdict refuses BEFORE truncate/lock.
	trusted := claimFileTrusted
	claimFileTrusted = func(os.FileInfo) bool { return false }
	_, wireErr := claimNativePortFile(64003, "job/c")
	claimFileTrusted = trusted
	if wireErr == nil {
		t.Fatal("claim must refuse an untrusted lock file")
	}
	if !strings.Contains(wireErr.Error(), "not owned by this user") {
		t.Fatalf("error = %v, want not-owned-by-this-user refusal", wireErr)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "planted\n" {
		t.Fatalf("planted file was rewritten by an untrusted claim: %q", b)
	}

	// 2) Real uid comparison, where privilege allows fabricating a
	// foreign-owned file (and the test user is not the target uid).
	if os.Getuid() != 65534 {
		if err := os.Chown(path, 65534, -1); err == nil {
			if _, err := claimNativePortFile(64003, "job/d"); err == nil {
				t.Fatal("foreign-owned claim file must be refused, not truncated")
			} else if !strings.Contains(err.Error(), "not owned by this user") {
				t.Fatalf("error = %v, want not-owned-by-this-user refusal", err)
			}
			if b, err := os.ReadFile(path); err != nil || string(b) != "planted\n" {
				t.Fatalf("foreign-owned file rewritten: %q %v", b, err)
			}
		}
	}
}
