package testutil

import (
	"os"
	"testing"
)

// TestPlatformGatesNoOpOnHost covers the gates on the host platform: on unix
// every gate must return without skipping, SetHome must point HOME at dir, and
// HasExecutable must resolve a real binary and reject a bogus one.
func TestPlatformGatesNoOpOnHost(t *testing.T) {
	UnixChmod(t)
	UnixShell(t)
	NotWindows(t, "exercise the unix path")
	RequireNonRoot(t)

	dir := t.TempDir()
	SetHome(t, dir)
	if got := os.Getenv("HOME"); got != dir {
		t.Fatalf("SetHome HOME = %q, want %q", got, dir)
	}

	if !HasExecutable("sh") {
		t.Fatal("HasExecutable(sh) = false on a POSIX host")
	}
	if HasExecutable("kiwi-testutil-definitely-missing-binary") {
		t.Fatal("HasExecutable resolved a bogus name")
	}
}
