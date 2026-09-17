// Package testutil provides platform gates for tests whose subject is
// genuinely POSIX-only. Windows CI runs the whole suite; chmod-based
// failure injection (making a path unreadable or a directory unwritable),
// POSIX shell scripts and HOME-based profile resolution do not behave the
// same there, so those tests skip instead of failing or hanging.
package testutil

import (
	"os/exec"
	"runtime"
	"testing"
)

// UnixChmod skips a test whose failure injection relies on POSIX
// permission semantics (chmod making paths unreadable/unwritable).
func UnixChmod(t testing.TB) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX chmod semantics required for this failure injection")
	}
}

// UnixShell skips a test that executes a `#!/bin/sh` (or other POSIX shell)
// fixture via exec.
func UnixShell(t testing.TB) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture required")
	}
}

// NotWindows skips a test whose subject does not exist on Windows at all.
func NotWindows(t testing.TB, why string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("not applicable on windows: " + why)
	}
}

// SetHome points the platform user-home resolution at dir: HOME on unix,
// USERPROFILE on Windows, so home-directory tests behave identically.
func SetHome(t testing.TB, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
}

// HasExecutable reports whether name resolves on PATH.
func HasExecutable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
