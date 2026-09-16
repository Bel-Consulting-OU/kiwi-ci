package executor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestReadJobFileNativeNoFollow verifies ReadJobFile resolves through the
// live backend session: a native read succeeds for a regular workspace file
// and fails (no-follow) once the file is swapped for a symlink pointing
// outside the workspace.
func TestReadJobFileNativeNoFollow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	ws := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(ws, "ok.txt")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := &Executor{}
	e.prepare()
	e.sessions.put("j1", &NativeBackend{})
	defer e.sessions.delete("j1")

	got, err := e.ReadJobFile(context.Background(), "j1", target, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Fatalf("read = %q, want data", got)
	}

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), target); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReadJobFile(context.Background(), "j1", target, 1<<20); err == nil {
		t.Fatal("symlinked file read without error: no-follow must refuse")
	}
}

// TestReadJobFileCapAndMissingSession pins the hard cap and the fail-closed
// behavior for jobs without a live session.
func TestReadJobFileCapAndMissingSession(t *testing.T) {
	ws := t.TempDir()
	target := filepath.Join(ws, "big.txt")
	if err := os.WriteFile(target, []byte(strings.Repeat("x", 1024)), 0o644); err != nil {
		t.Fatal(err)
	}
	e := &Executor{}
	e.prepare()
	e.sessions.put("j1", &NativeBackend{})
	defer e.sessions.delete("j1")

	if _, err := e.ReadJobFile(context.Background(), "j1", target, 16); err == nil {
		t.Fatal("oversized read must be rejected")
	}
	if _, err := e.ReadJobFile(context.Background(), "unknown", target, 1<<20); err == nil {
		t.Fatal("read for a job without a live session must fail")
	}
}
