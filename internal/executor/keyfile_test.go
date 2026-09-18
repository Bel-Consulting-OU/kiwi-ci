//go:build !windows

package executor

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteOwnerOnlyUnixMode asserts the Unix implementation creates the file
// at the requested path with mode 0600 — the owner-only access-control
// mechanism on Unix — and that the content round-trips.
func TestWriteOwnerOnlyUnixMode(t *testing.T) {
	path := t.TempDir() + "/id_ed25519"
	if _, err := WriteOwnerOnly(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "secret" {
		t.Fatalf("content = %q, want %q", data, "secret")
	}
}

// TestWriteOwnerOnlyReplacesPreexistingLooseMode verifies a pre-existing
// world-readable file (or symlink target) is replaced at 0600 instead of
// being written through with its old mode.
func TestWriteOwnerOnlyReplacesPreexistingLooseMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteOwnerOnly(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "secret" {
		t.Fatalf("content = %q, want secret", data)
	}
}

// TestWriteOwnerOnlyReplacesSymlink verifies a pre-planted symlink at the key
// path is removed and replaced by a fresh owner-only file rather than having
// the secret written through it.
func TestWriteOwnerOnlyReplacesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteOwnerOnly(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("key path is still a symlink")
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "old" {
		t.Fatalf("secret written through symlink: %q %v", b, err)
	}
}
