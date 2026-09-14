//go:build !windows

package executor

import (
	"os"
	"testing"
)

// TestWriteOwnerOnlyUnixMode asserts the Unix implementation creates the file
// at the requested path with mode 0600 — the owner-only access-control
// mechanism on Unix — and that the content round-trips.
func TestWriteOwnerOnlyUnixMode(t *testing.T) {
	path := t.TempDir() + "/id_ed25519"
	if err := WriteOwnerOnly(path, []byte("secret")); err != nil {
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
