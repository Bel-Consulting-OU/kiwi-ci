//go:build !windows

package snapshot

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestManifestForSkipsSpecialFiles proves non-regular files (FIFOs) are
// skipped rather than hashed or rejected. Unix-only (mkfifo).
func TestManifestForSkipsSpecialFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "real.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	m, err := ManifestFor(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 1 || m.Entries[0].Path != "real.txt" {
		t.Fatalf("entries = %+v, want only real.txt", m.Entries)
	}
}
