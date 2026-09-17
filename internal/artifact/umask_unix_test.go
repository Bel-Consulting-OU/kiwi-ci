//go:build !windows

package artifact

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestSaveUnreadableArchiveFailsDigestOpen pins the digest pass failing when
// the freshly created archive cannot be opened (umask 0o777). Unix-only:
// Windows has no umask semantics.
func TestSaveUnreadableArchiveFailsDigestOpen(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "r", "j"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o777)
	_, err := (&Store{Root: root}).Save("r", "j", "a", ws, []string{"."})
	syscall.Umask(old)
	if err == nil {
		t.Fatal("unreadable archive must fail the digest open")
	}
}
