//go:build !windows

package artifact

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

// TestSaveUnreadableArchiveFailsDigestOpen pins the digest pass failing when
// the freshly created archive cannot be opened (umask 0o777). Unix-only:
// Windows has no umask semantics. The mode bits are only enforced for a
// non-root euid, so root skips instead of passing tautologically. The skip is
// narrow: uid 0 cannot be denied an open-for-read of the regular file that
// Save renamed into place immediately before this open, and every structural
// block (a directory at the archive path) fails the earlier rename step, so
// an exact-branch root injection would need an archive-open seam in
// artifact.go, which is outside this change's file ownership.
func TestSaveUnreadableArchiveFailsDigestOpen(t *testing.T) {
	testutil.RequireNonRoot(t)
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
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Op != "open" {
		t.Fatalf("unreadable archive = %v; want the digest open (op open) to fail, not another step", err)
	}
}
