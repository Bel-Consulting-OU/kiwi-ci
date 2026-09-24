//go:build !windows

package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

// TestSaveDigestComesFromWriteStream pins that Save hashes the bytes as they
// are written instead of re-opening the renamed archive: with a restrictive
// umask (0o777) the freshly renamed archive is not readable by mode, yet Save
// still succeeds and the manifest digest matches the stored archive exactly.
// Unix-only: Windows has no umask semantics, and the mode bits are only
// enforced for a non-root euid.
func TestSaveDigestComesFromWriteStream(t *testing.T) {
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
	path, err := (&Store{Root: root}).Save("r", "j", "a", ws, []string{"."})
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("Save with restrictive umask: %v", err)
	}
	m, err := ReadManifest(path + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	// Make the archive readable so the assertion can compare its bytes; the
	// digest was already computed from the write stream, not this read.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != m.SHA256 || int64(len(b)) != m.Size {
		t.Fatalf("manifest digest/size %s/%d does not match stored archive %s/%d", m.SHA256, m.Size, got, len(b))
	}
}
