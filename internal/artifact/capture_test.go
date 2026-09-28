package artifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// cancelAfterChecks is a context whose Err() returns context.Canceled after
// the first n checks. It makes mid-archive cancellation deterministic: the
// producer checks the context at entry and once per archive write, so the
// capture is cancelled after a known number of writes instead of racing a
// wall-clock timer.
type cancelAfterChecks struct {
	context.Context
	remaining atomic.Int32
}

func (c *cancelAfterChecks) Err() error {
	if c.remaining.Add(-1) <= 0 {
		return context.Canceled
	}
	return nil
}

// writeWorkspaceFile creates a file of n pseudo-random (incompressible)
// bytes under ws, so archive-size assertions do not depend on gzip ratios.
func writeWorkspaceFile(t *testing.T, ws, name string, n int) {
	t.Helper()
	data := make([]byte, n)
	state := uint32(0x9e3779b9)
	for i := range data {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		data[i] = byte(state)
	}
	if err := os.WriteFile(filepath.Join(ws, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// entriesUnder lists all regular files under root (recursively), so tests can
// assert that a refused or cancelled capture left nothing behind.
func entriesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSaveContextEnforcesExplicitBound pins the capture contract the runner
// depends on: maxBytes caps the archive regardless of the store's configured
// MaxArtifactBytes, so an archive the control plane would reject is refused
// before it is ever uploaded.
func TestSaveContextEnforcesExplicitBound(t *testing.T) {
	ws := t.TempDir()
	writeWorkspaceFile(t, ws, "big.bin", 4096)
	store := &Store{Root: t.TempDir()}
	_, err := store.SaveContext(context.Background(), "run", "job", "art", ws, []string{"big.bin"}, 1024)
	if !errors.Is(err, safefs.ErrCapExceeded) {
		t.Fatalf("error = %v, want ErrCapExceeded", err)
	}
	if left := entriesUnder(t, store.Root); len(left) != 0 {
		t.Fatalf("refused capture left files behind: %v", left)
	}
}

// TestSaveContextCancelStopsCapture pins the cancellation contract: a job
// deadline during archive creation stops the traversal, removes the partial
// file, and never publishes an archive.
func TestSaveContextCancelStopsCapture(t *testing.T) {
	ws := t.TempDir()
	writeWorkspaceFile(t, ws, "data.bin", 64<<10)
	store := &Store{Root: t.TempDir()}
	ctx := &cancelAfterChecks{Context: context.Background()}
	ctx.remaining.Store(2)
	_, err := store.SaveContext(ctx, "run", "job", "art", ws, []string{"data.bin"}, 0)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if left := entriesUnder(t, store.Root); len(left) != 0 {
		t.Fatalf("cancelled capture left files behind: %v", left)
	}
}

// TestRemoveCapturedRemovesArchiveAndManifest pins the temporary publication
// cleanup: both the archive and its sidecar manifest disappear, and a second
// call is a no-op.
func TestRemoveCapturedRemovesArchiveAndManifest(t *testing.T) {
	ws := t.TempDir()
	writeWorkspaceFile(t, ws, "out.txt", 128)
	store := &Store{Root: t.TempDir()}
	p, err := store.SaveContext(context.Background(), "run", "job", "art", ws, []string{"out.txt"}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("archive missing before cleanup: %v", err)
	}
	if _, err := os.Stat(p + ".manifest.json"); err != nil {
		t.Fatalf("manifest missing before cleanup: %v", err)
	}
	if err := RemoveCaptured(p); err != nil {
		t.Fatalf("RemoveCaptured: %v", err)
	}
	for _, gone := range []string{p, p + ".manifest.json"} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after cleanup (err=%v)", gone, err)
		}
	}
	if err := RemoveCaptured(p); err != nil {
		t.Fatalf("RemoveCaptured must be idempotent: %v", err)
	}
	if err := RemoveCaptured(""); err != nil {
		t.Fatalf("RemoveCaptured(\"\") = %v", err)
	}
	if strings.TrimSpace(p) == "" {
		t.Fatal("sanity: save returned an empty path")
	}
}

// TestSaveContextManifestFailureRemovesArchive pins the no-unaccounted-bytes
// rule: when the sidecar manifest cannot be written after the archive was
// renamed into place, the archive is removed before SaveContext returns an
// error, so a capture caller that never receives a path cannot leak an
// unaccounted archive.
func TestSaveContextManifestFailureRemovesArchive(t *testing.T) {
	ws := t.TempDir()
	writeWorkspaceFile(t, ws, "out.txt", 64)
	root := t.TempDir()
	store := &Store{Root: root}
	dir := filepath.Join(root, encodeArtifactName("run"), encodeArtifactName("job"))
	manifest := filepath.Join(dir, encodeArtifactName("art")+".tar.gz.manifest.json")
	if err := os.MkdirAll(manifest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifest, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveContext(context.Background(), "run", "job", "art", ws, []string{"out.txt"}, 1<<20); err == nil {
		t.Fatal("SaveContext succeeded with an unwritable manifest path")
	}
	if _, err := os.Stat(filepath.Join(dir, encodeArtifactName("art")+".tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("archive left behind after manifest failure (err=%v)", err)
	}
}
