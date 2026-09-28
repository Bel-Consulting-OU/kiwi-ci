package cache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// cancelAfterChecks is a context whose Err() returns context.Canceled after
// the first n checks, making mid-archive cancellation deterministic.
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

// writeIncompressible writes n pseudo-random bytes at path so archive-size
// assertions do not depend on gzip ratios.
func writeIncompressible(t *testing.T, path string, n int) {
	t.Helper()
	data := make([]byte, n)
	state := uint32(0x9e3779b9)
	for i := range data {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		data[i] = byte(state)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func cacheStoreFiles(t *testing.T, root string) []string {
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

// TestSaveContextUnconfiguredStoreEnforcesDefaultBound is the P1 regression:
// with MaxCacheBytes unset (zero, the production runner configuration) the
// local archive writer and the free-space preflight must use the SAME 8 GiB
// default contract the restore path and remote upload enforce. The historical
// code branched on raw MaxCacheBytes and wrote an unbounded archive.
func TestSaveContextUnconfiguredStoreEnforcesDefaultBound(t *testing.T) {
	prev := defaultCacheArchiveBytes
	defaultCacheArchiveBytes = 512
	t.Cleanup(func() { defaultCacheArchiveBytes = prev })

	ws := t.TempDir()
	writeIncompressible(t, filepath.Join(ws, "big.bin"), 64<<10)
	store := &Store{Root: t.TempDir()}
	err := store.SaveContext(context.Background(), "key1", ws, []string{"big.bin"})
	if !errors.Is(err, safefs.ErrCapExceeded) {
		t.Fatalf("unconfigured store error = %v, want ErrCapExceeded from the default bound", err)
	}
	if left := cacheStoreFiles(t, store.Root); len(left) != 0 {
		t.Fatalf("refused cache save left files behind: %v", left)
	}
}

// TestSaveContextCancelStopsArchiveWrite pins the cancellation contract: the
// job deadline stops the local archive traversal/writes (not only the remote
// phase), the partial file is removed, and no archive or digest is recorded.
func TestSaveContextCancelStopsArchiveWrite(t *testing.T) {
	ws := t.TempDir()
	writeIncompressible(t, filepath.Join(ws, "data.bin"), 256<<10)
	store := &Store{Root: t.TempDir()}
	ctx := &cancelAfterChecks{Context: context.Background()}
	ctx.remaining.Store(2)
	err := store.SaveContext(ctx, "key2", ws, []string{"data.bin"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if left := cacheStoreFiles(t, store.Root); len(left) != 0 {
		t.Fatalf("cancelled cache save left files behind: %v", left)
	}
}
