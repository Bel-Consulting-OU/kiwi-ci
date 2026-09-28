package cache

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// TestKeyContextCancelsHashing pins finding 3: cache-key computation observes
// the job context while hashing hash_files, so a huge input cannot run past
// the declared lifetime before restore even starts.
func TestKeyContextCancelsHashing(t *testing.T) {
	ws := t.TempDir()
	writeIncompressible(t, filepath.Join(ws, "big.bin"), 256<<10)
	store := &Store{Root: t.TempDir()}
	ctx := &cancelAfterChecks{Context: context.Background()}
	ctx.remaining.Store(2)
	if _, err := store.KeyContext(ctx, "base", ws, []string{"big.bin"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("KeyContext error = %v, want context.Canceled", err)
	}
}

// TestRestoreContextCancelsLocalDigestVerification pins the local hashing
// half of the restore cancellation: the digest pass streams through a
// context-aware reader and stops when the job context ends.
func TestRestoreContextCancelsLocalDigestVerification(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	src := t.TempDir()
	writeIncompressible(t, filepath.Join(src, "data.bin"), 256<<10)
	if err := store.SaveContext(context.Background(), "key-hash", src, []string{"data.bin"}); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterChecks{Context: context.Background()}
	ctx.remaining.Store(2)
	dest := t.TempDir()
	hit, err := store.RestoreContext(ctx, "key-hash", dest, []string{"."})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RestoreContext = hit=%t err=%v, want context.Canceled", hit, err)
	}
}

// TestRestoreContextCancelsExtraction pins the extraction half: the archive
// reader handed to the extractor is context-aware, so a canceled job stops
// the filesystem walk instead of unpacking a multi-gigabyte archive after
// its deadline.
func TestRestoreContextCancelsExtraction(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	src := t.TempDir()
	writeIncompressible(t, filepath.Join(src, "data.bin"), 1024)
	if err := store.SaveContext(context.Background(), "key-extract", src, []string{"data.bin"}); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	gate := make(chan struct{})
	orig := extractCacheArchive
	extractCacheArchive = func(*safefs.Root, io.Reader, safefs.ExtractLimits) (*safefs.ExtractStats, error) {
		close(entered)
		<-gate
		return nil, errors.New("test: extraction stopped")
	}
	t.Cleanup(func() { extractCacheArchive = orig })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dest := t.TempDir()
	done := make(chan error, 1)
	go func() {
		_, err := store.RestoreContext(ctx, "key-extract", dest, []string{"."})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("extraction was never reached")
	}
	cancel()
	close(gate)
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RestoreContext error = %v, want context.Canceled", err)
	}
}
