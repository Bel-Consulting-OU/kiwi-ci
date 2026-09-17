package cas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
)

// TestCASPutSizeBoundary pins the per-object bound: a stream exactly at
// MaxBlobBytes is stored, and one byte more is rejected without writing the
// oversized object.
func TestCASPutSizeBoundary(t *testing.T) {
	dir := t.TempDir()
	c := &CAS{Blobs: blob.NewFS(dir), MaxBlobBytes: 16}
	exact := bytes.Repeat([]byte("x"), 16)
	obj, err := c.Put(context.Background(), bytes.NewReader(exact))
	if err != nil {
		t.Fatalf("exactly at the bound: %v", err)
	}
	if obj.Size != 16 {
		t.Fatalf("size = %d", obj.Size)
	}
	over := bytes.Repeat([]byte("y"), 17)
	if _, err := c.Put(context.Background(), bytes.NewReader(over)); !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("one byte over the bound: want ErrBlobTooLarge, got %v", err)
	}
	sum := sha256.Sum256(over)
	overKey := hex.EncodeToString(sum[:])
	if _, _, err := c.Blobs.Open(context.Background(), overKey); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("oversized object must not be stored: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("store has %d prefixes after rejected put, want 1", len(entries))
	}
}

// TestCASConcurrentPutOpenDeleteSameKey hammers one key with concurrent
// writers, readers and deleters: no operation may panic, and the store must
// still accept and serve the object afterwards.
func TestCASConcurrentPutOpenDeleteSameKey(t *testing.T) {
	c := New(blob.NewFS(t.TempDir()))
	payload := bytes.Repeat([]byte("concurrent-content"), 64)
	sum := sha256.Sum256(payload)
	key := hex.EncodeToString(sum[:])

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Put(context.Background(), bytes.NewReader(payload))
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, _, err := c.Open(context.Background(), key)
			if err != nil {
				return // deleted concurrently: fine
			}
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(rc)
			_ = rc.Close()
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Delete(context.Background(), key)
		}()
	}
	wg.Wait()

	if _, err := c.Put(context.Background(), bytes.NewReader(payload)); err != nil {
		t.Fatalf("store unusable after concurrent churn: %v", err)
	}
	rc, _, err := c.Open(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(rc); err != nil {
		t.Fatalf("read after churn: %v", err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatal("content corrupted")
	}
}
