package cas

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
)

// countingStore records the objects written so an over-limit Put can be
// proven to never reach the underlying blob store.
type countingStore struct {
	puts int
}

func (c *countingStore) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	c.puts++
	return blob.Object{Key: key, SHA256: key, Size: size}, nil
}

func (c *countingStore) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	return nil, blob.Object{}, blob.ErrNotFound
}

func (c *countingStore) Delete(ctx context.Context, key string) error { return nil }

func TestCASPutRejectsOverLimitBlob(t *testing.T) {
	st := &countingStore{}
	c := New(st)
	c.MaxBlobBytes = 1024

	// Exactly at the limit is accepted.
	if _, err := c.Put(context.Background(), bytes.NewReader(make([]byte, 1024))); err != nil {
		t.Fatalf("put at limit: %v", err)
	}
	// One byte over is rejected with ErrBlobTooLarge and never reaches the
	// store.
	before := st.puts
	if _, err := c.Put(context.Background(), bytes.NewReader(make([]byte, 1025))); !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("over-limit put = %v, want ErrBlobTooLarge", err)
	}
	if st.puts != before {
		t.Fatalf("over-limit stream reached the blob store: %d writes", st.puts)
	}
	// A stream that keeps producing data past the limit still fails the
	// same way (the counting reader bounds the read).
	if _, err := c.Put(context.Background(), io.MultiReader(bytes.NewReader(make([]byte, 2048)), bytes.NewReader(make([]byte, 2048)))); !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("multi-chunk over-limit put = %v, want ErrBlobTooLarge", err)
	}
}

func TestCASPutDefaultLimit(t *testing.T) {
	c := New(&countingStore{})
	if c.maxBytes() != DefaultMaxBlobBytes {
		t.Fatalf("default max = %d, want %d", c.maxBytes(), DefaultMaxBlobBytes)
	}
	// A custom positive bound wins.
	c.MaxBlobBytes = 128
	if c.maxBytes() != 128 {
		t.Fatalf("custom max = %d, want 128", c.maxBytes())
	}
	// Zero falls back to the default again.
	c.MaxBlobBytes = 0
	if c.maxBytes() != DefaultMaxBlobBytes {
		t.Fatalf("zero max = %d, want default %d", c.maxBytes(), DefaultMaxBlobBytes)
	}
}
