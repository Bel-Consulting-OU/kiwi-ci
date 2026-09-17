package storage

// Seam tests for the package entropy source: production always reads
// crypto/rand.Reader (randReader's default); tests override it with a failing
// reader to exercise the fail-closed identifier branches that a working
// entropy source can never reach.

import (
	"errors"
	"testing"
)

var errStorageSeamEntropy = errors.New("seam: entropy source failed")

type storageSeamErrReader struct{}

func (storageSeamErrReader) Read([]byte) (int, error) { return 0, errStorageSeamEntropy }

func TestStorageSeamNewIDFailsClosed(t *testing.T) {
	old := randReader
	randReader = storageSeamErrReader{}
	t.Cleanup(func() { randReader = old })
	id, err := newID()
	if err == nil || id != "" {
		t.Fatalf("newID with failing entropy = %q, %v; want empty, error", id, err)
	}
}
