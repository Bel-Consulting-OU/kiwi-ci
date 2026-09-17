package snapshot

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
)

// recordingBlobs is a blob.Store that records every call. It is wrapped in a
// CAS shared across the failure paths below, so a rollback Delete after a
// failed capture/persist step would show up as a non-zero delete count.
type recordingBlobs struct {
	mu      sync.Mutex
	objects map[string][]byte
	deletes int
}

func (r *recordingBlobs) Put(_ context.Context, key string, body io.Reader, _ int64) (blob.Object, error) {
	b, err := io.ReadAll(body)
	if err != nil {
		return blob.Object{}, err
	}
	r.mu.Lock()
	if r.objects == nil {
		r.objects = map[string][]byte{}
	}
	r.objects[key] = b
	r.mu.Unlock()
	return blob.Object{Key: key, SHA256: key, Size: int64(len(b))}, nil
}

func (r *recordingBlobs) Open(_ context.Context, key string) (io.ReadCloser, blob.Object, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.objects[key]
	if !ok {
		return nil, blob.Object{}, blob.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), blob.Object{Key: key, SHA256: key, Size: int64(len(b))}, nil
}

func (r *recordingBlobs) Delete(context.Context, string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deletes++
	return nil
}

func (r *recordingBlobs) deleteCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deletes
}

// failingWriter fails once the byte budget is exhausted, simulating a
// persistence failure while Create writes the archive.
type failingWriter struct{ remaining int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, errors.New("snapshot: destination write failed")
	}
	w.remaining -= len(p)
	return len(p), nil
}

// TestCreateFailureNeverDeletesSharedBlobs locks in the write lifecycle: a
// failing snapshot Create never deletes a CAS object, so a digest shared with
// other references survives every failure path. CAS writes are
// append/deduplicate; removal belongs to reference-aware GC only.
func TestCreateFailureNeverDeletesSharedBlobs(t *testing.T) {
	shared := &recordingBlobs{}
	c := cas.New(shared)
	obj, err := c.Put(context.Background(), strings.NewReader("shared payload"))
	if err != nil {
		t.Fatal(err)
	}
	if got := shared.deleteCount(); got != 0 {
		t.Fatalf("Put deleted %d object(s)", got)
	}

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Failure paths: empty workspace, missing workspace, failing destination.
	if _, err := Create("", io.Discard); err == nil {
		t.Fatal("empty-workspace create must fail")
	}
	if _, err := Create(filepath.Join(ws, "missing"), io.Discard); err == nil {
		t.Fatal("missing-workspace create must fail")
	}
	if _, err := Create(ws, &failingWriter{remaining: 64}); err == nil {
		t.Fatal("failing-destination create must fail")
	}

	if got := shared.deleteCount(); got != 0 {
		t.Fatalf("snapshot Create deleted %d blob(s) on failure paths", got)
	}
	if _, _, err := c.Open(context.Background(), obj.Key); err != nil {
		t.Fatalf("shared object no longer openable: %v", err)
	}
}
