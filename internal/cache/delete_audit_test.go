package cache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
)

// recordingBlobs is a blob.Store that records every call. It is wrapped in a
// CAS shared across the failure paths below, so a rollback Delete after a
// failed archive/metadata write would show up as a non-zero delete count.
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

// TestSaveFailureNeverDeletesSharedBlobs locks in the write lifecycle: a
// failing cache Save never deletes a CAS object, so a digest shared with
// other references survives every failure path. CAS writes are
// append/deduplicate; removal belongs to reference-aware GC only.
func TestSaveFailureNeverDeletesSharedBlobs(t *testing.T) {
	shared := &recordingBlobs{}
	c := cas.New(shared)
	obj, err := c.Put(context.Background(), bytes.NewReader([]byte("shared payload")))
	if err != nil {
		t.Fatal(err)
	}
	if got := shared.deleteCount(); got != 0 {
		t.Fatalf("Put deleted %d object(s)", got)
	}

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "big"), bytes.Repeat([]byte("x"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(remote.Close)

	// Failure paths: cap exceeded, invalid key, missing workspace, remote
	// push failure.
	capped := &Store{Root: t.TempDir(), MaxCacheBytes: 32}
	if err := capped.Save("valid-key", ws, []string{"."}); err == nil {
		t.Fatal("cap-exceeded save must fail")
	}
	if err := capped.Save("bad key", ws, nil); err == nil {
		t.Fatal("invalid-key save must fail")
	}
	if err := capped.Save("valid-key", filepath.Join(ws, "missing"), nil); err == nil {
		t.Fatal("missing-workspace save must fail")
	}
	remoteStore := &Store{Root: t.TempDir(), RemoteURL: remote.URL, Token: "t"}
	if err := remoteStore.Save("valid-key", ws, []string{"."}); err == nil {
		t.Fatal("remote push failure must fail the save")
	}
	// A failed remote push must not roll back the locally committed archive.
	if _, err := os.Stat(filepath.Join(remoteStore.Root, "valid-key.tar.gz")); err != nil {
		t.Fatalf("local archive removed after remote failure: %v", err)
	}

	if got := shared.deleteCount(); got != 0 {
		t.Fatalf("cache Save deleted %d blob(s) on failure paths", got)
	}
	if _, _, err := c.Open(context.Background(), obj.Key); err != nil {
		t.Fatalf("shared object no longer openable: %v", err)
	}
}
