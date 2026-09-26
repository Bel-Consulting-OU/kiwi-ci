package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// gcHookBlob is a controllable blob store for the CAS collector's guard
// branches: every failure mode is injected per operation.
type gcHookBlob struct {
	objects   map[string]blob.Object
	data      map[string][]byte
	openErr   error
	deleteErr error
	statErr   error
	listErr   error
	copyErr   error
}

func newGCHookBlob() *gcHookBlob {
	return &gcHookBlob{objects: map[string]blob.Object{}, data: map[string][]byte{}}
}

func (b *gcHookBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	d, err := io.ReadAll(r)
	if err != nil {
		return blob.Object{}, err
	}
	b.data[key] = d
	obj := blob.Object{Key: key, SHA256: key, Size: int64(len(d)), ModTime: time.Now().UTC()}
	b.objects[key] = obj
	return obj, nil
}

func (b *gcHookBlob) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	if b.openErr != nil {
		return nil, blob.Object{}, b.openErr
	}
	d, ok := b.data[key]
	if !ok {
		return nil, blob.Object{}, blob.ErrNotFound
	}
	if b.copyErr != nil {
		return io.NopCloser(&gcErrReader{err: b.copyErr}), b.objects[key], nil
	}
	return io.NopCloser(bytes.NewReader(d)), b.objects[key], nil
}

func (b *gcHookBlob) Delete(ctx context.Context, key string) error {
	if b.deleteErr != nil {
		return b.deleteErr
	}
	delete(b.data, key)
	delete(b.objects, key)
	return nil
}

func (b *gcHookBlob) List(ctx context.Context, fn func(blob.Object) error) error {
	if b.listErr != nil {
		return b.listErr
	}
	for _, obj := range b.objects {
		if err := fn(obj); err != nil {
			return err
		}
	}
	return nil
}

func (b *gcHookBlob) Stat(ctx context.Context, key string) (blob.Object, error) {
	if b.statErr != nil {
		return blob.Object{}, b.statErr
	}
	obj, ok := b.objects[key]
	if !ok {
		return blob.Object{}, blob.ErrNotFound
	}
	return obj, nil
}

// gcErrReader fails every read, modelling a backend that dies mid-stream.
type gcErrReader struct{ err error }

func (r *gcErrReader) Read(p []byte) (int, error) { return 0, r.err }

// TestLooksLikeSHA256HexGrammar pins the digest shape predicate the CAS
// collector relies on before it will trust a digest for content verification.
func TestLooksLikeSHA256HexGrammar(t *testing.T) {
	valid := strings.Repeat("a1b2c3d4", 8)
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{strings.Repeat("a", 63), false},
		{strings.Repeat("a", 65), false},
		{strings.Repeat("a", 63) + "z", false},
		{strings.Repeat("A", 64), true},
		{valid, true},
	}
	for _, tc := range cases {
		if got := looksLikeSHA256Hex(tc.in); got != tc.want {
			t.Fatalf("looksLikeSHA256Hex(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestVerifyCASObjectContentFailureDecoding covers the verification helper's
// refusals: no trustworthy digest to compare against, an unreadable object, a
// mid-stream failure and a content/digest mismatch.
func TestVerifyCASObjectContentFailureDecoding(t *testing.T) {
	ctx := context.Background()
	store := newGCHookBlob()
	if err := verifyCASObjectContent(ctx, store, "key", "", ""); err == nil || !strings.Contains(err.Error(), "no verifiable digest") {
		t.Fatalf("unverifiable digest = %v", err)
	}
	if err := verifyCASObjectContent(ctx, store, "missing", strings.Repeat("a", 64), ""); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("missing object = %v, want blob.ErrNotFound", err)
	}

	payload := []byte("payload")
	digest := sha256Hex(payload)
	store.data["k"] = payload
	store.objects["k"] = blob.Object{Key: "k", SHA256: digest, Size: int64(len(payload))}
	store.copyErr = errors.New("stream reset")
	if err := verifyCASObjectContent(ctx, store, "k", digest, digest); err == nil || !strings.Contains(err.Error(), "stream reset") {
		t.Fatalf("mid-stream failure = %v", err)
	}
	store.copyErr = nil
	if err := verifyCASObjectContent(ctx, store, "k", strings.Repeat("0", 64), digest); err == nil || !strings.Contains(err.Error(), "content digest mismatch") {
		t.Fatalf("content mismatch = %v", err)
	}
	if err := verifyCASObjectContent(ctx, store, "k", digest, digest); err != nil {
		t.Fatalf("matching content rejected: %v", err)
	}
}

// TestRunCASGCStoreSelectionAndDeletionGuards covers the collector's store
// selection fallbacks and every reason an unreferenced old object must be
// skipped instead of unlinked.
func TestRunCASGCStoreSelectionAndDeletionGuards(t *testing.T) {
	ctx := context.Background()

	t.Run("no store configured", func(t *testing.T) {
		s := New("tok")
		stats, err := s.runCASGC(ctx, casGCOptions{})
		if err != nil || stats != (casGCStats{}) {
			t.Fatalf("no-store pass = (%+v, %v), want a zero no-op", stats, err)
		}
	})

	t.Run("store selected through the CAS wrapper", func(t *testing.T) {
		s := New("tok")
		s.SetBlobStore(newMemBlob())
		s.BlobStore = nil
		if _, err := s.runCASGC(ctx, casGCOptions{MinAge: time.Hour, Batch: 4, Now: time.Now().UTC()}); err == nil {
			t.Fatal("non-enumerating CAS backend reported success")
		}
	})

	old := time.Now().UTC().Add(-48 * time.Hour)
	payload := []byte("payload")
	digest := sha256Hex(payload)
	opts := casGCOptions{MinAge: time.Hour, Batch: 8, Now: time.Now().UTC()}

	t.Run("unknown digest age", func(t *testing.T) {
		s := New("tok")
		hb := newGCHookBlob()
		hb.objects["legacy"] = blob.Object{Key: "legacy", ModTime: old}
		s.SetBlobStore(hb)
		stats, err := s.runCASGC(ctx, opts)
		if err != nil || stats.Deleted != 0 {
			t.Fatalf("legacy object pass = (%+v, %v), want a skip", stats, err)
		}
	})

	t.Run("unknown modification time", func(t *testing.T) {
		s := New("tok")
		hb := newGCHookBlob()
		hb.objects[digest] = blob.Object{Key: digest, SHA256: digest, Size: 3}
		hb.data[digest] = payload
		s.SetBlobStore(hb)
		stats, err := s.runCASGC(ctx, opts)
		if err != nil || stats.Deleted != 0 {
			t.Fatalf("timeless object pass = (%+v, %v), want a skip", stats, err)
		}
	})

	t.Run("object vanishes before stat", func(t *testing.T) {
		s := New("tok")
		hb := newGCHookBlob()
		hb.objects[digest] = blob.Object{Key: digest, SHA256: digest, Size: 3, ModTime: old}
		hb.data[digest] = payload
		hb.statErr = blob.ErrNotFound
		s.SetBlobStore(hb)
		stats, err := s.runCASGC(ctx, opts)
		if err != nil || stats.Deleted != 0 {
			t.Fatalf("vanished object pass = (%+v, %v), want a skip", stats, err)
		}
	})

	t.Run("object vanishes before verification", func(t *testing.T) {
		s := New("tok")
		hb := newGCHookBlob()
		hb.objects[digest] = blob.Object{Key: digest, SHA256: digest, Size: 3, ModTime: old}
		hb.data[digest] = payload
		hb.openErr = blob.ErrNotFound
		s.SetBlobStore(hb)
		stats, err := s.runCASGC(ctx, opts)
		if err != nil || stats.Deleted != 0 {
			t.Fatalf("unopenable object pass = (%+v, %v), want a skip", stats, err)
		}
	})

	t.Run("delete reports not found", func(t *testing.T) {
		s := New("tok")
		hb := newGCHookBlob()
		hb.objects[digest] = blob.Object{Key: digest, SHA256: digest, Size: int64(len(payload)), ModTime: old}
		hb.data[digest] = payload
		hb.deleteErr = blob.ErrNotFound
		s.SetBlobStore(hb)
		stats, err := s.runCASGC(ctx, opts)
		if err != nil || stats.Deleted != 0 {
			t.Fatalf("already-gone object pass = (%+v, %v), want a skip", stats, err)
		}
	})

	t.Run("delete fails", func(t *testing.T) {
		s := New("tok")
		hb := newGCHookBlob()
		hb.objects[digest] = blob.Object{Key: digest, SHA256: digest, Size: int64(len(payload)), ModTime: old}
		hb.data[digest] = payload
		hb.deleteErr = errors.New("disk wedged")
		s.SetBlobStore(hb)
		if _, err := s.runCASGC(ctx, opts); err == nil || !strings.Contains(err.Error(), "enumerate") {
			t.Fatalf("failed delete = %v, want an enumeration error", err)
		}
	})

	t.Run("enumeration fails", func(t *testing.T) {
		s := New("tok")
		hb := newGCHookBlob()
		hb.objects[digest] = blob.Object{Key: digest, SHA256: digest, Size: 3, ModTime: old}
		hb.listErr = errors.New("storage offline")
		s.SetBlobStore(hb)
		if _, err := s.runCASGC(ctx, opts); err == nil || !strings.Contains(err.Error(), "storage offline") {
			t.Fatalf("failed enumeration = %v", err)
		}
	})

	t.Run("referenced object survives", func(t *testing.T) {
		s := New("tok")
		hb := newGCHookBlob()
		hb.objects[digest] = blob.Object{Key: digest, SHA256: digest, Size: int64(len(payload)), ModTime: old}
		hb.data[digest] = payload
		s.SetBlobStore(hb)
		s.mu.Lock()
		s.artifacts["a1"] = model.ArtifactRecord{ID: "a1", RunID: "run", Name: "bin", SHA256: digest, CreatedAt: time.Now().UTC()}
		s.mu.Unlock()
		stats, err := s.runCASGC(ctx, opts)
		if err != nil || stats.Deleted != 0 || stats.Referenced != 1 {
			t.Fatalf("referenced pass = (%+v, %v), want the object kept", stats, err)
		}
		if _, still := hb.objects[digest]; !still {
			t.Fatal("referenced object was unlinked")
		}
	})
}

// TestMaybeRunCASGCFailureIsLogged covers the maintenance hook's error path:
// after the arming tick, a pass that cannot enumerate is logged and does not
// propagate (housekeeping must not fail the tick).
func TestMaybeRunCASGCFailureIsLogged(t *testing.T) {
	s := New("tok")
	s.SetBlobStore(newMemBlob()) // not a blob.Enumerator
	s.CASGCInterval = time.Nanosecond
	now := time.Now().UTC()
	s.maybeRunCASGC(context.Background(), now)                  // arms the interval
	s.maybeRunCASGC(context.Background(), now.Add(time.Second)) // runs, fails, logs
	if s.casGCLast.IsZero() {
		t.Fatal("collector interval was never armed")
	}
}
