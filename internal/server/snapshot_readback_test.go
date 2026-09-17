package server

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
)

// truncatingBlob is a blob.Store whose Put silently stores only the first
// half of the bytes it is handed while reporting success (and an honest
// object), simulating a backend that truncates an archive write. The CAS
// digest check and the upload read-back must both reject such an object.
type truncatingBlob struct {
	inner *memBlob
}

func (b *truncatingBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return blob.Object{}, err
	}
	half := len(data) / 2
	if half < 1 {
		half = 1
	}
	b.inner.mu.Lock()
	b.inner.objects[key] = data[:half]
	b.inner.mu.Unlock()
	return blob.Object{Key: key, SHA256: key, Size: size}, nil
}

func (b *truncatingBlob) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	return b.inner.Open(ctx, key)
}

func (b *truncatingBlob) Delete(ctx context.Context, key string) error {
	return b.inner.Delete(ctx, key)
}

// TestFlowSnapshotDBUploadReadBackDetectsTruncation is the regression test
// for the missing read-back: an archive that is truncated by the blob layer
// after a successful CAS.Put must fail the upload with 503, and no snapshot
// record may be persisted for it.
func TestFlowSnapshotDBUploadReadBackDetectsTruncation(t *testing.T) {
	s, f, mb, hdrs := cacheFixture(t)
	s.SetBlobStore(&truncatingBlob{inner: mb})
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("truncated snapshot upload = %d, want 503: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	persisted := len(f.snapshots)
	f.mu.Unlock()
	if persisted != 0 {
		t.Fatalf("snapshot record persisted despite read-back failure (%d records)", persisted)
	}
}

// TestFlowSnapshotDBUploadReadBackAcceptsHonestStore proves the read-back
// does not reject healthy uploads: the honest in-memory store still yields
// 201 with a CAS-path record.
func TestFlowSnapshotDBUploadReadBackAcceptsHonestStore(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusCreated {
		t.Fatalf("honest snapshot upload = %d, want 201: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.snapshots) != 1 || f.snapshots[0].Path == "" {
		t.Fatalf("snapshot record = %+v", f.snapshots)
	}
}
