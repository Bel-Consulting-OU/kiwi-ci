package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// memBlob is an observable in-memory blob.Store for CAS-level cache tests.
type memBlob struct {
	mu      sync.Mutex
	objects map[string][]byte
	deleted []string
}

func newMemBlob() *memBlob { return &memBlob{objects: map[string][]byte{}} }

func (m *memBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	b, err := io.ReadAll(io.LimitReader(r, size+1))
	if err != nil {
		return blob.Object{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = b
	return blob.Object{Key: key, SHA256: key, Size: int64(len(b))}, nil
}

func (m *memBlob) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[key]
	if !ok {
		return nil, blob.Object{}, blob.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), blob.Object{Key: key, SHA256: key, Size: int64(len(b))}, nil
}

func (m *memBlob) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	m.deleted = append(m.deleted, key)
	return nil
}

// cacheFixture wires a DB-mode server with a seeded leased job and an
// observable CAS blob store.
func cacheFixture(t *testing.T) (*Server, *dbFakeStore, *memBlob, map[string]string) {
	t.Helper()
	f := newDBFakeStore()
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	mb := newMemBlob()
	s.SetBlobStore(mb)
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	f.mu.Lock()
	f.runs["run-c"] = model.Run{ID: "run-c", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning}
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a",
		Status: model.StatusRunning, Trusted: true, LeaseRunnerID: "runner-a", LeaseTokenHash: hashLeaseToken(s.leaseKey, "cache-lease-token"), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	f.runners["runner-a"] = model.Runner{ID: "runner-a", Name: "runner-a", Capacity: 1}
	f.mu.Unlock()
	return s, f, mb, hdrs
}

// TestCacheUploadManifestFailureRemovesBlobAndFails proves the durable
// manifest contract: when the manifest row cannot be committed the upload
// returns 5xx and the CAS blob is removed (no orphan without a signed
// mapping), and no 201 is ever sent.
func TestCacheUploadManifestFailureRemovesBlobAndFails(t *testing.T) {
	s, f, mb, hdrs := cacheFixture(t)
	key := strings.Repeat("a", 64)
	f.mu.Lock()
	f.cacheManErr = fmt.Errorf("manifest table down")
	f.mu.Unlock()

	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload-bytes", hdrs)
	if w.Code < 500 {
		t.Fatalf("cache put with failing manifest store = %d, want 5xx", w.Code)
	}
	if strings.Contains(w.Body.String(), "201") || w.Code == http.StatusCreated {
		t.Fatal("upload acknowledged despite manifest failure")
	}
	mb.mu.Lock()
	objs := len(mb.objects)
	deleted := len(mb.deleted)
	mb.mu.Unlock()
	if objs != 0 {
		t.Fatalf("CAS blob left behind after manifest failure: %d objects", objs)
	}
	if deleted != 1 {
		t.Fatalf("orphan blob removals = %d, want 1", deleted)
	}
	f.mu.Lock()
	rows := len(f.cacheMans)
	f.mu.Unlock()
	if rows != 0 {
		t.Fatalf("manifest rows = %d, want 0", rows)
	}
}

// TestCacheDownloadDBModeVerifiesEnvelope proves DB-mode restore verifies
// the signed envelope exactly like fs mode: a tampered envelope serves
// nothing, and a digest mismatch between the row and the verified envelope
// serves nothing — never a corrupt payload.
func TestCacheDownloadDBModeVerifiesEnvelope(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	key := strings.Repeat("b", 64)
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "genuine-payload", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("cache put = %d: %s", w.Code, w.Body.String())
	}
	// Unmodified row serves the payload.
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs); w.Code != http.StatusOK || w.Body.String() != "genuine-payload" {
		t.Fatalf("cache get = %d %q", w.Code, w.Body.String())
	}

	// Tampered envelope (flipped signature byte): verification fails and no
	// payload is served.
	f.mu.Lock()
	rec := f.cacheMans["o/repo-a\x00trusted\x00"+key]
	env := append([]byte(nil), rec.Envelope...)
	last := len(env) - 1
	env[last] ^= 0xff
	rec.Envelope = env
	f.cacheMans["o/repo-a\x00trusted\x00"+key] = rec
	f.mu.Unlock()
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs)
	if w.Code == http.StatusOK {
		t.Fatalf("tampered envelope served: %d %q", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "genuine-payload") {
		t.Fatal("tampered envelope leaked the payload")
	}

	// Restore a valid envelope by re-uploading, then break the row digest:
	// the verified envelope no longer matches the row and the download
	// refuses.
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "genuine-payload", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("re-put = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	rec = f.cacheMans["o/repo-a\x00trusted\x00"+key]
	rec.BlobSHA256 = strings.Repeat("c", 64)
	f.cacheMans["o/repo-a\x00trusted\x00"+key] = rec
	f.mu.Unlock()
	w = doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs)
	if w.Code == http.StatusOK {
		t.Fatalf("digest-mismatched row served: %d %q", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "genuine-payload") {
		t.Fatal("digest-mismatched row leaked the payload")
	}
}
