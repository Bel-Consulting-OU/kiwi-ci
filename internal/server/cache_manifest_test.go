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
// observable CAS blob store. Construction-time options (for example
// WithStagingBudget) are passed to the persistent constructor, since staging
// is immutable after construction.
func cacheFixture(t *testing.T, opts ...Option) (*Server, *dbFakeStore, *memBlob, map[string]string) {
	t.Helper()
	f := newDBFakeStore()
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir(), opts...)
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

// TestCacheManifestFailureKeepsSharedCASBlobAndFails proves the durable
// manifest contract WITHOUT the blind rollback delete: when the manifest row
// cannot be committed the upload returns 5xx and never a 201, but a CAS
// digest shared with an existing record is left untouched (the reference-
// aware blob GC owns reclamation) — the pre-existing cache entry still
// resolves its bytes afterwards.
func TestCacheManifestFailureKeepsSharedCASBlobAndFails(t *testing.T) {
	s, f, mb, hdrs := cacheFixture(t)
	keyA := strings.Repeat("a", 64)
	payload := "shared-payload-bytes"
	// Job A commits digest X under its signed manifest.
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+keyA, "runner-tok", payload, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("seed cache put = %d: %s", w.Code, w.Body.String())
	}
	digest := sha256Hex([]byte(payload))

	// Job B uploads IDENTICAL bytes under a different logical key: CAS
	// deduplicates to X, and the manifest persist fails.
	hdrsB := seedCacheJob(t, s, "job-b", "runner-b", "https://github.com/o/repo-a.git", "o/repo-a", true)
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	f.mu.Lock()
	f.jobs["job-b"] = model.Job{ID: "job-b", RunID: "run-c", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a",
		Status: model.StatusRunning, Trusted: true, LeaseRunnerID: "runner-b", LeaseTokenHash: hashLeaseToken(s.leaseKey, "cache-lease-token"), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	f.runners["runner-b"] = model.Runner{ID: "runner-b", Name: "runner-b", Capacity: 1}
	f.cacheManErr = fmt.Errorf("manifest table down")
	f.mu.Unlock()

	keyB := strings.Repeat("b", 64)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-b/cache/"+keyB, "runner-tok", payload, hdrsB)
	if w.Code < 500 {
		t.Fatalf("cache put with failing manifest store = %d, want 5xx", w.Code)
	}
	if w.Code == http.StatusCreated {
		t.Fatal("upload acknowledged despite manifest failure")
	}

	// X survives: no blind delete was issued and the blob is still openable.
	mb.mu.Lock()
	_, present := mb.objects[digest]
	deleted := len(mb.deleted)
	mb.mu.Unlock()
	if !present {
		t.Fatalf("shared CAS digest %s was deleted by the failed upload", digest)
	}
	if deleted != 0 {
		t.Fatalf("CAS deletes issued = %d, want 0 (no blind rollback)", deleted)
	}
	rc, _, err := s.CAS.Open(context.Background(), digest)
	if err != nil {
		t.Fatalf("CAS open after failed upload: %v", err)
	}
	rc.Close()

	// The record referencing X still downloads byte-identically.
	w = doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+keyA, "runner-tok", "", hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("pre-existing cache entry after failed upload = %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != payload {
		t.Fatalf("cache payload = %q, want %q", w.Body.String(), payload)
	}
	if got := w.Header().Get("X-Kiwi-Cache-SHA256"); got != digest {
		t.Fatalf("cache digest header = %q, want %q", got, digest)
	}
	// The failed key B has no signed mapping: it stays a miss.
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-b/cache/"+keyB, "runner-tok", "", hdrsB); w.Code != http.StatusNotFound {
		t.Fatalf("failed cache key = %d, want 404", w.Code)
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
	rec := f.cacheMans["github.com/o/repo-a\x00trusted\x00"+key]
	env := append([]byte(nil), rec.Envelope...)
	last := len(env) - 1
	env[last] ^= 0xff
	rec.Envelope = env
	f.cacheMans["github.com/o/repo-a\x00trusted\x00"+key] = rec
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
	rec = f.cacheMans["github.com/o/repo-a\x00trusted\x00"+key]
	rec.BlobSHA256 = strings.Repeat("c", 64)
	f.cacheMans["github.com/o/repo-a\x00trusted\x00"+key] = rec
	f.mu.Unlock()
	w = doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs)
	if w.Code == http.StatusOK {
		t.Fatalf("digest-mismatched row served: %d %q", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "genuine-payload") {
		t.Fatal("digest-mismatched row leaked the payload")
	}
}
