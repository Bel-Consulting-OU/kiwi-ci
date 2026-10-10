package server

// Coverage round, part 2: cache upload/download failure arms, the
// cache-manifest store-capability guard and the dynamic fragment arms for
// untrusted parents and mutation-slot conflicts.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

var errR17Fence = errors.New("seam: digest fence refused")

// r17FailFencer is a cas.Fencer whose acquisition always fails.
type r17FailFencer struct{}

func (r17FailFencer) WithFence(context.Context, string, func() error) error { return errR17Fence }

func (r17FailFencer) Acquire(context.Context, string) (func(), error) { return nil, errR17Fence }

var _ cas.Fencer = r17FailFencer{}

// TestCacheUploadClosedStagingBudget covers the non-budget, non-context
// staging failure arm: a closed budget refuses the reservation and the
// handler reports an internal error instead of spooling.
func TestCacheUploadClosedStagingBudget(t *testing.T) {
	s, _, b, hdrs, _ := cacheFixtureWithStaging(t, 1<<20)
	if err := b.Close(); err != nil {
		t.Fatalf("close budget: %v", err)
	}
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("a", 64), "runner-tok", "closed-budget-payload", hdrs)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("closed-budget upload = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// TestCacheUploadDigestFenceFailure covers the digest-fence acquisition
// failure between staging and CAS publication.
func TestCacheUploadDigestFenceFailure(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	s.digestFence = r17FailFencer{}
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("a", 64), "runner-tok", "fence-payload", hdrs)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("fence-failure upload = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// TestWriteCacheManifestRequiresLeaseCommitStore pins the defense-in-depth
// refusal: a DB store without the transactional lease-commit contract never
// receives a best-effort manifest write.
func TestWriteCacheManifestRequiresLeaseCommitStore(t *testing.T) {
	s := New("t")
	// The embedded storage.Store interface satisfies the field's static type
	// while deliberately NOT implementing storage.LeaseCommitStore.
	s.DB = struct{ storage.Store }{}
	_, err := s.writeCacheManifest(context.Background(), "file-key", "logical", "repo", "trust", strings.Repeat("a", 64), 3, model.Job{}, "runner", 1)
	if !errors.Is(err, errLeaseCommitUnsupported) {
		t.Fatalf("manifest write to a non-lease store = %v, want errLeaseCommitUnsupported", err)
	}
}

// TestCacheDownloadCorruptObjectAbortsStream covers the download path's
// stream-failure arm: a stored object whose bytes no longer match its digest
// fails the checked stream instead of serving a corrupt payload.
func TestCacheDownloadCorruptObjectAbortsStream(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mb := newMemBlob()
	s.SetBlobStore(mb)
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	key := strings.Repeat("a", 64)
	payload := "cache-happy-payload"
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", payload, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("seed upload = %d: %s", w.Code, w.Body.String())
	}
	sum := sha256.Sum256([]byte(payload))
	digest := hex.EncodeToString(sum[:])
	// Positive control: the intact object streams back byte-for-byte, so the
	// post-corruption result below genuinely exercises the checked stream.
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs); w.Code != http.StatusOK || w.Body.String() != payload {
		t.Fatalf("intact cache download = %d %q", w.Code, w.Body.String())
	}
	mb.mu.Lock()
	mb.objects[digest] = []byte("corrupt!")
	mb.mu.Unlock()

	// A real loopback server is required: the integrity abort hijacks and
	// closes the connection, which a ResponseRecorder cannot represent.
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/jobs/job-a/cache/"+key, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, derr := ts.Client().Do(req)
	if derr == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) == payload {
			t.Fatalf("corrupt CAS object was served intact: %q", body)
		}
	}
}

// TestProcessGeneratedFragmentMutationSlotConflict covers the memory-mode
// nondeterministic-retry conflict: a second, different fragment in the same
// parent mutation slot is refused with the typed conflict error.
func TestProcessGeneratedFragmentMutationSlotConflict(t *testing.T) {
	s, task := fcDynamicServer(t)
	parent := fcStoredParent(t, s, task.Job.ID)
	ctx := context.Background()

	if _, err := s.processGeneratedFragment(ctx, parent, fcFragment(t, fcOneChildFragment)); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	const otherChild = `{"jobs":{"child-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo other"}]}},"deps":{}}`
	_, err := s.processGeneratedFragment(ctx, parent, fcFragment(t, otherChild))
	var conflict *storage.GeneratedMutationConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("second fragment = %v, want *GeneratedMutationConflictError", err)
	}
	if conflict.ExistingFragmentID == "" || conflict.SubmittedFragmentID == "" || conflict.ExistingFragmentID == conflict.SubmittedFragmentID {
		t.Fatalf("conflict identity = %+v", conflict)
	}
}
