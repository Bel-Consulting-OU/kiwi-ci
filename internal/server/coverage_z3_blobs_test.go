package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestFlowBlobUploadArtifactStagingBudgetBranches covers the artifact staging
// reservation contract that precedes any byte handling: a server without a
// configured bound refuses the upload, a declared body above the whole
// capacity is rejected before staging, a fully reserved budget refuses the
// reservation, and an unknown-length body past its frozen contract is caught
// by the spool bound.
func TestFlowBlobUploadArtifactStagingBudgetBranches(t *testing.T) {
	t.Run("no staging budget", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t, WithStagingBudget(nil))
		fcSeedContract(s, "job-a", fcBinContract())
		w := fcUploadBlobArtifact(t, s, hdrs, "payload")
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "staging budget unavailable") {
			t.Fatalf("artifact upload without a budget = %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("declared length above capacity", func(t *testing.T) {
		s, hdrs, b := fcMemoryBlobServerWithStaging(t, 8)
		fcSeedContract(s, "job-a", fcBinContract())
		r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", strings.NewReader("payload"))
		r.Header.Set("Authorization", "Bearer runner-tok")
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		r.ContentLength = 1 << 20
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "exceeds the staging capacity") {
			t.Fatalf("declared length above capacity = %d: %s", w.Code, w.Body.String())
		}
		if b.Used() != 0 {
			t.Fatalf("budget charged %d bytes for a refused upload", b.Used())
		}
	})

	t.Run("reservation refused", func(t *testing.T) {
		s, hdrs, b := fcMemoryBlobServerWithStaging(t, 8)
		fcSeedContract(s, "job-a", fcBinContract())
		// An unknown-length body reserves the endpoint maximum (the global
		// blob ceiling), which is larger than the whole budget: the request
		// can never be admitted and is refused without staging anything.
		r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", &fcHookReader{data: []byte("payload")})
		r.Header.Set("Authorization", "Bearer runner-tok")
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "capacity unavailable") {
			t.Fatalf("reservation above the budget = %d: %s", w.Code, w.Body.String())
		}
		if b.Used() != 0 {
			t.Fatalf("budget charged %d bytes for an unadmittable request", b.Used())
		}
	})

	t.Run("client gone while waiting for capacity", func(t *testing.T) {
		s, hdrs, b := fcMemoryBlobServerWithStaging(t, 8)
		fcSeedContract(s, "job-a", fcBinContract())
		res, err := b.Acquire(context.Background(), b.MaxBytes())
		if err != nil {
			t.Fatalf("hold the whole budget: %v", err)
		}
		defer res.Release()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", strings.NewReader("pay")).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer runner-tok")
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Fatalf("canceled wait wrote a response: %d %q", w.Code, w.Body.String())
		}
	})

	t.Run("unknown length over contract", func(t *testing.T) {
		s, hdrs, _ := fcMemoryBlobServerWithStaging(t, 1<<20)
		c := fcBinContract()
		c.MaxSize = 4
		fcSeedContract(s, "job-a", c)
		r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", &fcHookReader{data: []byte("0123456789")})
		r.Header.Set("Authorization", "Bearer runner-tok")
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "declared maximum size") {
			t.Fatalf("chunked body over the frozen contract = %d: %s", w.Code, w.Body.String())
		}
		if s.Staging.Used() != 0 {
			t.Fatalf("budget charged %d bytes after the spool bound refused the body", s.Staging.Used())
		}
	})
}

// TestFlowBlobUploadArtifactCommitDefenseBranches covers the commit-time
// resolution of the artifact upload: a store that loses the transactional
// lease-commit capability while the body is in flight fails closed, and the
// memory-mode commit re-resolves the lease and the (job, generation, name)
// key under the same mutex that guards the insert, so a revocation or a
// concurrent writer landing after the handler's early check can never be
// acknowledged.
func TestFlowBlobUploadArtifactCommitDefenseBranches(t *testing.T) {
	t.Run("store loses lease commit capability", func(t *testing.T) {
		s, f, _, hdrs := artifactIdentityFixture(t)
		prev := artifactStageHook
		artifactStageHook = func(string, int64) {
			s.DB = artifactNoLeaseStore{Store: f, DigestFenceStore: f, ArtifactSidecarStore: f}
		}
		defer func() { artifactStageHook = prev }()
		w := fcUploadBlobArtifact(t, s, hdrs, "payload")
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "transactional lease commits") {
			t.Fatalf("commit without a lease-capable store = %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("memory commit observes a revoked lease", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		fcSeedContract(s, "job-a", fcBinContract())
		prev := provenanceSidecarWrite
		provenanceSidecarWrite = func(path string, b []byte, mode os.FileMode) error {
			s.mu.Lock()
			j := s.jobs["job-a"]
			past := time.Now().UTC().Add(-time.Hour)
			j.LeaseExpiresAt = &past
			s.jobs["job-a"] = j
			s.mu.Unlock()
			return prev(path, b, mode)
		}
		defer func() { provenanceSidecarWrite = prev }()
		w := fcUploadBlobArtifact(t, s, hdrs, "payload")
		if w.Code != http.StatusConflict {
			t.Fatalf("revoked-at-commit artifact upload = %d, want 409: %s", w.Code, w.Body.String())
		}
		s.mu.Lock()
		n := len(s.artifacts)
		s.mu.Unlock()
		if n != 0 {
			t.Fatalf("artifact rows after a revoked lease = %d, want 0", n)
		}
	})

	t.Run("memory commit catches a digest conflict", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		fcSeedContract(s, "job-a", fcBinContract())
		prev := provenanceSidecarWrite
		provenanceSidecarWrite = func(path string, b []byte, mode os.FileMode) error {
			s.mu.Lock()
			s.artifacts["race"] = model.ArtifactRecord{ID: "race", RunID: "run-other", JobID: "job-a", JobKey: "build", Name: "bin", LeaseGeneration: 5, SHA256: strings.Repeat("0", 64), CreatedAt: time.Now().UTC()}
			s.mu.Unlock()
			return prev(path, b, mode)
		}
		defer func() { provenanceSidecarWrite = prev }()
		w := fcUploadBlobArtifact(t, s, hdrs, "payload")
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "different digest") {
			t.Fatalf("commit-time digest conflict = %d: %s", w.Code, w.Body.String())
		}
		s.mu.Lock()
		n := len(s.artifacts)
		s.mu.Unlock()
		if n != 1 {
			t.Fatalf("artifact rows after a commit-time conflict = %d, want the pre-existing 1", n)
		}
	})

	t.Run("memory commit resolves an idempotent replay", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		fcSeedContract(s, "job-a", fcBinContract())
		sum := sha256.Sum256([]byte("payload"))
		digest := hex.EncodeToString(sum[:])
		prev := provenanceSidecarWrite
		provenanceSidecarWrite = func(path string, b []byte, mode os.FileMode) error {
			s.mu.Lock()
			s.artifacts["race"] = model.ArtifactRecord{ID: "race-id", RunID: "run-other", JobID: "job-a", JobKey: "build", Name: "bin", LeaseGeneration: 5, SHA256: digest, Size: int64(len("payload")), CreatedAt: time.Now().UTC()}
			s.mu.Unlock()
			return prev(path, b, mode)
		}
		defer func() { provenanceSidecarWrite = prev }()
		w := fcUploadBlobArtifact(t, s, hdrs, "payload")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "race-id") {
			t.Fatalf("commit-time idempotent replay = %d: %s", w.Code, w.Body.String())
		}
		s.mu.Lock()
		n := len(s.artifacts)
		s.mu.Unlock()
		if n != 1 {
			t.Fatalf("artifact rows after a replay = %d, want the pre-existing 1", n)
		}
	})
}

// TestFlowBlobUploadJobCacheCommitBranches covers the cache upload's late
// failure paths: a staged file that cannot be re-hashed after staging fails
// closed before any manifest is written, and the memory-mode commit predicate
// rejects a lease revoked while the body was streamed.
func TestFlowBlobUploadJobCacheCommitBranches(t *testing.T) {
	t.Run("staged file vanishes before hashing", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		prev := cacheStageHook
		cacheStageHook = func(path string, _ int64) { _ = os.Remove(path) }
		defer func() { cacheStageHook = prev }()
		key := strings.Repeat("c", 64)
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("cache upload with a vanished spool = %d, want 500: %s", w.Code, w.Body.String())
		}
		f.mu.Lock()
		n := len(f.cacheMans)
		f.mu.Unlock()
		if n != 0 {
			t.Fatalf("cache manifests after a vanished spool = %d, want 0", n)
		}
	})

	t.Run("memory commit observes a revoked lease", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		prev := cacheStageHook
		cacheStageHook = func(string, int64) {
			s.mu.Lock()
			j := s.jobs["job-a"]
			past := time.Now().UTC().Add(-time.Hour)
			j.LeaseExpiresAt = &past
			s.jobs["job-a"] = j
			s.mu.Unlock()
		}
		defer func() { cacheStageHook = prev }()
		key := strings.Repeat("d", 64)
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs)
		if w.Code != http.StatusConflict {
			t.Fatalf("revoked-at-commit cache upload = %d, want 409: %s", w.Code, w.Body.String())
		}
		if s.Staging != nil && s.Staging.Used() != 0 {
			t.Fatalf("staging remains charged after a refused commit: %d", s.Staging.Used())
		}
	})
}

// TestLeaseActiveAtCommitModes pins the helper's two storage-mode contracts:
// memory mode resolves the live job (missing job or stale lease is false),
// while DB mode delegates authority to the transactional store capability.
func TestLeaseActiveAtCommitModes(t *testing.T) {
	ctx := context.Background()
	mem, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gen := int64(5)
	if mem.leaseActiveAtCommit(ctx, "job-a", "runner-a", "token", gen) {
		t.Fatal("missing job reported an active lease")
	}
	hdrs := seedCacheJob(t, mem, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	token := hdrs["X-Kiwi-Lease-Token"]
	if mem.leaseActiveAtCommit(ctx, "job-a", "runner-a", "wrong-token", gen) {
		t.Fatal("wrong token reported an active lease")
	}
	if !mem.leaseActiveAtCommit(ctx, "job-a", "runner-a", token, gen) {
		t.Fatal("live memory lease reported inactive")
	}
	mem.mu.Lock()
	j := mem.jobs["job-a"]
	j.LeaseGeneration = 6
	mem.jobs["job-a"] = j
	mem.mu.Unlock()
	if mem.leaseActiveAtCommit(ctx, "job-a", "runner-a", token, gen) {
		t.Fatal("stale generation reported an active lease")
	}

	db, f, _, _ := cacheFixture(t)
	if !db.leaseActiveAtCommit(ctx, "job-a", "runner-a", token, gen) {
		t.Fatal("DB mode with a lease-commit store reported inactive")
	}
	db.DB = fcPlainStore{f}
	if db.leaseActiveAtCommit(ctx, "job-a", "runner-a", token, gen) {
		t.Fatal("DB mode without a lease-commit store reported active")
	}
}

// misreportedSizeBlob serves correct bytes under the requested key but
// reports a larger size in the object metadata, exercising the read-back
// size check that a well-behaved backend would never fail.
type misreportedSizeBlob struct {
	data []byte
}

func (b *misreportedSizeBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	d, err := io.ReadAll(r)
	if err != nil {
		return blob.Object{}, err
	}
	b.data = d
	return blob.Object{Key: key, SHA256: key, Size: int64(len(d))}, nil
}

func (b *misreportedSizeBlob) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	if b.data == nil {
		return nil, blob.Object{}, blob.ErrNotFound
	}
	return io.NopCloser(strings.NewReader(string(b.data))), blob.Object{Key: key, SHA256: key, Size: int64(len(b.data)) + 1}, nil
}

func (b *misreportedSizeBlob) Delete(ctx context.Context, key string) error { return nil }

// TestVerifyStoredBlobRejectsMisreportedSize proves the read-back check is
// not satisfied by readable bytes alone: a backend whose object metadata
// advertises a different length than the committed record fails the
// verification even though the content digest matches.
func TestVerifyStoredBlobRejectsMisreportedSize(t *testing.T) {
	payload := []byte("verify-me")
	b := &misreportedSizeBlob{data: payload}
	s := New("tok")
	s.SetBlobStore(b)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	err := verifyStoredBlob(context.Background(), s.CAS, digest, int64(len(payload)))
	if err == nil || !strings.Contains(err.Error(), "reports size") {
		t.Fatalf("verifyStoredBlob = %v, want a reported-size mismatch", err)
	}
}

// TestCopyFileIntoPlaceFailureBranches covers the cross-filesystem
// finalization's fail-closed branches: an unreadable source, a source that
// cannot be streamed, and a destination that refuses the publish all return
// the error without leaving a partial destination in place.
func TestCopyFileIntoPlaceFailureBranches(t *testing.T) {
	dir := t.TempDir()
	if err := copyFileIntoPlace(filepath.Join(dir, "missing"), filepath.Join(dir, "dst")); err == nil {
		t.Fatal("missing source accepted")
	}

	// A directory opens successfully but cannot be streamed: the copy step
	// must fail and clean up its destination-local temp file.
	srcDir := filepath.Join(dir, "src-dir")
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst-copy")
	if err := copyFileIntoPlace(srcDir, dst); err == nil {
		t.Fatal("directory source streamed as a file")
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination exists after a failed copy: %v", err)
	}

	// A destination that is a directory refuses the final rename.
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	dstDir := filepath.Join(dir, "dst-dir")
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := copyFileIntoPlace(src, dstDir); err == nil {
		t.Fatal("rename onto a directory unexpectedly succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".dst-dir.tmp-") {
			t.Fatalf("temp file left behind after a failed rename: %s", e.Name())
		}
	}
}

// TestRunCASGCSkipsUnverifiableObjects drives the content re-verification
// inside one collection pass: an unreferenced, aged object whose stored bytes
// no longer hash to the enumerated digest is skipped (never unlinked), while
// the pass completes without error and keeps the object.
func TestRunCASGCSkipsUnverifiableObjects(t *testing.T) {
	s, fs := casGCTestServer(t)
	obj := putCASBlob(t, s, "original payload")
	ageCASBlob(t, s, obj.SHA256, 48*time.Hour)
	path := filepath.Join(fs.Root, "sha256", obj.SHA256[:2], obj.SHA256)
	if err := os.WriteFile(path, []byte("replaced bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: time.Hour, Batch: 10, Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if stats.Enumerated != 1 || stats.Deleted != 0 {
		t.Fatalf("stats = %+v, want 1 enumerated and 0 deleted (unverifiable content)", stats)
	}
	if !casBlobExists(t, s, obj.SHA256) {
		t.Fatal("unverifiable object was deleted")
	}
}
