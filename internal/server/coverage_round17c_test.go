package server

// Coverage round, part 3: snapshot upload/delete failure arms, jobInRun
// resolution arms and the test-intelligence authorization helpers.

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// r17DeleteSnapshotStore adds the optional durable snapshot-deletion
// capability to the fake store.
type r17DeleteSnapshotStore struct {
	*dbFakeStore
	deleted bool
	err     error
	calls   int
}

func (r *r17DeleteSnapshotStore) DeleteSnapshotRecord(context.Context, string, string) (bool, error) {
	r.calls++
	return r.deleted, r.err
}

// TestSnapshotUploadMemoryCommitCap covers the commit-time per-job cap in
// memory mode: a record that the run-scoped preflight count cannot see (it
// belongs to another run) still trips the job-scoped cap under the commit
// mutex, and the staged archive is removed.
func TestSnapshotUploadMemoryCommitCap(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t, WithSnapshotMaxPerJob(1))
	s.mu.Lock()
	s.snapshots["seed-other-run"] = model.SnapshotRecord{ID: "seed-other-run", RunID: "other-run", JobID: "job-a", Path: "cas:" + strings.Repeat("a", 64)}
	s.mu.Unlock()

	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusConflict {
		t.Fatalf("commit-time cap = %d, want 409: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "snapshot limit reached") {
		t.Fatalf("cap body = %q", w.Body.String())
	}
	// The rejected upload removed its archive and manifest pair.
	dir := strings.Join([]string{s.store.Root, "snapshots", "run-c", "job-a"}, "/")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read snapshot dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected upload left %v", entries)
	}
}

// TestSnapshotUploadSyncDirFailure covers the memory-mode parent-directory
// fsync failure: the archive is removed and the upload fails closed.
func TestSnapshotUploadSyncDirFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(string) error { return errors.New("dir fsync refused") }})
	defer restore()

	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("sync failure = %d, want 500: %s", w.Code, w.Body.String())
	}
	dir := strings.Join([]string{s.store.Root, "snapshots", "run-c", "job-a"}, "/")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read snapshot dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed upload left %v", entries)
	}
}

// TestSnapshotUploadDBClosedStagingBudget covers the DB-mode staging refusal
// for a closed budget: the upload answers 503 without spooling or touching
// the CAS.
func TestSnapshotUploadDBClosedStagingBudget(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	if err := s.StagingBudget().Close(); err != nil {
		t.Fatalf("close staging budget: %v", err)
	}
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed-budget db snapshot = %d, want 503: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "snapshot staging capacity unavailable") {
		t.Fatalf("closed-budget db snapshot body = %q", w.Body.String())
	}
}

// TestDeleteSnapshotDBStoreResult covers the DB-mode deletion return and the
// unsupported-store refusal.
func TestDeleteSnapshotDBStoreResult(t *testing.T) {
	ctx := context.Background()

	f := &r17DeleteSnapshotStore{dbFakeStore: newDBFakeStore(), deleted: true}
	s := New("t")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ok, err := s.DeleteSnapshot(ctx, "run-1", "snap-1")
	if err != nil || !ok || f.calls != 1 {
		t.Fatalf("db delete = (%v, %v), calls=%d want (true, nil, 1)", ok, err, f.calls)
	}

	plain := New("t")
	plain.DB = struct{ storage.Store }{}
	if _, err := plain.DeleteSnapshot(ctx, "run-1", "snap-1"); err == nil {
		t.Fatal("delete against a store without the capability succeeded")
	}
}

// TestJobInRunArms covers the resolution arms: empty reference, hard store
// errors from both the primary lookup and the fallback list, and a reference
// that matches nothing.
func TestJobInRunArms(t *testing.T) {
	ctx := context.Background()

	t.Run("empty ref", func(t *testing.T) {
		s := New("t")
		if _, ok, err := s.jobInRun(ctx, "run-1", ""); ok || err != nil {
			t.Fatalf("empty ref = (%v, %v), want (false, nil)", ok, err)
		}
	})

	t.Run("primary lookup error", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("t")
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.getJobErr = errors.New("store down")
		f.mu.Unlock()
		if _, _, err := s.jobInRun(ctx, "run-1", "job-1"); err == nil {
			t.Fatal("primary lookup error was swallowed")
		}
	})

	t.Run("fallback list error", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("t")
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.listJobsByRunErr = errors.New("list down")
		f.mu.Unlock()
		if _, _, err := s.jobInRun(ctx, "run-1", "missing"); err == nil {
			t.Fatal("fallback list error was swallowed")
		}
	})

	t.Run("unmatched reference", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("t")
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.jobInRun(ctx, "run-1", "missing"); ok || err != nil {
			t.Fatalf("unmatched ref = (%v, %v), want (false, nil)", ok, err)
		}
	})
}

// TestTestIntelligenceHelperArms covers the helper-level arms: blank resolved
// ids, alias/identity grant mismatches and canonical-vs-alias query forms.
func TestTestIntelligenceHelperArms(t *testing.T) {
	s := New("t")
	r := httptest.NewRequest(http.MethodGet, "/api/v1/test-intelligence?repo=acme/app", nil)

	if got := s.authorizedTestHistoryRepoIDs(r, []string{"", "  ", "acme/app"}); len(got) != 1 || got[0] != "acme/app" {
		t.Fatalf("authorized ids = %v, want the single non-blank id", got)
	}

	principal := auth.Principal{
		Subject: "dev",
		Repositories: map[string]auth.RepositoryPermission{
			"acme/other":             {}, // alias for another repo
			"github.com/acme/other":  {}, // canonical identity for another repo
			"not a parseable grant!": {}, // unparseable key
		},
	}
	gr := r.WithContext(auth.WithPrincipal(r.Context(), principal))
	if got := s.testHistoryPermittedRepoIDs(gr, "acme/app"); len(got) != 0 {
		t.Fatalf("alias-query permitted ids = %v, want none", got)
	}
	if got := s.testHistoryPermittedRepoIDs(gr, "github.com/acme/app"); len(got) != 0 {
		t.Fatalf("canonical-query permitted ids = %v, want none", got)
	}

	// A bare grant for the queried name keeps resolution unrestricted: every
	// forge presenting the name must still be discoverable.
	bare := auth.Principal{
		Subject:      "dev",
		Repositories: map[string]auth.RepositoryPermission{"acme/app": {}},
	}
	br := r.WithContext(auth.WithPrincipal(r.Context(), bare))
	if got := s.testHistoryPermittedRepoIDs(br, "acme/app"); got != nil {
		t.Fatalf("bare-grant permitted ids = %v, want nil (unrestricted)", got)
	}
}

// r17FenceFailStore makes the optional digest-fence acquisition fail, which
// exercises the artifact upload's fence refusal in CAS mode.
type r17FenceFailStore struct{ *dbFakeStore }

func (r *r17FenceFailStore) AcquireDigestFence(context.Context, string) (func(), error) {
	return nil, errors.New("seam: digest fence refused")
}

// itArtifactFixture builds a DB-mode CAS server (optional fence failure) plus
// the server-side job/run a direct uploadArtifactPayload call needs.
func itArtifactFixture(t *testing.T, fenceErr bool) (*Server, model.Job, model.Run, string) {
	t.Helper()
	var f *dbFakeStore
	var db storage.Store
	if fenceErr {
		ff := &r17FenceFailStore{dbFakeStore: newDBFakeStore()}
		f = ff.dbFakeStore
		db = ff
	} else {
		f = newDBFakeStore()
		db = f
	}
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(db); err != nil {
		t.Fatal(err)
	}
	s.SetBlobStore(newMemBlob())
	const raw = "cache-lease-token"
	seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	s.mu.Lock()
	j := s.jobs["job-a"]
	run := s.runs["run-c"]
	s.mu.Unlock()
	exp := time.Now().UTC().Add(time.Hour)
	f.mu.Lock()
	f.runs["run-c"] = run
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", RepoURL: j.RepoURL, RepoFullName: j.RepoFullName,
		Status: model.StatusRunning, Trusted: true, LeaseRunnerID: "runner-a", LeaseTokenHash: hashLeaseToken(s.leaseKey, raw), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	f.mu.Unlock()
	return s, j, run, raw
}

// TestArtifactUploadClosedStagingBudget covers the non-budget staging refusal
// on the artifact path: the closed budget answers 500 instead of spooling.
func TestArtifactUploadClosedStagingBudget(t *testing.T) {
	s, _, b := fcMemoryBlobServerWithStaging(t, 1<<20)
	if err := b.Close(); err != nil {
		t.Fatalf("close budget: %v", err)
	}
	s.mu.Lock()
	j := s.jobs["job-a"]
	run := s.runs["run-c"]
	s.mu.Unlock()
	body := []byte("artifact-closed-budget")
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	s.uploadArtifactPayload(w, r, j, run, storage.ArtifactContract{Name: "bin"}, "bin", "runner-a", "cache-lease-token", j.LeaseGeneration)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("closed-budget artifact = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// TestArtifactUploadDigestFenceFailure covers the payload digest-fence
// refusal before CAS publication.
func TestArtifactUploadDigestFenceFailure(t *testing.T) {
	s, j, run, raw := itArtifactFixture(t, true)
	body := []byte("artifact-fence-payload")
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	s.uploadArtifactPayload(w, r, j, run, storage.ArtifactContract{Name: "bin"}, "bin", "runner-a", raw, j.LeaseGeneration)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("fence-failure artifact = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// TestArtifactUploadGenerationRecheck covers the last-moment lease-generation
// re-assertion: a request generation that no longer matches the loaded job is
// refused with 409 before provenance signing, and no record is committed.
func TestArtifactUploadGenerationRecheck(t *testing.T) {
	s, j, run, raw := itArtifactFixture(t, false)
	stale := j
	stale.LeaseGeneration = j.LeaseGeneration + 1
	body := []byte("artifact-generation-payload")
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	s.uploadArtifactPayload(w, r, stale, run, storage.ArtifactContract{Name: "bin"}, "bin", "runner-a", raw, j.LeaseGeneration)
	if w.Code != http.StatusConflict {
		t.Fatalf("generation mismatch artifact = %d, want 409: %s", w.Code, w.Body.String())
	}
	records, err := s.DB.ListArtifacts(context.Background(), "run-c")
	if err != nil {
		t.Fatalf("list artifacts: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("generation conflict committed %d artifact record(s)", len(records))
	}
}

// TestCopyFileIntoPlaceCopyFailure covers the cross-filesystem finalization's
// stream failure: a source that opens but cannot be read (a directory) leaves
// no destination and no temp litter.
func TestCopyFileIntoPlaceCopyFailure(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src-dir")
	if err := os.Mkdir(src, 0o700); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst.bin")
	if err := copyFileIntoPlace(src, dst); err == nil {
		t.Fatal("copy from an unreadable directory succeeded")
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed copy left a destination: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "src-dir" {
		t.Fatalf("failed copy left temp litter: %v", entries)
	}
}

// TestLimitPlusOneSaturation pins the overflow guard: MaxInt64 is returned
// unchanged so the caller's bound is never turned into a rejection.
func TestLimitPlusOneSaturation(t *testing.T) {
	if got := limitPlusOne(math.MaxInt64); got != math.MaxInt64 {
		t.Fatalf("limitPlusOne(MaxInt64) = %d, want MaxInt64", got)
	}
	if got := limitPlusOne(4); got != 5 {
		t.Fatalf("limitPlusOne(4) = %d, want 5", got)
	}
}

// TestSnapshotValidateUnreadableArchive covers the snapshot file validator's
// stream failure: a directory path opens but cannot be hashed.
func TestSnapshotValidateUnreadableArchive(t *testing.T) {
	dir := t.TempDir()
	rec := model.SnapshotRecord{ID: "snap-1", Path: dir}
	if err := validateSnapshotFiles(rec); err == nil {
		t.Fatal("validator over an unreadable archive succeeded")
	}
}
