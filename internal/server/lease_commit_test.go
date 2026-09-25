package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// leaseFakeStore is a DB-mode test store that implements storage.
// LeaseCommitStore by evaluating the live-lease predicate against the wrapped
// fake's jobs at commit time, and counts which commit path the handler used.
// It deliberately shadows the plain insert methods so a test can prove the
// handler took the lease-fenced path (and not the fallback).
type leaseFakeStore struct {
	*dbFakeStore

	mu        sync.Mutex
	forceLost bool
	leaseCall int
	plainCall int
}

func (f *leaseFakeStore) setForceLost(v bool) {
	f.mu.Lock()
	f.forceLost = v
	f.mu.Unlock()
}

func (f *leaseFakeStore) calls() (lease, plain int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.leaseCall, f.plainCall
}

// leaseLive reports whether the wrapped store's job currently satisfies the
// commit-time predicate (running, same runner+generation, unexpired).
func (f *leaseFakeStore) leaseLive(jobID, runnerID string, generation int64) bool {
	f.dbFakeStore.mu.Lock()
	defer f.dbFakeStore.mu.Unlock()
	j, ok := f.dbFakeStore.jobs[jobID]
	if !ok {
		return false
	}
	return j.Status == model.StatusRunning && j.LeaseRunnerID == runnerID &&
		j.LeaseGeneration == generation && j.LeaseExpiresAt != nil && j.LeaseExpiresAt.After(time.Now().UTC())
}

func (f *leaseFakeStore) leaseOK(jobID, runnerID string, generation int64) bool {
	f.mu.Lock()
	lost := f.forceLost
	f.leaseCall++
	f.mu.Unlock()
	return !lost && f.leaseLive(jobID, runnerID, generation)
}

func (f *leaseFakeStore) PutCacheManifestForLease(ctx context.Context, jobID, runnerID string, generation int64, rec storage.CacheManifestRecord) error {
	if !f.leaseOK(jobID, runnerID, generation) {
		return fmt.Errorf("%w: cache manifest", storage.ErrLeaseLost)
	}
	return f.dbFakeStore.PutCacheManifest(ctx, rec)
}

func (f *leaseFakeStore) InsertSnapshotForLease(ctx context.Context, jobID, runnerID string, generation int64, maxPerJob int, rec model.SnapshotRecord) error {
	if !f.leaseOK(jobID, runnerID, generation) {
		return fmt.Errorf("%w: snapshot", storage.ErrLeaseLost)
	}
	if maxPerJob > 0 {
		f.mu.Lock()
		n := 0
		for _, existing := range f.snapshots {
			if existing.RunID == rec.RunID && existing.JobID == rec.JobID {
				n++
			}
		}
		f.mu.Unlock()
		if n >= maxPerJob {
			return fmt.Errorf("%w: job %s already has %d snapshots", storage.ErrSnapshotCapReached, jobID, n)
		}
	}
	return f.dbFakeStore.InsertSnapshotRecord(ctx, rec)
}

func (f *leaseFakeStore) InsertArtifactOnceForLease(ctx context.Context, jobID, runnerID string, generation int64, a model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	if !f.leaseOK(jobID, runnerID, generation) {
		return model.ArtifactRecord{}, false, fmt.Errorf("%w: artifact", storage.ErrLeaseLost)
	}
	return f.dbFakeStore.InsertArtifactOnce(ctx, a)
}

func (f *leaseFakeStore) PutCacheManifest(ctx context.Context, rec storage.CacheManifestRecord) error {
	f.mu.Lock()
	f.plainCall++
	f.mu.Unlock()
	return f.dbFakeStore.PutCacheManifest(ctx, rec)
}

func (f *leaseFakeStore) InsertSnapshotRecord(ctx context.Context, rec model.SnapshotRecord) error {
	f.mu.Lock()
	f.plainCall++
	f.mu.Unlock()
	return f.dbFakeStore.InsertSnapshotRecord(ctx, rec)
}

func (f *leaseFakeStore) InsertArtifactOnce(ctx context.Context, a model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	f.mu.Lock()
	f.plainCall++
	f.mu.Unlock()
	return f.dbFakeStore.InsertArtifactOnce(ctx, a)
}

// TestCacheUploadUsesLeaseFencedCommit proves the cache handler commits
// through the lease-fenced store method (not the plain upsert) in DB mode.
func TestCacheUploadUsesLeaseFencedCommit(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	lf := &leaseFakeStore{dbFakeStore: f}
	s.DB = lf
	key := strings.Repeat("a", 64)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("cache put = %d: %s", w.Code, w.Body.String())
	}
	lease, plain := lf.calls()
	if lease != 1 || plain != 0 {
		t.Fatalf("commit path = lease:%d plain:%d, want lease-only", lease, plain)
	}
}

// TestCacheUploadLeaseRevokedDuringUploadReturns409 is the P1 regression: the
// lease is revoked (here: expired) AFTER the body is fully staged and before
// the manifest commit. The transactional predicate must reject it with 409
// and commit NO manifest, even though the handler-side late check would not
// have observed the revocation in its own read.
func TestCacheUploadLeaseRevokedDuringUploadReturns409(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	lf := &leaseFakeStore{dbFakeStore: f}
	s.DB = lf
	prev := cacheStageHook
	cacheStageHook = func(string, int64) {
		f.mu.Lock()
		j := f.jobs["job-a"]
		past := time.Now().UTC().Add(-time.Minute)
		j.LeaseExpiresAt = &past
		f.jobs["job-a"] = j
		f.mu.Unlock()
	}
	defer func() { cacheStageHook = prev }()

	key := strings.Repeat("b", 64)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs)
	if w.Code != http.StatusConflict {
		t.Fatalf("revoked cache put = %d, want 409: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	n := len(f.cacheMans)
	f.mu.Unlock()
	if n != 0 {
		t.Fatalf("cache manifests = %d, want 0 after a revoked lease", n)
	}
}

// TestSnapshotUploadUsesLeaseFencedCommitAndRejectsLostLease covers the
// snapshot handler: the live lease commits through the fenced method, and a
// predicate rejected at commit time answers 409 and records nothing.
func TestSnapshotUploadUsesLeaseFencedCommitAndRejectsLostLease(t *testing.T) {
	f := newDBFakeStore()
	s, runnerID, jobID, task, c := snapshotCASServer(t, f, t.TempDir())
	lf := &leaseFakeStore{dbFakeStore: f}
	s.DB = lf
	body, _ := snapshotArchive(t)

	if w := uploadSnapshotCAS(t, c, jobID, runnerID, task, body); w.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d: %s", w.Code, w.Body.String())
	}
	lease, plain := lf.calls()
	if lease != 1 || plain != 0 {
		t.Fatalf("snapshot commit path = lease:%d plain:%d, want lease-only", lease, plain)
	}

	// A fresh job for the rejected path.
	f2 := newDBFakeStore()
	s2, runnerID2, jobID2, task2, c2 := snapshotCASServer(t, f2, t.TempDir())
	lf2 := &leaseFakeStore{dbFakeStore: f2}
	s2.DB = lf2
	lf2.setForceLost(true)
	w := uploadSnapshotCAS(t, c2, jobID2, runnerID2, task2, body)
	if w.Code != http.StatusConflict {
		t.Fatalf("lost-lease snapshot upload = %d, want 409: %s", w.Code, w.Body.String())
	}
	f2.mu.Lock()
	n := len(f2.snapshots)
	f2.mu.Unlock()
	if n != 0 {
		t.Fatalf("snapshots = %d, want 0 after a lost lease", n)
	}
}

// TestArtifactUploadUsesLeaseFencedCommitAndRejectsLostLease covers the
// artifact handler: the live lease commits through the atomic lease-fenced
// insert (closing the handler-side TOCTOU), and a predicate rejected at commit
// time answers 409 and writes no artifact row.
func TestArtifactUploadUsesLeaseFencedCommitAndRejectsLostLease(t *testing.T) {
	s, f, _, hdrs := artifactIdentityFixture(t)
	lf := &leaseFakeStore{dbFakeStore: f}
	s.DB = lf
	if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	lease, plain := lf.calls()
	if lease != 1 || plain != 0 {
		t.Fatalf("artifact commit path = lease:%d plain:%d, want lease-only", lease, plain)
	}

	s2, f2, _, hdrs2 := artifactIdentityFixture(t)
	lf2 := &leaseFakeStore{dbFakeStore: f2}
	s2.DB = lf2
	lf2.setForceLost(true)
	w := fcUploadBlobArtifact(t, s2, hdrs2, "payload")
	if w.Code != http.StatusConflict {
		t.Fatalf("lost-lease artifact upload = %d, want 409: %s", w.Code, w.Body.String())
	}
	f2.mu.Lock()
	n := len(f2.artifacts)
	f2.mu.Unlock()
	if n != 0 {
		t.Fatalf("artifact rows = %d, want 0 after a lost lease", n)
	}
}

// TestLeaseLostAtCommitMaps409Not500 pins the error classification: the typed
// storage.ErrLeaseLost is a conflict, never an internal error, for every area.
func TestLeaseLostAtCommitMaps409Not500(t *testing.T) {
	if !leaseLostAtCommit(fmt.Errorf("wrap: %w", storage.ErrLeaseLost)) {
		t.Fatal("wrapped ErrLeaseLost was not classified")
	}
	if leaseLostAtCommit(errors.New("other")) {
		t.Fatal("unrelated error classified as lease loss")
	}
	ctx := context.Background()
	_ = ctx
}
