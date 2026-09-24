package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// leaseCommitSeed installs one running, unexpired job under
// (runnerID, generation) in the in-memory store and returns its id.
func leaseCommitSeed(t *testing.T, m *memStore, status model.Status, runnerID string, generation int64, expires time.Time) string {
	t.Helper()
	ctx := context.Background()
	jobID := pgITNewID(t)
	runID := pgITNewID(t)
	job := model.Job{
		ID:              jobID,
		RunID:           runID,
		Key:             "build",
		Status:          status,
		LeaseRunnerID:   runnerID,
		LeaseGeneration: generation,
		LeaseExpiresAt:  &expires,
		CreatedAt:       time.Now().UTC(),
	}
	if err := m.InsertJob(ctx, job); err != nil {
		t.Fatalf("InsertJob: %v", err)
	}
	if err := m.InsertRun(ctx, model.Run{ID: runID, Status: model.StatusRunning, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("InsertRun: %v", err)
	}
	return jobID
}

func leaseCommitManifest(t *testing.T, key string) CacheManifestRecord {
	t.Helper()
	return CacheManifestRecord{
		Repo:        "github.com/acme/widget",
		TrustDomain: "trusted",
		LogicalKey:  key,
		BlobSHA256:  strings64('a'),
		BlobSize:    7,
		ProducerRun: pgITNewID(t),
		ProducerJob: pgITNewID(t),
		CreatedAt:   time.Now().UTC(),
	}
}

func strings64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// TestMemStoreLeaseCommitPredicates is the T2-1 unit regression: every
// revocation class (cancelled, generation replaced, runner replaced, expired,
// vanished) fails the predicate with ErrLeaseLost and commits NOTHING, while a
// live lease commits exactly what the plain method would.
func TestMemStoreLeaseCommitPredicates(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	exp := time.Now().UTC().Add(time.Hour)
	jobID := leaseCommitSeed(t, m, model.StatusRunning, strings.Repeat("1", 32), 7, exp)

	// Live lease: success for all three areas.
	if err := m.PutCacheManifestForLease(ctx, jobID, strings.Repeat("1", 32), 7, leaseCommitManifest(t, "k1")); err != nil {
		t.Fatalf("PutCacheManifestForLease live: %v", err)
	}
	snap := model.SnapshotRecord{ID: pgITNewID(t), RunID: pgITNewID(t), JobID: jobID, CreatedAt: time.Now().UTC()}
	if err := m.InsertSnapshotForLease(ctx, jobID, strings.Repeat("1", 32), 7, snap); err != nil {
		t.Fatalf("InsertSnapshotForLease live: %v", err)
	}
	art := model.ArtifactRecord{ID: pgITNewID(t), RunID: pgITNewID(t), JobID: jobID, Name: "dist", LeaseGeneration: 7, SHA256: strings64('b'), CreatedAt: time.Now().UTC()}
	if _, created, err := m.InsertArtifactOnceForLease(ctx, jobID, strings.Repeat("1", 32), 7, art); err != nil || !created {
		t.Fatalf("InsertArtifactOnceForLease live = (%v, %v), want created", created, err)
	}

	type testCase struct {
		name       string
		runnerID   string
		generation int64
		mutate     func(j *model.Job)
	}
	cases := []testCase{
		{name: "runner replaced", runnerID: strings.Repeat("2", 32), generation: 7},
		{name: "generation replaced", runnerID: strings.Repeat("1", 32), generation: 8},
		{name: "cancelled", runnerID: strings.Repeat("1", 32), generation: 7, mutate: func(j *model.Job) {
			j.Status = model.StatusCancelled
		}},
		{name: "expired", runnerID: strings.Repeat("1", 32), generation: 7, mutate: func(j *model.Job) {
			past := time.Now().UTC().Add(-time.Minute)
			j.LeaseExpiresAt = &past
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Re-seed a fresh store per case so mutations do not leak.
			mm := newMemStore()
			id := leaseCommitSeed(t, mm, model.StatusRunning, strings.Repeat("1", 32), 7, time.Now().UTC().Add(time.Hour))
			if tc.mutate != nil {
				j, err := mm.GetJob(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				tc.mutate(&j)
				if err := mm.InsertJob(ctx, j); err != nil {
					t.Fatal(err)
				}
			}
			if err := mm.PutCacheManifestForLease(ctx, id, tc.runnerID, tc.generation, leaseCommitManifest(t, "k2")); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("PutCacheManifestForLease = %v, want ErrLeaseLost", err)
			}
			if _, found, _ := mm.GetCacheManifest(ctx, "github.com/acme/widget", "trusted", "k2"); found {
				t.Fatal("cache manifest was committed despite a lost lease")
			}
			if err := mm.InsertSnapshotForLease(ctx, id, tc.runnerID, tc.generation, model.SnapshotRecord{ID: pgITNewID(t), RunID: pgITNewID(t), CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("InsertSnapshotForLease = %v, want ErrLeaseLost", err)
			}
			if got, _ := mm.ListSnapshotsByRun(ctx, ""); len(got) != 0 {
				t.Fatalf("snapshot committed despite a lost lease: %d", len(got))
			}
			if _, _, err := mm.InsertArtifactOnceForLease(ctx, id, tc.runnerID, tc.generation, model.ArtifactRecord{ID: pgITNewID(t), RunID: pgITNewID(t), JobID: id, Name: "dist", LeaseGeneration: tc.generation, CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("InsertArtifactOnceForLease = %v, want ErrLeaseLost", err)
			}
			if got, _ := mm.ListArtifacts(ctx, ""); len(got) != 0 {
				t.Fatalf("artifact committed despite a lost lease: %d", len(got))
			}
		})
	}

	// A vanished job fails the predicate closed.
	if err := m.PutCacheManifestForLease(ctx, pgITNewID(t), strings.Repeat("1", 32), 7, leaseCommitManifest(t, "k3")); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("PutCacheManifestForLease unknown job = %v, want ErrLeaseLost", err)
	}
	// The conflict precedence: a lost lease wins over an artifact digest
	// conflict, so a revoked upload is never ack'd as an idempotent replay.
	sameName := model.ArtifactRecord{ID: pgITNewID(t), RunID: pgITNewID(t), JobID: jobID, Name: "same", LeaseGeneration: 7, SHA256: strings64('c'), CreatedAt: time.Now().UTC()}
	if _, created, err := m.InsertArtifactOnceForLease(ctx, jobID, strings.Repeat("1", 32), 7, sameName); err != nil || !created {
		t.Fatalf("seed same artifact = (%v, %v)", created, err)
	}
	conflict := sameName
	conflict.ID = pgITNewID(t)
	conflict.SHA256 = strings64('d')
	if _, _, err := m.InsertArtifactOnceForLease(ctx, jobID, strings.Repeat("2", 32), 7, conflict); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("lost lease with a digest conflict = %v, want ErrLeaseLost (predicate precedes conflict)", err)
	}
}

// TestFaultyStoreLeaseCommitParity pins the wrapper parity: the fault is
// injected before Inner is touched, and the methods delegate unchanged when no
// fault is armed.
func TestFaultyStoreLeaseCommitParity(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	jobID := leaseCommitSeed(t, m, model.StatusRunning, strings.Repeat("1", 32), 3, time.Now().UTC().Add(time.Hour))
	f := &FaultyStore{Inner: m}
	rec := leaseCommitManifest(t, "wrap")
	if err := f.PutCacheManifestForLease(ctx, jobID, strings.Repeat("1", 32), 3, rec); err != nil {
		t.Fatalf("FaultyStore delegate: %v", err)
	}
	boom := errors.New("injected mutation fault")
	f.FailAfter = 1
	f.Err = boom
	if err := f.PutCacheManifestForLease(ctx, jobID, strings.Repeat("1", 32), 3, leaseCommitManifest(t, "wrap2")); !errors.Is(err, boom) {
		t.Fatalf("FaultyStore fault = %v, want %v", err, boom)
	}
	f.FailAfter = 2
	if err := f.InsertSnapshotForLease(ctx, jobID, strings.Repeat("1", 32), 3, model.SnapshotRecord{ID: pgITNewID(t), RunID: pgITNewID(t), CreatedAt: time.Now().UTC()}); !errors.Is(err, boom) {
		t.Fatalf("FaultyStore snapshot fault = %v, want %v", err, boom)
	}
	f.FailAfter = 3
	if _, _, err := f.InsertArtifactOnceForLease(ctx, jobID, strings.Repeat("1", 32), 3, model.ArtifactRecord{ID: pgITNewID(t), RunID: pgITNewID(t), JobID: jobID, Name: "a", LeaseGeneration: 3, CreatedAt: time.Now().UTC()}); !errors.Is(err, boom) {
		t.Fatalf("FaultyStore artifact fault = %v, want %v", err, boom)
	}
}

// TestLeaseCommitValidationRejectsMalformedKeys pins the shared input
// contract: a malformed job/runner key is rejected before any predicate or
// write.
func TestLeaseCommitValidationRejectsMalformedKeys(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	if err := m.PutCacheManifestForLease(ctx, "", strings.Repeat("1", 32), 1, leaseCommitManifest(t, "k")); err == nil {
		t.Fatal("empty job id accepted")
	}
	if err := m.PutCacheManifestForLease(ctx, pgITNewID(t), "", 1, leaseCommitManifest(t, "k")); err == nil {
		t.Fatal("empty runner id accepted")
	}
	if err := m.InsertSnapshotForLease(ctx, pgITNewID(t), strings.Repeat("1", 32), -1, model.SnapshotRecord{ID: pgITNewID(t), RunID: pgITNewID(t)}); err == nil {
		t.Fatal("negative generation accepted")
	}
}
