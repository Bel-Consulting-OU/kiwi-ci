package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// leaseCommitJob builds a running job with a live lease under
// (runnerID, generation) and the canonical acme/widget repository identity
// (untrusted). Tests override fields to seed cross-job identity cases.
func leaseCommitJob(jobID, runID, runnerID string, generation int64, expires time.Time) model.Job {
	return model.Job{
		ID:              jobID,
		RunID:           runID,
		Key:             "build",
		RepoURL:         "https://github.com/acme/widget.git",
		RepoFullName:    "acme/widget",
		Status:          model.StatusRunning,
		LeaseRunnerID:   runnerID,
		LeaseGeneration: generation,
		LeaseExpiresAt:  &expires,
		CreatedAt:       time.Now().UTC(),
	}
}

func leaseCommitSeedJob(t *testing.T, m *memStore, job model.Job) {
	t.Helper()
	ctx := context.Background()
	if err := m.InsertRun(ctx, model.Run{ID: job.RunID, Status: model.StatusRunning, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("InsertRun: %v", err)
	}
	if err := m.InsertJob(ctx, job); err != nil {
		t.Fatalf("InsertJob: %v", err)
	}
}

// leaseCommitSeed installs one running, unexpired job under
// (runnerID, generation) in the in-memory store and returns its id and run id.
func leaseCommitSeed(t *testing.T, m *memStore, status model.Status, runnerID string, generation int64, expires time.Time) (jobID, runID string) {
	t.Helper()
	jobID = pgITNewID(t)
	runID = pgITNewID(t)
	job := leaseCommitJob(jobID, runID, runnerID, generation, expires)
	job.Status = status
	leaseCommitSeedJob(t, m, job)
	return jobID, runID
}

func leaseCommitManifest(t *testing.T, key string) CacheManifestRecord {
	t.Helper()
	return CacheManifestRecord{
		Repo:        "github.com/acme/widget",
		TrustDomain: "untrusted",
		LogicalKey:  key,
		BlobSHA256:  strings64('a'),
		BlobSize:    7,
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
	jobID, runID := leaseCommitSeed(t, m, model.StatusRunning, strings.Repeat("1", 32), 7, exp)

	// Live lease: success for all three areas, with the record identity bound
	// to the locked job's coordinates.
	if err := m.PutCacheManifestForLease(ctx, jobID, strings.Repeat("1", 32), 7, leaseCommitManifest(t, "k1")); err != nil {
		t.Fatalf("PutCacheManifestForLease live: %v", err)
	}
	snap := model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: "build", CreatedAt: time.Now().UTC()}
	if err := m.InsertSnapshotForLease(ctx, jobID, strings.Repeat("1", 32), 7, 0, snap); err != nil {
		t.Fatalf("InsertSnapshotForLease live: %v", err)
	}
	art := model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "dist", LeaseGeneration: 7, SHA256: strings64('b'), CreatedAt: time.Now().UTC()}
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
			id, idRun := leaseCommitSeed(t, mm, model.StatusRunning, strings.Repeat("1", 32), 7, time.Now().UTC().Add(time.Hour))
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
			if _, found, _ := mm.GetCacheManifest(ctx, "github.com/acme/widget", "untrusted", "k2"); found {
				t.Fatal("cache manifest was committed despite a lost lease")
			}
			if err := mm.InsertSnapshotForLease(ctx, id, tc.runnerID, tc.generation, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: idRun, JobID: id, CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("InsertSnapshotForLease = %v, want ErrLeaseLost", err)
			}
			if got, _ := mm.ListSnapshotsByRun(ctx, ""); len(got) != 0 {
				t.Fatalf("snapshot committed despite a lost lease: %d", len(got))
			}
			if _, _, err := mm.InsertArtifactOnceForLease(ctx, id, tc.runnerID, tc.generation, model.ArtifactRecord{ID: pgITNewID(t), RunID: idRun, JobID: id, Name: "dist", LeaseGeneration: tc.generation, CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrLeaseLost) {
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
	sameName := model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "same", LeaseGeneration: 7, SHA256: strings64('c'), CreatedAt: time.Now().UTC()}
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

// TestMemStoreLeaseCommitIdentityBindingCrossJobRefused is the X3-A unit
// regression: a live lease over job A can never carry job B's
// snapshot/artifact/cache record. Every cross-bound identity-bearing field is
// refused with the typed ErrLeaseIdentityMismatch and commits NOTHING.
func TestMemStoreLeaseCommitIdentityBindingCrossJobRefused(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	exp := time.Now().UTC().Add(time.Hour)
	runnerA := strings.Repeat("1", 32)
	jobA, runA := leaseCommitSeed(t, m, model.StatusRunning, runnerA, 7, exp)
	runnerB := strings.Repeat("2", 32)
	jobB, runB := leaseCommitSeed(t, m, model.StatusRunning, runnerB, 9, exp)
	// Job B uses the trusted flag and a different repository so a namespace
	// cross-binding is observable too.
	jb, err := m.GetJob(ctx, jobB)
	if err != nil {
		t.Fatal(err)
	}
	jb.Trusted = true
	jb.RepoURL = "https://github.com/evil/other.git"
	jb.RepoFullName = "evil/other"
	if err := m.InsertJob(ctx, jb); err != nil {
		t.Fatal(err)
	}

	assertNothingCommitted := func(t *testing.T) {
		t.Helper()
		if got, _ := m.ListSnapshotsByRun(ctx, ""); len(got) != 0 {
			t.Fatalf("snapshots committed: %d", len(got))
		}
		if got, _ := m.ListArtifacts(ctx, ""); len(got) != 0 {
			t.Fatalf("artifacts committed: %d", len(got))
		}
		for _, ns := range [][2]string{{"github.com/acme/widget", "untrusted"}, {"github.com/evil/other", "trusted"}} {
			if _, found, _ := m.GetCacheManifest(ctx, ns[0], ns[1], "x"); found {
				t.Fatalf("cache manifest committed under %v", ns)
			}
		}
	}

	// Snapshot bound to job B's run/job while proving A's lease.
	snapB := model.SnapshotRecord{ID: pgITNewID(t), RunID: runB, JobID: jobB, CreatedAt: time.Now().UTC()}
	if err := m.InsertSnapshotForLease(ctx, jobA, runnerA, 7, 0, snapB); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("cross-bound snapshot = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Same job, wrong run.
	snapWrongRun := model.SnapshotRecord{ID: pgITNewID(t), RunID: runB, JobID: jobA, CreatedAt: time.Now().UTC()}
	if err := m.InsertSnapshotForLease(ctx, jobA, runnerA, 7, 0, snapWrongRun); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-run snapshot = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Right identity but a wrong job key (non-empty disagreement).
	snapWrongKey := model.SnapshotRecord{ID: pgITNewID(t), RunID: runA, JobID: jobA, JobKey: "other", CreatedAt: time.Now().UTC()}
	if err := m.InsertSnapshotForLease(ctx, jobA, runnerA, 7, 0, snapWrongKey); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-key snapshot = %v, want ErrLeaseIdentityMismatch", err)
	}

	// Artifact bound to B's job/run/generation while proving A's lease.
	artB := model.ArtifactRecord{ID: pgITNewID(t), RunID: runB, JobID: jobB, Name: "dist", LeaseGeneration: 9, SHA256: strings64('b'), CreatedAt: time.Now().UTC()}
	if _, _, err := m.InsertArtifactOnceForLease(ctx, jobA, runnerA, 7, artB); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("cross-bound artifact = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Right job/run but the record claims B's generation.
	artWrongGen := artB
	artWrongGen.ID = pgITNewID(t)
	artWrongGen.RunID = runA
	artWrongGen.JobID = jobA
	if _, _, err := m.InsertArtifactOnceForLease(ctx, jobA, runnerA, 7, artWrongGen); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-generation artifact = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Right coordinates but a wrong job key.
	artWrongKey := artB
	artWrongKey.ID = pgITNewID(t)
	artWrongKey.RunID = runA
	artWrongKey.JobID = jobA
	artWrongKey.LeaseGeneration = 7
	artWrongKey.JobKey = "other"
	if _, _, err := m.InsertArtifactOnceForLease(ctx, jobA, runnerA, 7, artWrongKey); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-key artifact = %v, want ErrLeaseIdentityMismatch", err)
	}

	// Cache manifest claiming job B's repository/trust/producer while proving
	// A's lease.
	cacheB := leaseCommitManifest(t, "x")
	cacheB.Repo = "github.com/evil/other"
	cacheB.TrustDomain = "trusted"
	cacheB.ProducerJob = jobB
	cacheB.ProducerRun = runB
	if err := m.PutCacheManifestForLease(ctx, jobA, runnerA, 7, cacheB); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("cross-bound cache manifest = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Correct namespace but a producer that names another job.
	cacheWrongProducer := leaseCommitManifest(t, "x")
	cacheWrongProducer.ProducerJob = jobB
	if err := m.PutCacheManifestForLease(ctx, jobA, runnerA, 7, cacheWrongProducer); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-producer cache manifest = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Correct namespace but the wrong trust domain.
	cacheWrongTrust := leaseCommitManifest(t, "x")
	cacheWrongTrust.TrustDomain = "trusted"
	if err := m.PutCacheManifestForLease(ctx, jobA, runnerA, 7, cacheWrongTrust); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-trust cache manifest = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Correct namespace but another repository.
	cacheWrongRepo := leaseCommitManifest(t, "x")
	cacheWrongRepo.Repo = "github.com/evil/other"
	if err := m.PutCacheManifestForLease(ctx, jobA, runnerA, 7, cacheWrongRepo); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-repo cache manifest = %v, want ErrLeaseIdentityMismatch", err)
	}

	assertNothingCommitted(t)

	// The matching record for A must still commit, and the derived producer
	// coordinates must be stamped from the locked job.
	if err := m.PutCacheManifestForLease(ctx, jobA, runnerA, 7, leaseCommitManifest(t, "ok")); err != nil {
		t.Fatalf("matching cache manifest: %v", err)
	}
	rec, found, _ := m.GetCacheManifest(ctx, "github.com/acme/widget", "untrusted", "ok")
	if !found || rec.ProducerJob != jobA || rec.ProducerRun != runA {
		t.Fatalf("committed manifest = (%+v, %v), want producer %s/%s", rec, found, runA, jobA)
	}
}

// TestMemStoreSnapshotCapCountsLockedJob proves the commit-time snapshot cap
// is keyed to the LOCKED job's (run, job) coordinates: another job's records
// and legacy rows with no job id never count toward it.
func TestMemStoreSnapshotCapCountsLockedJob(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	exp := time.Now().UTC().Add(time.Hour)
	runnerA := strings.Repeat("1", 32)
	jobA, runA := leaseCommitSeed(t, m, model.StatusRunning, runnerA, 7, exp)
	runnerC := strings.Repeat("3", 32)
	jobC, runC := leaseCommitSeed(t, m, model.StatusRunning, runnerC, 3, exp)

	// A legacy distractor on A's run with no job id (the pre-X3-A NULL row
	// shape) and a row for another job C with many records.
	m.snapshots = append(m.snapshots, model.SnapshotRecord{ID: pgITNewID(t), RunID: runA, CreatedAt: time.Now().UTC()})
	for i := 0; i < 3; i++ {
		if err := m.InsertSnapshotForLease(ctx, jobC, runnerC, 3, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: runC, JobID: jobC, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("seed snapshot for C: %v", err)
		}
	}

	// A's first record fits under cap 1 even though its run already holds a
	// NULL-job legacy row: the count is keyed to job A, not the run.
	first := model.SnapshotRecord{ID: pgITNewID(t), RunID: runA, JobID: jobA, CreatedAt: time.Now().UTC()}
	if err := m.InsertSnapshotForLease(ctx, jobA, runnerA, 7, 1, first); err != nil {
		t.Fatalf("A's first snapshot under cap 1: %v", err)
	}
	// A's second exceeds the cap; C's records are irrelevant to A's count.
	second := model.SnapshotRecord{ID: pgITNewID(t), RunID: runA, JobID: jobA, CreatedAt: time.Now().UTC()}
	if err := m.InsertSnapshotForLease(ctx, jobA, runnerA, 7, 1, second); !errors.Is(err, ErrSnapshotCapReached) {
		t.Fatalf("A's second snapshot = %v, want ErrSnapshotCapReached", err)
	}
	// A cross-bound record naming C is refused as an identity mismatch, never
	// evaluated against C's cap or A's.
	cross := model.SnapshotRecord{ID: pgITNewID(t), RunID: runC, JobID: jobC, CreatedAt: time.Now().UTC()}
	if err := m.InsertSnapshotForLease(ctx, jobA, runnerA, 7, 1, cross); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("cross-bound snapshot under cap = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Exactly one record was committed for A.
	n := 0
	for _, s := range m.snapshots {
		if s.RunID == runA && s.JobID == jobA {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("job A snapshots = %d, want 1", n)
	}
}

// TestFaultyStoreLeaseCommitParity pins the wrapper parity: the fault is
// injected before Inner is touched, the methods delegate unchanged when no
// fault is armed, and the inner implementation's identity binding still
// refuses a cross-bound record through the wrapper.
func TestFaultyStoreLeaseCommitParity(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	jobID, runID := leaseCommitSeed(t, m, model.StatusRunning, strings.Repeat("1", 32), 3, time.Now().UTC().Add(time.Hour))
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
	if err := f.InsertSnapshotForLease(ctx, jobID, strings.Repeat("1", 32), 3, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()}); !errors.Is(err, boom) {
		t.Fatalf("FaultyStore snapshot fault = %v, want %v", err, boom)
	}
	f.FailAfter = 3
	if _, _, err := f.InsertArtifactOnceForLease(ctx, jobID, strings.Repeat("1", 32), 3, model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "a", LeaseGeneration: 3, CreatedAt: time.Now().UTC()}); !errors.Is(err, boom) {
		t.Fatalf("FaultyStore artifact fault = %v, want %v", err, boom)
	}
	// A cross-bound record is refused by the inner store through the wrapper.
	f.FailAfter = 0
	crossArt := model.ArtifactRecord{ID: pgITNewID(t), RunID: pgITNewID(t), JobID: pgITNewID(t), Name: "b", LeaseGeneration: 3, CreatedAt: time.Now().UTC()}
	if _, _, err := f.InsertArtifactOnceForLease(ctx, jobID, strings.Repeat("1", 32), 3, crossArt); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("FaultyStore cross-bound artifact = %v, want ErrLeaseIdentityMismatch", err)
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
	if err := m.InsertSnapshotForLease(ctx, pgITNewID(t), strings.Repeat("1", 32), -1, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: pgITNewID(t)}); err == nil {
		t.Fatal("negative generation accepted")
	}
}
