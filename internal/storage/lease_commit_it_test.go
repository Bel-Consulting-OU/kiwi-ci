package storage

// Real-PostgreSQL integration tests for the transactional commit-time lease
// predicates (T2-1). Gated on KIWI_TEST_POSTGRES_URL exactly like the other
// storage integration tests: each test owns a throwaway database and every
// revocation is applied to the live database between lease acquisition and
// the metadata commit (i.e. "during upload").

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// leaseCommitITJob enqueues one run+job and acquires a running lease for it,
// returning the job id, the runner id and the lease generation.
func leaseCommitITJob(t *testing.T, st *PostgresStore, repo string) (runID, jobID, runnerID string, generation int64) {
	t.Helper()
	ctx := context.Background()
	runID = pgITNewID(t)
	jobID = pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, repo)
	runnerID = pgITNewID(t)
	if _, err := st.AcquireLease(ctx, jobID, runnerID, []byte("tok"), 1, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("AcquireLease(%s): %v", jobID, err)
	}
	return runID, jobID, runnerID, 1
}

func leaseCommitITManifest(key string) CacheManifestRecord {
	// pgITEnqueueOne's jobs carry RepoURL pgITRepo + RepoFullName
	// "kiwi-it/repo" and no Trusted flag: the authoritative namespace derived
	// from the locked job is (pgITRepoID, "untrusted").
	return CacheManifestRecord{
		Repo:        pgITRepoID,
		TrustDomain: "untrusted",
		LogicalKey:  key,
		BlobSHA256:  strings.Repeat("a", 64),
		BlobSize:    11,
		CreatedAt:   time.Now().UTC(),
	}
}

// TestIntegrationLeaseCommitPredicatesLive drives the happy path on a real
// database: a live lease commits the cache manifest, the snapshot record and
// the artifact row through the lease-fenced methods.
func TestIntegrationLeaseCommitPredicatesLive(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID, gen := leaseCommitITJob(t, st, pgITRepo)

	if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, gen, leaseCommitITManifest("live")); err != nil {
		t.Fatalf("PutCacheManifestForLease: %v", err)
	}
	if _, found, err := st.GetCacheManifest(ctx, pgITRepoID, "untrusted", "live"); err != nil || !found {
		t.Fatalf("cache manifest after live commit = (%v, %v)", found, err)
	}
	rec := model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()}
	if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, gen, 0, rec); err != nil {
		t.Fatalf("InsertSnapshotForLease: %v", err)
	}
	if got, err := st.ListSnapshotsByRun(ctx, runID); err != nil || len(got) != 1 {
		t.Fatalf("snapshots after live commit = (%d, %v)", len(got), err)
	}
	art := model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "dist", LeaseGeneration: gen, SHA256: strings.Repeat("b", 64), CreatedAt: time.Now().UTC()}
	stored, created, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, gen, art)
	if err != nil || !created || stored.ID != art.ID {
		t.Fatalf("InsertArtifactOnceForLease live = (%+v, %v, %v)", stored, created, err)
	}
	if got, err := st.ListArtifacts(ctx, runID); err != nil || len(got) != 1 {
		t.Fatalf("artifacts after live commit = (%d, %v)", len(got), err)
	}
}

// TestIntegrationLeaseCommitPredicatesRevoked is the core T2-1 fresh-DB
// regression: the lease is revoked in each of its four ways AFTER acquisition
// and BEFORE the metadata write, and every lease-fenced commit must return
// ErrLeaseLost and persist NOTHING.
func TestIntegrationLeaseCommitPredicatesRevoked(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	revocations := []struct {
		name string
		sql  string
	}{
		{"cancelled", `UPDATE jobs SET status='cancelled', lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`},
		{"generation replaced", `UPDATE jobs SET lease_generation = lease_generation + 1 WHERE id=$1`},
		{"expired", `UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id=$1`},
		{"runner replaced", `UPDATE jobs SET lease_runner_id = $2 WHERE id=$1`},
	}
	for _, rv := range revocations {
		t.Run(rv.name, func(t *testing.T) {
			runID, jobID, runnerID, gen := leaseCommitITJob(t, st, pgITRepo)
			args := []any{jobID}
			if rv.name == "runner replaced" {
				args = append(args, pgITNewID(t))
			}
			if _, err := st.pool.Exec(ctx, rv.sql, args...); err != nil {
				t.Fatalf("apply revocation %s: %v", rv.name, err)
			}

			key := "lost-" + strings.ReplaceAll(rv.name, " ", "-")
			if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, gen, leaseCommitITManifest(key)); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("PutCacheManifestForLease = %v, want ErrLeaseLost", err)
			}
			if _, found, _ := st.GetCacheManifest(ctx, pgITRepoID, "untrusted", key); found {
				t.Fatal("cache manifest committed despite a revoked lease")
			}
			if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, gen, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("InsertSnapshotForLease = %v, want ErrLeaseLost", err)
			}
			if got, _ := st.ListSnapshotsByRun(ctx, runID); len(got) != 0 {
				t.Fatalf("snapshot committed despite a revoked lease: %d", len(got))
			}
			if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, gen, model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "dist", LeaseGeneration: gen, CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("InsertArtifactOnceForLease = %v, want ErrLeaseLost", err)
			}
			if got, _ := st.ListArtifacts(ctx, runID); len(got) != 0 {
				t.Fatalf("artifact committed despite a revoked lease: %d", len(got))
			}
		})
	}
}

// TestIntegrationLeaseCommitConcurrentCancel proves the predicate is
// transactional against a concurrent cancel: the cancel holds the job row
// lock, the commit blocks on it, and after the cancel commits the blocked
// predicate observes the cancelled row and writes nothing. Deterministic: the
// outer transaction owns the lock until it commits the cancel.
func TestIntegrationLeaseCommitConcurrentCancel(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID, gen := leaseCommitITJob(t, st, pgITRepo)

	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM jobs WHERE id=$1 FOR UPDATE`, jobID); err != nil {
		t.Fatalf("lock job row: %v", err)
	}
	done := make(chan error, 3)
	go func() {
		done <- st.PutCacheManifestForLease(ctx, jobID, runnerID, gen, leaseCommitITManifest("race-cache"))
	}()
	go func() {
		done <- st.InsertSnapshotForLease(ctx, jobID, runnerID, gen, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()})
	}()
	go func() {
		_, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, gen, model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "dist", LeaseGeneration: gen, CreatedAt: time.Now().UTC()})
		done <- err
	}()
	// Let the three commits block on the row lock before releasing it with a
	// cancel in the same transaction.
	select {
	case err := <-done:
		t.Fatalf("a commit finished before the cancel committed: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`, jobID); err != nil {
		t.Fatalf("cancel inside lock: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit cancel: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := <-done; !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("commit after concurrent cancel = %v, want ErrLeaseLost", err)
		}
	}
	if _, found, _ := st.GetCacheManifest(ctx, pgITRepoID, "untrusted", "race-cache"); found {
		t.Fatal("cache manifest committed after a concurrent cancel")
	}
	if got, _ := st.ListSnapshotsByRun(ctx, runID); len(got) != 0 {
		t.Fatalf("snapshot committed after a concurrent cancel: %d", len(got))
	}
	if got, _ := st.ListArtifacts(ctx, runID); len(got) != 0 {
		t.Fatalf("artifact committed after a concurrent cancel: %d", len(got))
	}
}

// TestIntegrationLeaseCommitArtifactConflictPrecedence pins that a lost lease
// wins over an idempotency conflict: a revoked re-upload of an existing
// (job, generation, name) with a different digest is a 409 lease loss, never a
// digest conflict and never an idempotent replay.
func TestIntegrationLeaseCommitArtifactConflictPrecedence(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID, gen := leaseCommitITJob(t, st, pgITRepo)

	first := model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "dist", LeaseGeneration: gen, SHA256: strings.Repeat("c", 64), CreatedAt: time.Now().UTC()}
	if _, created, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, gen, first); err != nil || !created {
		t.Fatalf("first insert = (%v, %v)", created, err)
	}
	// Same key, different digest: a live lease is a digest conflict.
	conflict := first
	conflict.ID = pgITNewID(t)
	conflict.SHA256 = strings.Repeat("d", 64)
	if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, gen, conflict); !errors.Is(err, ErrArtifactDigestConflict) {
		t.Fatalf("live conflict = %v, want ErrArtifactDigestConflict", err)
	}
	// Revoke the lease: the SAME conflict is now a lease loss, not a conflict.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='cancelled', lease_runner_id=NULL, lease_expires_at=NULL WHERE id=$1`, jobID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, gen, conflict); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("revoked conflict = %v, want ErrLeaseLost (predicate precedes conflict)", err)
	}
}

// TestIntegrationLeaseCommitIdentityBindingCrossJobRefused is the X3-A
// fresh-DB regression: a live lease over job A cannot carry job B's
// snapshot/artifact/cache identity. Every cross-bound field is refused with
// the typed ErrLeaseIdentityMismatch and commits NOTHING (the assertion
// covers both jobs' runs and every cache namespace variant).
func TestIntegrationLeaseCommitIdentityBindingCrossJobRefused(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runA, jobA, runnerA, genA := leaseCommitITJob(t, st, pgITRepo)
	runB, jobB, _, _ := leaseCommitITJob(t, st, pgITRepo)

	// Snapshot carrying B's run and job id while proving A's lease.
	snapB := model.SnapshotRecord{ID: pgITNewID(t), RunID: runB, JobID: jobB, CreatedAt: time.Now().UTC()}
	if err := st.InsertSnapshotForLease(ctx, jobA, runnerA, genA, 0, snapB); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("cross-bound snapshot = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Right job id, B's run.
	snapWrongRun := snapB
	snapWrongRun.ID = pgITNewID(t)
	snapWrongRun.JobID = jobA
	if err := st.InsertSnapshotForLease(ctx, jobA, runnerA, genA, 0, snapWrongRun); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-run snapshot = %v, want ErrLeaseIdentityMismatch", err)
	}

	// Artifact carrying B's job/run/generation while proving A's lease.
	artB := model.ArtifactRecord{ID: pgITNewID(t), RunID: runB, JobID: jobB, Name: "dist", LeaseGeneration: 1, SHA256: strings.Repeat("b", 64), CreatedAt: time.Now().UTC()}
	if _, _, err := st.InsertArtifactOnceForLease(ctx, jobA, runnerA, genA, artB); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("cross-bound artifact = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Right job/run, wrong generation.
	artWrongGen := artB
	artWrongGen.ID = pgITNewID(t)
	artWrongGen.RunID = runA
	artWrongGen.JobID = jobA
	artWrongGen.LeaseGeneration = genA + 1
	if _, _, err := st.InsertArtifactOnceForLease(ctx, jobA, runnerA, genA, artWrongGen); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-generation artifact = %v, want ErrLeaseIdentityMismatch", err)
	}

	// Cache manifest claiming B's producer coordinates under A's lease.
	cacheB := leaseCommitITManifest("x")
	cacheB.ProducerJob = jobB
	cacheB.ProducerRun = runB
	if err := st.PutCacheManifestForLease(ctx, jobA, runnerA, genA, cacheB); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("cross-bound cache manifest = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Correct namespace, wrong trust domain (the job is untrusted).
	cacheTrust := leaseCommitITManifest("x")
	cacheTrust.TrustDomain = "trusted"
	if err := st.PutCacheManifestForLease(ctx, jobA, runnerA, genA, cacheTrust); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-trust cache manifest = %v, want ErrLeaseIdentityMismatch", err)
	}
	// Wrong repository.
	cacheRepo := leaseCommitITManifest("x")
	cacheRepo.Repo = "github.com/other/repo"
	if err := st.PutCacheManifestForLease(ctx, jobA, runnerA, genA, cacheRepo); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("wrong-repo cache manifest = %v, want ErrLeaseIdentityMismatch", err)
	}

	// NOTHING was committed anywhere.
	for _, runID := range []string{runA, runB} {
		if got, _ := st.ListSnapshotsByRun(ctx, runID); len(got) != 0 {
			t.Fatalf("snapshots committed for run %s: %d", runID, len(got))
		}
		if got, _ := st.ListArtifacts(ctx, runID); len(got) != 0 {
			t.Fatalf("artifacts committed for run %s: %d", runID, len(got))
		}
	}
	for _, ns := range [][2]string{{pgITRepoID, "untrusted"}, {pgITRepoID, "trusted"}, {"github.com/other/repo", "untrusted"}} {
		if _, found, _ := st.GetCacheManifest(ctx, ns[0], ns[1], "x"); found {
			t.Fatalf("cache manifest committed under (%s, %s)", ns[0], ns[1])
		}
	}

	// The matching record commits, and its producer coordinates are stamped
	// from the locked job.
	if err := st.PutCacheManifestForLease(ctx, jobA, runnerA, genA, leaseCommitITManifest("good")); err != nil {
		t.Fatalf("matching cache manifest: %v", err)
	}
	rec, found, err := st.GetCacheManifest(ctx, pgITRepoID, "untrusted", "good")
	if err != nil || !found {
		t.Fatalf("matching manifest lookup = (%v, %v)", found, err)
	}
	if rec.ProducerJob != jobA || rec.ProducerRun != runA {
		t.Fatalf("manifest producer = %s/%s, want %s/%s", rec.ProducerRun, rec.ProducerJob, runA, jobA)
	}
}

// TestIntegrationLeaseCommitSnapshotCapCountsLockedJob is the X3-A cap
// regression on a fresh database: the commit-time cap counts the LOCKED job's
// records only. A legacy NULL-job_id row on the same run and another job's
// records never count toward A, and a cross-bound record is refused by the
// identity binding before the cap is even evaluated.
func TestIntegrationLeaseCommitSnapshotCapCountsLockedJob(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runA, jobA, runnerA, genA := leaseCommitITJob(t, st, pgITRepo)
	runB, jobB, runnerB, genB := leaseCommitITJob(t, st, pgITRepo)
	runC, jobC, _, _ := leaseCommitITJob(t, st, pgITRepo)

	// A legacy workspace_snapshots row on A's run with a NULL job id (the
	// pre-X3-A shape) must not count toward A's cap.
	if _, err := st.pool.Exec(ctx, `INSERT INTO workspace_snapshots (id, run_id, job_id, created_at, payload) VALUES ($1, $2, NULL, now(), '{}'::jsonb)`, pgITNewID(t), runA); err != nil {
		t.Fatalf("seed legacy NULL-job snapshot: %v", err)
	}
	// B's own snapshot under B's lease does not count toward A either.
	if err := st.InsertSnapshotForLease(ctx, jobB, runnerB, genB, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: runB, JobID: jobB, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("B snapshot: %v", err)
	}
	// A's first snapshot fits under cap 1.
	if err := st.InsertSnapshotForLease(ctx, jobA, runnerA, genA, 1, model.SnapshotRecord{ID: pgITNewID(t), RunID: runA, JobID: jobA, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("A first snapshot under cap 1: %v", err)
	}
	// A's second exceeds the cap (counted under the locked job).
	if err := st.InsertSnapshotForLease(ctx, jobA, runnerA, genA, 1, model.SnapshotRecord{ID: pgITNewID(t), RunID: runA, JobID: jobA, CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrSnapshotCapReached) {
		t.Fatalf("A second snapshot = %v, want ErrSnapshotCapReached", err)
	}
	// A record naming job C under A's lease is an identity mismatch, never a
	// cap decision about C.
	cross := model.SnapshotRecord{ID: pgITNewID(t), RunID: runC, JobID: jobC, CreatedAt: time.Now().UTC()}
	if err := st.InsertSnapshotForLease(ctx, jobA, runnerA, genA, 1, cross); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("cross-bound snapshot under cap = %v, want ErrLeaseIdentityMismatch", err)
	}
	// A's run holds exactly the NULL legacy row plus the one A record.
	if got, _ := st.ListSnapshotsByRun(ctx, runA); len(got) != 2 {
		t.Fatalf("A run snapshots = %d, want 2 (legacy NULL + one A record)", len(got))
	}
	nA := 0
	if got, _ := st.ListSnapshotsByRun(ctx, runA); len(got) > 0 {
		for _, s := range got {
			if s.JobID == jobA {
				nA++
			}
		}
	}
	if nA != 1 {
		t.Fatalf("job A snapshots = %d, want 1", nA)
	}
}
