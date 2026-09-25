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
	return CacheManifestRecord{
		Repo:        "github.com/kiwi-it/repo",
		TrustDomain: "trusted",
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
	if _, found, err := st.GetCacheManifest(ctx, "github.com/kiwi-it/repo", "trusted", "live"); err != nil || !found {
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
			if _, found, _ := st.GetCacheManifest(ctx, "github.com/kiwi-it/repo", "trusted", key); found {
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
	if _, found, _ := st.GetCacheManifest(ctx, "github.com/kiwi-it/repo", "trusted", "race-cache"); found {
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
