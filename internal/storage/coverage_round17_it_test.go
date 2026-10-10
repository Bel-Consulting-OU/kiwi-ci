package storage

// Coverage round: lease-fenced commit arms, log-batch write arms, execution
// event retention arms, repository-identity repair arms and the in-memory
// mirrors. PG tests use a throwaway database cloned from the migrated
// template (pgITStore) and the established boom/break seams; the real
// assertions are on typed errors, rolled-back state and persisted rows.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// itDeferBoom installs a DEFERRABLE INITIALLY DEFERRED constraint trigger that
// raises at COMMIT, so a method's final tx.Commit error path is reachable
// deterministically.
func itDeferBoom(t *testing.T, st *PostgresStore, table string) {
	t.Helper()
	ctx := context.Background()
	fn := "kiwi_defer_boom_" + table
	if _, err := st.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'deferred failure on `+table+`'; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create deferred trigger function for %s: %v", table, err)
	}
	if _, err := st.pool.Exec(ctx, `CREATE CONSTRAINT TRIGGER `+fn+`_t AFTER INSERT OR UPDATE ON `+table+` DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION `+fn+`()`); err != nil {
		t.Fatalf("create deferred trigger on %s: %v", table, err)
	}
}

// itLeasedJob enqueues one run/job and acquires its live lease.
func itLeasedJob(t *testing.T, st *PostgresStore) (runID, jobID, runnerID string, leased model.Job) {
	t.Helper()
	runID, jobID, runnerID = pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	leased = gapITLeaseObject(t, st, jobID, runnerID)
	return runID, jobID, runnerID, leased
}

func itArtifactRecord(t *testing.T, runID, jobID, jobKey string, gen int64) model.ArtifactRecord {
	t.Helper()
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	return model.ArtifactRecord{
		ID:              pgITNewID(t),
		RunID:           runID,
		JobID:           jobID,
		JobKey:          jobKey,
		Name:            "bin",
		Size:            3,
		SHA256:          strings.Repeat("a", 64),
		CreatedAt:       now,
		ExpiresAt:       &expires,
		LeaseGeneration: gen,
	}
}

// TestPostgresIntegrationLeaseCommitArtifactArms drives the transactional
// artifact commit's failure arms: input validation, begin/lock/encode/write/
// commit errors and a corrupt stored payload at the idempotency key.
func TestPostgresIntegrationLeaseCommitArtifactArms(t *testing.T) {
	ctx := context.Background()

	t.Run("validation", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		good := itArtifactRecord(t, runID, jobID, leased.Key, leased.LeaseGeneration)

		badID := good
		badID.ID = "bad"
		if _, ok, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, leased.LeaseGeneration, badID); err == nil || ok {
			t.Fatalf("invalid artifact id = (%v, %v), want error", ok, err)
		}
		badRun := good
		badRun.RunID = "bad"
		if _, ok, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, leased.LeaseGeneration, badRun); err == nil || ok {
			t.Fatalf("invalid artifact run = (%v, %v), want error", ok, err)
		}
	})

	t.Run("begin tx error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := itArtifactRecord(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		st.Close()
		if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); err == nil {
			t.Fatal("artifact commit over a closed pool succeeded")
		}
	})

	t.Run("locked row read error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := itArtifactRecord(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		pgITBreakColumn(t, st, "jobs", "lease_expires_at")
		if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); err == nil {
			t.Fatal("artifact commit over an undecodable locked row succeeded")
		}
	})

	t.Run("encode error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := itArtifactRecord(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		defer seamPGFailAll(t)()
		if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("encode failure = %v, want the seam error", err)
		}
	})

	t.Run("insert error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := itArtifactRecord(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		pgITBoomOp(t, st, "artifacts", "INSERT")
		if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); err == nil || !strings.Contains(err.Error(), "injected INSERT failure") {
			t.Fatalf("insert failure = %v, want the injected error", err)
		}
	})

	t.Run("commit error rolls the insert back", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := itArtifactRecord(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		itDeferBoom(t, st, "artifacts")
		if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); err == nil || !strings.Contains(err.Error(), "deferred failure") {
			t.Fatalf("commit failure = %v, want the deferred error", err)
		}
		var n int
		if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM artifacts WHERE id=$1`, rec.ID).Scan(&n); err != nil {
			t.Fatalf("count artifacts: %v", err)
		}
		if n != 0 {
			t.Fatalf("rolled-back artifact %s survived", rec.ID)
		}
	})

	t.Run("corrupt stored payload at the idempotency key", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := itArtifactRecord(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		if _, err := st.pool.Exec(ctx,
			`INSERT INTO artifacts (id, run_id, job_id, job_key, name, size, sha256, created_at, expires_at, job_generation, payload)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now() + interval '1 hour', $8, '"corrupt"'::jsonb)`,
			pgITNewID(t), runID, jobID, leased.Key, rec.Name, 3, strings.Repeat("b", 64), leased.LeaseGeneration); err != nil {
			t.Fatalf("seed corrupt artifact: %v", err)
		}
		if _, ok, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); err == nil || ok {
			t.Fatalf("corrupt stored payload = (%v, %v), want a decode error", ok, err)
		}
	})
}

// TestPostgresIntegrationLeaseCommitSnapshotArms drives the transactional
// snapshot commit's failure arms: record validation, begin/locked/count/
// encode/insert/event-append errors.
func TestPostgresIntegrationLeaseCommitSnapshotArms(t *testing.T) {
	ctx := context.Background()
	snap := func(t *testing.T, runID, jobID, jobKey string, gen int64) model.SnapshotRecord {
		return model.SnapshotRecord{
			ID:              pgITNewID(t),
			RunID:           runID,
			JobID:           jobID,
			JobKey:          jobKey,
			Path:            "cas:" + strings.Repeat("c", 64),
			Size:            3,
			SHA256:          strings.Repeat("c", 64),
			CreatedAt:       time.Now().UTC(),
			Phase:           "post_job",
			LeaseGeneration: gen,
		}
	}

	t.Run("validation", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		good := snap(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		badID := good
		badID.ID = "bad"
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, leased.LeaseGeneration, 0, badID); err == nil {
			t.Fatal("invalid snapshot id was accepted")
		}
		badRun := good
		badRun.RunID = "bad"
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, leased.LeaseGeneration, 0, badRun); err == nil {
			t.Fatal("invalid snapshot run was accepted")
		}
	})

	t.Run("begin tx error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := snap(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		st.Close()
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, leased.LeaseGeneration, 0, rec); err == nil {
			t.Fatal("snapshot commit over a closed pool succeeded")
		}
	})

	t.Run("locked row read error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := snap(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		pgITBreakColumn(t, st, "jobs", "lease_expires_at")
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, leased.LeaseGeneration, 0, rec); err == nil {
			t.Fatal("snapshot commit over an undecodable locked row succeeded")
		}
	})

	t.Run("cap count error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := snap(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		pgITDropColumn(t, st, "workspace_snapshots", "run_id")
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, leased.LeaseGeneration, 5, rec); err == nil {
			t.Fatal("snapshot commit over a missing count column succeeded")
		}
	})

	t.Run("encode error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := snap(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		defer seamPGFailAll(t)()
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, leased.LeaseGeneration, 0, rec); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("encode failure = %v, want the seam error", err)
		}
	})

	t.Run("insert error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := snap(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		pgITBoomOp(t, st, "workspace_snapshots", "INSERT")
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, leased.LeaseGeneration, 0, rec); err == nil || !strings.Contains(err.Error(), "injected INSERT failure") {
			t.Fatalf("insert failure = %v, want the injected error", err)
		}
	})

	t.Run("event append error rolls the record back", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID, leased := itLeasedJob(t, st)
		rec := snap(t, runID, jobID, leased.Key, leased.LeaseGeneration)
		pgITBoomOp(t, st, "execution_events", "INSERT")
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, leased.LeaseGeneration, 0, rec); err == nil {
			t.Fatal("snapshot commit with a failing event append succeeded")
		}
		var n int
		if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM workspace_snapshots WHERE id=$1`, rec.ID).Scan(&n); err != nil {
			t.Fatalf("count snapshots: %v", err)
		}
		if n != 0 {
			t.Fatalf("rolled-back snapshot %s survived", rec.ID)
		}
	})
}

// TestPostgresIntegrationLeaseCommitCacheManifestArms drives the
// transactional cache-manifest commit: the zero-CreatedAt database-clock
// stamping plus begin/locked/encode/write errors.
func TestPostgresIntegrationLeaseCommitCacheManifestArms(t *testing.T) {
	ctx := context.Background()

	// itManifest derives the exact namespace the store computes from the
	// locked job, so the identity binding accepts the record.
	itManifest := func(t *testing.T, st *PostgresStore, jobID string) (CacheManifestRecord, cacheManifestLookup) {
		t.Helper()
		var repoID, policyID, repoURL, repoFull string
		var trusted bool
		if err := st.pool.QueryRow(ctx, `SELECT COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''),
			COALESCE(payload->>'repo_url',''), COALESCE(payload->>'repo_full_name',''),
			CASE WHEN jsonb_typeof(payload->'trusted')='boolean' THEN (payload->>'trusted')::boolean ELSE FALSE END
			FROM jobs WHERE id=$1`, jobID).Scan(&repoID, &policyID, &repoURL, &repoFull, &trusted); err != nil {
			t.Fatalf("read job identity: %v", err)
		}
		repo := RepoIDForJob(model.Job{RepoID: repoID, PolicyRepoID: policyID, RepoURL: repoURL, RepoFullName: repoFull})
		trust := cacheTrustDomain(trusted)
		return CacheManifestRecord{
			Repo:        repo,
			TrustDomain: trust,
			LogicalKey:  "k",
			BlobSHA256:  strings.Repeat("a", 64),
			BlobSize:    3,
		}, cacheManifestLookup{repo: repo, trust: trust, key: "k"}
	}

	t.Run("zero createdAt gets the fence clock", func(t *testing.T) {
		st := pgITStore(t)
		_, jobID, runnerID, leased := itLeasedJob(t, st)
		rec, look := itManifest(t, st, jobID)
		if !rec.CreatedAt.IsZero() {
			t.Fatal("fixture must carry the zero CreatedAt")
		}
		if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); err != nil {
			t.Fatalf("manifest commit: %v", err)
		}
		stored, found, err := st.GetCacheManifest(ctx, look.repo, look.trust, look.key)
		if err != nil || !found {
			t.Fatalf("stored manifest = found=%v err=%v", found, err)
		}
		if stored.CreatedAt.IsZero() {
			t.Fatal("zero CreatedAt was not stamped from the database clock")
		}
	})

	t.Run("begin tx error", func(t *testing.T) {
		st := pgITStore(t)
		_, jobID, runnerID, leased := itLeasedJob(t, st)
		rec, _ := itManifest(t, st, jobID)
		rec.CreatedAt = time.Now().UTC()
		st.Close()
		if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); err == nil {
			t.Fatal("manifest commit over a closed pool succeeded")
		}
	})

	t.Run("locked row read error", func(t *testing.T) {
		st := pgITStore(t)
		_, jobID, runnerID, leased := itLeasedJob(t, st)
		rec, _ := itManifest(t, st, jobID)
		rec.CreatedAt = time.Now().UTC()
		pgITBreakColumn(t, st, "jobs", "lease_expires_at")
		if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); err == nil {
			t.Fatal("manifest commit over an undecodable locked row succeeded")
		}
	})

	t.Run("encode error", func(t *testing.T) {
		st := pgITStore(t)
		_, jobID, runnerID, leased := itLeasedJob(t, st)
		rec, _ := itManifest(t, st, jobID)
		rec.CreatedAt = time.Now().UTC()
		defer seamPGFailAll(t)()
		if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("encode failure = %v, want the seam error", err)
		}
	})

	t.Run("write error", func(t *testing.T) {
		st := pgITStore(t)
		_, jobID, runnerID, leased := itLeasedJob(t, st)
		rec, _ := itManifest(t, st, jobID)
		rec.CreatedAt = time.Now().UTC()
		pgITBoomOp(t, st, "cache_manifests", "INSERT")
		if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, leased.LeaseGeneration, rec); err == nil || !strings.Contains(err.Error(), "injected INSERT failure") {
			t.Fatalf("write failure = %v, want the injected error", err)
		}
	})
}

type cacheManifestLookup struct{ repo, trust, key string }

// TestLeaseCommitMemoryMirrorArms covers the in-memory and faulted-wrapper
// arms: the namespace guard, the zero-CreatedAt stamp and the forwarded
// snapshot insert.
func TestLeaseCommitMemoryMirrorArms(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()

	// Incomplete namespace: rejected before the lease predicate.
	if err := m.PutCacheManifestForLease(ctx, pgITNewID(t), pgITNewID(t), 1, CacheManifestRecord{Repo: "r"}); err == nil {
		t.Fatal("incomplete cache manifest namespace was accepted")
	}
	// Zero CreatedAt is stamped, then the missing lease still fails closed.
	if err := m.PutCacheManifestForLease(ctx, pgITNewID(t), pgITNewID(t), 1, CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "l"}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("manifest without a live lease = %v, want ErrLeaseLost", err)
	}
	// Invalid lease key through the artifact mirror.
	if _, _, err := m.InsertArtifactOnceForLease(ctx, "bad", pgITNewID(t), 1, model.ArtifactRecord{}); err == nil {
		t.Fatal("invalid lease key was accepted by the memory artifact mirror")
	}

	// The faulted wrapper forwards a snapshot insert when no fault fires.
	f := &FaultyStore{Inner: m}
	err := f.InsertSnapshotForLease(ctx, pgITNewID(t), pgITNewID(t), 1, 0, model.SnapshotRecord{})
	if err == nil {
		t.Fatal("snapshot insert for an unknown job unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "missing inner") {
		t.Fatalf("snapshot insert was not forwarded: %v", err)
	}
}

// TestPostgresIntegrationLogBatchArms drives every failure arm of the
// transactional log-batch append: identity/entry validation, begin/receipt/
// read/cursor/line/commit errors (with rollback assertions).
func TestPostgresIntegrationLogBatchArms(t *testing.T) {
	ctx := context.Background()

	t.Run("validation", func(t *testing.T) {
		// The guards run before any pool access, so a zero store is enough.
		if _, err := (&PostgresStore{}).AppendLogBatch(ctx, nil, LogBatchIdentity{}); err == nil {
			t.Fatal("empty log batch identity was accepted")
		}
		if _, err := (&PostgresStore{}).AppendLogBatch(ctx, nil, LogBatchIdentity{JobID: pgITNewID(t), BatchID: "b"}); err == nil {
			t.Fatal("empty log batch was accepted")
		}
	})

	entries := func(runID string) []model.LogEntry {
		return []model.LogEntry{{RunID: runID, JobID: pgITNewID(t), Line: "hello", CreatedAt: time.Now().UTC()}}
	}

	t.Run("entries span two runs", func(t *testing.T) {
		st := pgITStore(t)
		multi := []model.LogEntry{
			{RunID: pgITNewID(t), JobID: pgITNewID(t), Line: "a", CreatedAt: time.Now().UTC()},
			{RunID: pgITNewID(t), JobID: pgITNewID(t), Line: "b", CreatedAt: time.Now().UTC()},
		}
		_, err := st.AppendLogBatch(ctx, multi, LogBatchIdentity{JobID: pgITNewID(t), Generation: 1, BatchID: "b1"})
		if err == nil || !strings.Contains(err.Error(), "share one run") {
			t.Fatalf("cross-run batch = %v, want the shared-run refusal", err)
		}
	})

	t.Run("begin tx error", func(t *testing.T) {
		st := pgITStore(t)
		st.Close()
		if _, err := st.AppendLogBatch(ctx, entries(pgITNewID(t)), LogBatchIdentity{JobID: pgITNewID(t), Generation: 1, BatchID: "b1"}); err == nil {
			t.Fatal("log batch over a closed pool succeeded")
		}
	})

	t.Run("receipt insert error", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoomOp(t, st, "log_batches", "INSERT")
		if _, err := st.AppendLogBatch(ctx, entries(pgITNewID(t)), LogBatchIdentity{JobID: pgITNewID(t), Generation: 1, BatchID: "b1"}); err == nil {
			t.Fatal("log batch with a failing receipt insert succeeded")
		}
	})

	t.Run("duplicate receipt with a NULL digest", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		if _, err := st.pool.Exec(ctx, `ALTER TABLE log_batches ALTER COLUMN payload_sha256 DROP NOT NULL`); err != nil {
			t.Fatalf("drop not null: %v", err)
		}
		if _, err := st.pool.Exec(ctx, `INSERT INTO log_batches (job_id, generation, batch_id, created_at, payload_sha256) VALUES ($1, 1, 'dup', now(), NULL)`, jobID); err != nil {
			t.Fatalf("seed NULL digest: %v", err)
		}
		if _, err := st.AppendLogBatch(ctx, entries(pgITNewID(t)), LogBatchIdentity{JobID: jobID, Generation: 1, BatchID: "dup"}); err == nil {
			t.Fatal("duplicate receipt with a NULL digest was accepted")
		}
	})

	t.Run("cursor error", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoomOp(t, st, "log_cursors", "INSERT")
		if _, err := st.AppendLogBatch(ctx, entries(pgITNewID(t)), LogBatchIdentity{JobID: pgITNewID(t), Generation: 1, BatchID: "b1"}); err == nil {
			t.Fatal("log batch with a failing cursor allocation succeeded")
		}
	})

	t.Run("line insert error rolls back the receipt", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		pgITBoomOp(t, st, "log_entries", "INSERT")
		if _, err := st.AppendLogBatch(ctx, entries(pgITNewID(t)), LogBatchIdentity{JobID: jobID, Generation: 1, BatchID: "b1"}); err == nil {
			t.Fatal("log batch with a failing line insert succeeded")
		}
		var n int
		if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM log_batches WHERE job_id=$1`, jobID).Scan(&n); err != nil {
			t.Fatalf("count receipts: %v", err)
		}
		if n != 0 {
			t.Fatalf("rolled-back log batch receipt survived (%d rows)", n)
		}
	})

	t.Run("commit error", func(t *testing.T) {
		st := pgITStore(t)
		itDeferBoom(t, st, "log_batches")
		if _, err := st.AppendLogBatch(ctx, entries(pgITNewID(t)), LogBatchIdentity{JobID: pgITNewID(t), Generation: 1, BatchID: "b1"}); err == nil || !strings.Contains(err.Error(), "deferred failure") {
			t.Fatalf("commit failure = %v, want the deferred error", err)
		}
	})
}

// TestPostgresIntegrationExecutionEventPruneArms drives the retention prune's
// failure arms: the default-limit arm, closed pool, cursor insert/watermark
// read/delete/watermark update/commit errors and the latest-cursor read.
func TestPostgresIntegrationExecutionEventPruneArms(t *testing.T) {
	ctx := context.Background()
	oldEvent := func() model.ExecutionEvent {
		return model.ExecutionEvent{Type: "job.queued", CreatedAt: time.Now().UTC().Add(-48 * time.Hour)}
	}

	t.Run("default limit without events", func(t *testing.T) {
		st := pgITStore(t)
		pruned, retained, err := st.PruneExecutionEvents(ctx, time.Now().UTC(), 0)
		if err != nil || pruned != 0 || retained != 0 {
			t.Fatalf("prune with the default limit = (%d, %d, %v), want (0, 0, nil)", pruned, retained, err)
		}
	})

	t.Run("begin tx error", func(t *testing.T) {
		st := pgITStore(t)
		st.Close()
		if _, _, err := st.PruneExecutionEvents(ctx, time.Now().UTC(), 10); err == nil {
			t.Fatal("prune over a closed pool succeeded")
		}
	})

	t.Run("cursor insert error", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoomOp(t, st, "execution_event_cursor", "INSERT")
		if _, _, err := st.PruneExecutionEvents(ctx, time.Now().UTC(), 10); err == nil {
			t.Fatal("prune with a failing cursor insert succeeded")
		}
	})

	t.Run("watermark read error", func(t *testing.T) {
		st := pgITStore(t)
		pgITDropColumn(t, st, "execution_event_cursor", "retained_from")
		if _, _, err := st.PruneExecutionEvents(ctx, time.Now().UTC(), 10); err == nil {
			t.Fatal("prune without the watermark column succeeded")
		}
	})

	t.Run("delete statement error", func(t *testing.T) {
		st := pgITStore(t)
		pgITDropColumn(t, st, "execution_events", "created_at")
		if _, _, err := st.PruneExecutionEvents(ctx, time.Now().UTC().Add(-24*time.Hour), 10); err == nil {
			t.Fatal("prune without the created_at column succeeded")
		}
	})

	t.Run("delete error", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.AppendExecutionEvent(ctx, oldEvent()); err != nil {
			t.Fatalf("append: %v", err)
		}
		pgITBoomOp(t, st, "execution_events", "DELETE")
		if _, _, err := st.PruneExecutionEvents(ctx, time.Now().UTC().Add(-24*time.Hour), 10); err == nil {
			t.Fatal("prune with a failing delete succeeded")
		}
	})

	t.Run("watermark update error", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.AppendExecutionEvent(ctx, oldEvent()); err != nil {
			t.Fatalf("append: %v", err)
		}
		pgITBoomOp(t, st, "execution_event_cursor", "UPDATE")
		if _, _, err := st.PruneExecutionEvents(ctx, time.Now().UTC().Add(-24*time.Hour), 10); err == nil {
			t.Fatal("prune with a failing watermark update succeeded")
		}
	})

	t.Run("commit error", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.AppendExecutionEvent(ctx, oldEvent()); err != nil {
			t.Fatalf("append: %v", err)
		}
		itDeferBoom(t, st, "execution_event_cursor")
		if _, _, err := st.PruneExecutionEvents(ctx, time.Now().UTC().Add(-24*time.Hour), 10); err == nil || !strings.Contains(err.Error(), "deferred failure") {
			t.Fatalf("commit failure = %v, want the deferred error", err)
		}
	})

	t.Run("latest cursor read error", func(t *testing.T) {
		st := pgITStore(t)
		st.Close()
		if _, err := st.LatestExecutionEventSeq(ctx); err == nil {
			t.Fatal("latest cursor over a closed pool succeeded")
		}
	})
}

// TestRepositoryPruneExecutionEventsArms drives the filesystem retention
// prune's failure arms with real on-disk corruption and write refusal: no
// journal, canceled context, corrupt watermark, unreadable/corrupt journal,
// journal write failure and watermark write failure.
func TestRepositoryPruneExecutionEventsArms(t *testing.T) {
	ctx := context.Background()

	t.Run("no journal uses the default limit", func(t *testing.T) {
		repo := New(t.TempDir())
		pruned, retained, err := repo.PruneExecutionEvents(ctx, time.Now().UTC(), 0)
		if err != nil || pruned != 0 || retained != 0 {
			t.Fatalf("prune without a journal = (%d, %d, %v)", pruned, retained, err)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		repo := New(t.TempDir())
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, _, err := repo.PruneExecutionEvents(cctx, time.Now().UTC(), 1); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled prune = %v, want context.Canceled", err)
		}
	})

	t.Run("nothing to prune", func(t *testing.T) {
		repo := New(t.TempDir())
		if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{Type: "job.queued"}); err != nil {
			t.Fatalf("append: %v", err)
		}
		pruned, retained, err := repo.PruneExecutionEvents(ctx, time.Now().UTC().Add(-time.Hour), 10)
		if err != nil || pruned != 0 || retained != 0 {
			t.Fatalf("past cutoff = (%d, %d, %v), want no victims", pruned, retained, err)
		}
	})

	t.Run("corrupt watermark", func(t *testing.T) {
		dir := t.TempDir()
		repo := New(dir)
		// First call loads the in-memory seq watermark; then the on-disk
		// watermark is corrupted and the second call must fail closed.
		if _, _, err := repo.PruneExecutionEvents(ctx, time.Now().UTC(), 1); err != nil {
			t.Fatalf("warm-up prune: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, executionEventsRetainedFile), []byte("not-a-number"), 0o600); err != nil {
			t.Fatalf("corrupt watermark: %v", err)
		}
		if _, _, err := repo.PruneExecutionEvents(ctx, time.Now().UTC(), 1); err == nil {
			t.Fatal("prune with a corrupt watermark succeeded")
		}
	})

	t.Run("unreadable journal", func(t *testing.T) {
		dir := t.TempDir()
		repo := New(dir)
		if _, _, err := repo.PruneExecutionEvents(ctx, time.Now().UTC(), 1); err != nil {
			t.Fatalf("warm-up prune: %v", err)
		}
		path := filepath.Join(dir, executionEventsFile)
		if err := os.WriteFile(path, []byte("{}"), 0o000); err != nil {
			t.Fatalf("write journal: %v", err)
		}
		if _, _, err := repo.PruneExecutionEvents(ctx, time.Now().UTC(), 1); err == nil {
			t.Fatal("prune over an unreadable journal succeeded")
		}
	})

	t.Run("corrupt journal", func(t *testing.T) {
		dir := t.TempDir()
		repo := New(dir)
		if _, _, err := repo.PruneExecutionEvents(ctx, time.Now().UTC(), 1); err != nil {
			t.Fatalf("warm-up prune: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, executionEventsFile), []byte("{not json"), 0o600); err != nil {
			t.Fatalf("corrupt journal: %v", err)
		}
		if _, _, err := repo.PruneExecutionEvents(ctx, time.Now().UTC(), 1); err == nil {
			t.Fatal("prune over a corrupt journal succeeded")
		}
	})

	t.Run("journal write failure", func(t *testing.T) {
		dir := t.TempDir()
		repo := New(dir)
		if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{Type: "job.queued", CreatedAt: time.Now().UTC().Add(-48 * time.Hour)}); err != nil {
			t.Fatalf("append: %v", err)
		}
		if os.Geteuid() == 0 {
			t.Skip("root ignores a read-only directory")
		}
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		if _, _, err := repo.PruneExecutionEvents(ctx, time.Now().UTC().Add(-24*time.Hour), 10); err == nil {
			t.Fatal("prune with an unwritable journal directory succeeded")
		}
	})

	t.Run("watermark write failure", func(t *testing.T) {
		dir := t.TempDir()
		repo := New(dir)
		if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{Type: "job.queued", CreatedAt: time.Now().UTC().Add(-48 * time.Hour)}); err != nil {
			t.Fatalf("append: %v", err)
		}
		// Fail only the watermark rename: the journal rewrite itself succeeds,
		// so the prune must fail at the watermark write and leave the old
		// watermark in place (retention never over-reports a crash).
		restore := fsutil.SetHooks(fsutil.Hooks{Rename: func(oldpath, newpath string) error {
			if strings.HasSuffix(newpath, executionEventsRetainedFile) {
				return errors.New("watermark rename refused")
			}
			return os.Rename(oldpath, newpath)
		}})
		defer restore()
		if _, _, err := repo.PruneExecutionEvents(ctx, time.Now().UTC().Add(-24*time.Hour), 10); err == nil {
			t.Fatal("prune with an unwritable watermark path succeeded")
		}
	})
}
