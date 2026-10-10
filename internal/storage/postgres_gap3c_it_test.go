package storage

// Third coverage round, part 4: lease-commit transactions (artifact, snapshot,
// cache manifest) and execution-attestation commit arms.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestLeaseCommitValidationArms runs the pre-transaction validation of the
// lease-commit helpers without any database.
func TestLeaseCommitValidationArms(t *testing.T) {
	ctx := context.Background()
	st := &PostgresStore{}
	if _, _, err := st.InsertArtifactOnceForLease(ctx, "", "", 0, model.ArtifactRecord{}); err == nil {
		t.Fatal("empty lease key was accepted for an artifact")
	}
	if _, _, err := st.InsertArtifactOnceForLease(ctx, pgITNewID(t), "runner", 1, model.ArtifactRecord{}); err == nil {
		t.Fatal("invalid artifact id was accepted")
	}
	if _, _, err := st.InsertArtifactOnceForLease(ctx, pgITNewID(t), "runner", 1, model.ArtifactRecord{ID: pgITNewID(t)}); err == nil {
		t.Fatal("invalid artifact run id was accepted")
	}
	if err := st.InsertSnapshotForLease(ctx, "", "", 0, 0, model.SnapshotRecord{}); err == nil {
		t.Fatal("empty lease key was accepted for a snapshot")
	}
	if err := st.InsertSnapshotForLease(ctx, pgITNewID(t), "runner", 1, 0, model.SnapshotRecord{}); err == nil {
		t.Fatal("invalid snapshot id was accepted")
	}
	if err := st.InsertSnapshotForLease(ctx, pgITNewID(t), "runner", 1, 0, model.SnapshotRecord{ID: pgITNewID(t)}); err == nil {
		t.Fatal("invalid snapshot run id was accepted")
	}
	if err := st.PutCacheManifestForLease(ctx, "", "", 0, CacheManifestRecord{}); err == nil {
		t.Fatal("empty lease key was accepted for a cache manifest")
	}
	if err := st.PutCacheManifestForLease(ctx, pgITNewID(t), "runner", 1, CacheManifestRecord{LogicalKey: "k"}); err == nil {
		t.Fatal("incomplete cache manifest namespace was accepted")
	}
	if err := st.PutCacheManifestForLease(ctx, pgITNewID(t), "runner", 1, CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "k"}); err == nil {
		t.Fatal("invalid cache manifest digest was accepted")
	}
}

// TestPostgresIntegrationInsertArtifactOnceForLeaseArms drives the artifact
// commit's event-append failure, replay and digest-conflict arms.
func TestPostgresIntegrationInsertArtifactOnceForLeaseArms(t *testing.T) {
	ctx := context.Background()
	artifact := func(j *model.Job, name, sha string) model.ArtifactRecord {
		return model.ArtifactRecord{ID: pgITNewID(t), JobID: j.ID, RunID: j.RunID, JobKey: j.Key, Name: name, Size: 3, SHA256: sha, LeaseGeneration: 1, CreatedAt: time.Now().UTC()}
	}

	t.Run("eventAppendFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		pgITBoomOp(t, st, "execution_events", "INSERT")
		if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 1, artifact(&model.Job{ID: jobID, RunID: runID, Key: "k"}, "bin", "sha-one")); err == nil {
			t.Fatal("artifact commit with a failing event append succeeded")
		}
		var n int
		if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM artifacts WHERE job_id=$1`, jobID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("failed artifact commit left %d row(s)", n)
		}
	})

	t.Run("replayAndConflict", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		j, err := st.GetJob(ctx, jobID)
		if err != nil {
			t.Fatal(err)
		}
		first, created, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 1, artifact(&j, "bin", "sha-one"))
		if err != nil || !created {
			t.Fatalf("first artifact commit = created %v, %v", created, err)
		}
		replay, created, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 1, artifact(&j, "bin", "sha-one"))
		if err != nil || created || replay.ID != first.ID {
			t.Fatalf("artifact replay = %+v created=%v err=%v, want the stored row", replay, created, err)
		}
		conflict, created, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 1, artifact(&j, "bin", "sha-two"))
		if !errors.Is(err, ErrArtifactDigestConflict) || created || conflict.SHA256 != "sha-one" {
			t.Fatalf("artifact digest conflict = %+v created=%v err=%v", conflict, created, err)
		}
	})

	t.Run("leaseLost", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		j, err := st.GetJob(ctx, jobID)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, pgITNewID(t), 1, artifact(&j, "bin", "sha-one")); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("foreign-runner artifact commit = %v, want ErrLeaseLost", err)
		}
	})
}

// TestPostgresIntegrationInsertSnapshotForLeaseArms drives the snapshot
// commit's cap, event-append and insert failure arms.
func TestPostgresIntegrationInsertSnapshotForLeaseArms(t *testing.T) {
	ctx := context.Background()
	snapshot := func(t *testing.T, jobID, runID string) model.SnapshotRecord {
		return model.SnapshotRecord{ID: pgITNewID(t), JobID: jobID, RunID: runID, LeaseGeneration: 1, CreatedAt: time.Now().UTC()}
	}

	t.Run("capReached", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, 1, 1, snapshot(t, jobID, runID)); err != nil {
			t.Fatalf("first snapshot = %v", err)
		}
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, 1, 1, snapshot(t, jobID, runID)); !errors.Is(err, ErrSnapshotCapReached) {
			t.Fatalf("second snapshot = %v, want ErrSnapshotCapReached", err)
		}
	})

	t.Run("insertFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		pgITBoomOp(t, st, "workspace_snapshots", "INSERT")
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, 1, 0, snapshot(t, jobID, runID)); err == nil {
			t.Fatal("snapshot insert failure was swallowed")
		}
	})

	t.Run("eventAppendFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		pgITBoomOp(t, st, "execution_events", "INSERT")
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, 1, 0, snapshot(t, jobID, runID)); err == nil {
			t.Fatal("snapshot event append failure was swallowed")
		}
		var n int
		if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM workspace_snapshots WHERE job_id=$1`, jobID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("failed snapshot commit left %d row(s)", n)
		}
	})
}

// TestPostgresIntegrationPutCacheManifestForLeaseArms drives the manifest
// commit's encoder and insert failure arms.
func TestPostgresIntegrationPutCacheManifestForLeaseArms(t *testing.T) {
	ctx := context.Background()
	rec := func() CacheManifestRecord {
		return CacheManifestRecord{Repo: "github.com/kiwi-it/repo", TrustDomain: "untrusted", LogicalKey: "cache-key", BlobSHA256: hexGapDigest(), BlobSize: 3, CreatedAt: time.Now().UTC()}
	}

	t.Run("marshalFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		defer seamPGFailAll(t)()
		if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, 1, rec()); err == nil {
			t.Fatal("manifest with a failing encoder succeeded")
		}
	})

	t.Run("insertFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		pgITBoomOp(t, st, "cache_manifests", "INSERT")
		if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, 1, rec()); err == nil {
			t.Fatal("manifest insert failure was swallowed")
		}
	})

	t.Run("upsertReplay", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, 1, rec()); err != nil {
			t.Fatalf("first manifest = %v", err)
		}
		second := rec()
		second.BlobSize = 9
		if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, 1, second); err != nil {
			t.Fatalf("manifest upsert = %v", err)
		}
		var size int64
		if err := st.pool.QueryRow(ctx, `SELECT blob_size FROM cache_manifests WHERE repo=$1 AND trust_domain=$2 AND logical_key=$3`, second.Repo, second.TrustDomain, second.LogicalKey).Scan(&size); err != nil {
			t.Fatal(err)
		}
		if size != 9 {
			t.Fatalf("manifest blob size = %d, want the upserted 9", size)
		}
	})
}

// TestPostgresIntegrationCommitExecutionAttestationArms drives the
// insert-once attestation commit's failure and replay arms.
func TestPostgresIntegrationCommitExecutionAttestationArms(t *testing.T) {
	ctx := context.Background()
	rec := func(jobID string) model.ExecutionAttestationRecord {
		return model.ExecutionAttestationRecord{JobID: jobID, Generation: 1, RunID: pgITNewID(t), Status: "success", StatementSHA256: "sum", EnvelopeRef: "file:///e", CreatedAt: time.Now().UTC()}
	}
	ev := func(r model.ExecutionAttestationRecord) model.ExecutionEvent { return ExecutionAttestationEvent(r) }

	t.Run("emptyJobID", func(t *testing.T) {
		if _, _, err := (&PostgresStore{}).CommitExecutionAttestation(ctx, model.ExecutionAttestationRecord{}, model.ExecutionEvent{Type: model.EventExecutionAttested}); err == nil {
			t.Fatal("empty attestation job id was accepted")
		}
	})

	t.Run("insertFail", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoomOp(t, st, "execution_attestations", "INSERT")
		r := rec(pgITNewID(t))
		if _, _, err := st.CommitExecutionAttestation(ctx, r, ev(r)); err == nil {
			t.Fatal("attestation insert failure was swallowed")
		}
	})

	t.Run("eventAppendFail", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoomOp(t, st, "execution_events", "INSERT")
		r := rec(pgITNewID(t))
		if _, _, err := st.CommitExecutionAttestation(ctx, r, ev(r)); err == nil {
			t.Fatal("attestation event append failure was swallowed")
		}
	})

	t.Run("storedReadFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		firstRec := rec(jobID)
		first, created, err := st.CommitExecutionAttestation(ctx, firstRec, ev(firstRec))
		if err != nil || !created {
			t.Fatalf("first attestation = created %v, %v", created, err)
		}
		if _, err := st.pool.Exec(ctx, `ALTER TABLE execution_attestations ALTER COLUMN statement_sha256 DROP DEFAULT`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.pool.Exec(ctx, `ALTER TABLE execution_attestations ALTER COLUMN statement_sha256 TYPE bytea USING '\x00'::bytea`); err != nil {
			t.Fatal(err)
		}
		replay := rec(jobID)
		if _, _, err := st.CommitExecutionAttestation(ctx, replay, ev(replay)); err == nil {
			t.Fatal("attestation replay over a mistyped stored column succeeded")
		}
		if first.StatementSHA256 != "sum" {
			t.Fatalf("stored attestation = %+v", first)
		}
	})
}

func hexGapDigest() string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

// TestPostgresIntegrationCheckCompiledRunJobKeysArms drives the run-scoped
// logical identity probe's query and scan failure arms directly.
func TestPostgresIntegrationCheckCompiledRunJobKeysArms(t *testing.T) {
	ctx := context.Background()

	t.Run("queryError", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITBreakColumn(t, st, "jobs", "key")
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := st.checkCompiledRunJobKeysTx(ctx, tx, runID, map[string]model.Job{"n": {Key: "x"}}); err == nil {
			t.Fatal("key probe over a mistyped key column succeeded")
		}
	})

	t.Run("scanError", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITBreakColumnToArray(t, st, "jobs", "key")
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := st.checkCompiledRunJobKeysTx(ctx, tx, runID, map[string]model.Job{"n": {Key: "x"}}); err == nil {
			t.Fatal("key probe scan over a text[] key succeeded")
		}
	})

	t.Run("conflict", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		j, err := st.GetJob(ctx, jobID)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var conflict *GeneratedJobKeyConflictError
		if err := st.checkCompiledRunJobKeysTx(ctx, tx, runID, map[string]model.Job{j.ID: {ID: j.ID, Key: j.Key}}); !errors.As(err, &conflict) {
			t.Fatalf("duplicate run key = %v, want *GeneratedJobKeyConflictError", err)
		}
	})

	t.Run("emptyJobs", func(t *testing.T) {
		st := pgITStore(t)
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := st.checkCompiledRunJobKeysTx(ctx, tx, "run-any", nil); err != nil {
			t.Fatalf("empty job map = %v, want nil", err)
		}
	})
}
