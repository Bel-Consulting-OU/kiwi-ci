package storage

// Coverage squeeze for the Postgres store: reader Scan/decode failures via
// deliberately mistyped columns, single-statement write failures via BEFORE
// triggers, and direct helper calls over a poisoned schema. Every case runs
// on its own throwaway schema, so the damage never leaks.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITBreakColumn retypes one column to integer so the store's text/bool/
// timestamp/json scanners fail deterministically on the next read. USING 0
// rewrites every existing row to the new type.
func pgITBreakColumn(t *testing.T, st *PostgresStore, table, column string) {
	t.Helper()
	q := fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN %s TYPE integer USING 0`, table, column)
	if _, err := st.pool.Exec(context.Background(), q); err != nil {
		t.Fatalf("break %s.%s: %v", table, column, err)
	}
}

// pgITBoomOp makes only one write event on table fail, so a later statement
// in a multi-statement helper can fail while earlier ones succeed.
func pgITBoomOp(t *testing.T, st *PostgresStore, table, event string, optionalColumn ...string) {
	t.Helper()
	ctx := context.Background()
	fn := "kiwi_boom_" + table + "_" + strings.ToLower(event)
	if _, err := st.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected `+event+` failure on `+table+`'; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create trigger function for %s: %v", table, err)
	}
	of := ""
	if len(optionalColumn) > 0 && optionalColumn[0] != "" {
		of = " OF " + optionalColumn[0]
	}
	if _, err := st.pool.Exec(ctx, `CREATE TRIGGER `+fn+`_t BEFORE `+event+of+` ON `+table+` FOR EACH ROW EXECUTE FUNCTION `+fn+`()`); err != nil {
		t.Fatalf("create %s trigger on %s: %v", event, table, err)
	}
}

// pgITBreakColumnToArray retypes a text column to text[] so the store's
// string scanners fail while the surrounding query stays valid.
func pgITBreakColumnToArray(t *testing.T, st *PostgresStore, table, column string) {
	t.Helper()
	q := fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN %s DROP DEFAULT`, table, column)
	if _, err := st.pool.Exec(context.Background(), q); err != nil {
		t.Fatalf("drop default %s.%s: %v", table, column, err)
	}
	q = fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN %s TYPE text[] USING ARRAY[]::text[]`, table, column)
	if _, err := st.pool.Exec(context.Background(), q); err != nil {
		t.Fatalf("break %s.%s: %v", table, column, err)
	}
}

// pgITDropColumn removes a column so a specific query fails while earlier
// statements in the same helper succeed.
func pgITDropColumn(t *testing.T, st *PostgresStore, table, column string) {
	t.Helper()
	q := fmt.Sprintf(`ALTER TABLE %s DROP COLUMN %s`, table, column)
	if _, err := st.pool.Exec(context.Background(), q); err != nil {
		t.Fatalf("drop %s.%s: %v", table, column, err)
	}
}

// TestPostgresIntegrationReaderScanSweep drives the rows.Scan error return of
// every reader by mistyping the column it scans.
func TestPostgresIntegrationReaderScanSweep(t *testing.T) {
	t.Run("ListRuns", func(t *testing.T) {
		st := pgITStore(t)
		pgITEnqueueOne(t, st, pgITNewID(t), pgITNewID(t), pgITRepo)
		pgITBreakColumn(t, st, "runs", "payload")
		if _, err := st.ListRuns(context.Background(), 10); err == nil {
			t.Fatal("ListRuns over a mistyped status = nil error")
		}
	})
	t.Run("ListJobsByRun", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBreakColumnToArray(t, st, "jobs", "key")
		if _, err := st.ListJobsByRun(context.Background(), runID); err == nil {
			t.Fatal("ListJobsByRun = nil error")
		}
	})
	t.Run("ListJobsByEnvironment", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		j := pgITJob(runID, jobID, pgITRepo)
		j.Environment = "prod"
		if err := st.InsertCompiledRun(context.Background(), InsertCompiledRunRequest{
			Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
			Jobs: map[string]model.Job{jobID: j},
		}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToArray(t, st, "jobs", "key")
		if _, err := st.ListJobsByEnvironment(context.Background(), pgITRepo, "prod"); err == nil {
			t.Fatal("ListJobsByEnvironment = nil error")
		}
	})
	t.Run("ListQueuedJobs", func(t *testing.T) {
		st := pgITStore(t)
		pgITEnqueueOne(t, st, pgITNewID(t), pgITNewID(t), pgITRepo)
		pgITBreakColumnToArray(t, st, "jobs", "key")
		if _, err := st.ListQueuedJobs(context.Background()); err == nil {
			t.Fatal("ListQueuedJobs = nil error")
		}
	})
	t.Run("ListJobsByRunner", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		runnerID := pgITNewID(t)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		if task, err := st.AcquireLeaseAtomic(context.Background(), LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, TokenHash: []byte("h"), ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil || task.ID != jobID {
			t.Fatalf("lease: %v %+v", err, task)
		}
		pgITBreakColumnToArray(t, st, "jobs", "key")
		if _, err := st.ListJobsByRunner(context.Background(), runnerID); err == nil {
			t.Fatal("ListJobsByRunner = nil error")
		}
	})
	t.Run("ListRunners", func(t *testing.T) {
		st := pgITStore(t)
		pgITSeedRunner(t, st, pgITNewID(t), 1, 0, 0)
		pgITBreakColumn(t, st, "runners", "registered")
		if _, err := st.ListRunners(context.Background()); err == nil {
			t.Fatal("ListRunners = nil error")
		}
	})
	t.Run("ReadLogs", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		if err := st.AppendLog(context.Background(), model.LogEntry{RunID: runID, JobID: jobID, JobKey: "build", Step: "s", Line: "l", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "log_entries", "step")
		if _, err := st.ReadLogs(context.Background(), runID, 0, 10); err == nil {
			t.Fatal("ReadLogs = nil error")
		}
	})
	t.Run("ReadAudit", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.AppendAudit(context.Background(), model.AuditEvent{ID: pgITNewID(t), Action: "a", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "audit_events", "created_at")
		if _, err := st.ReadAudit(context.Background(), 10); err == nil {
			t.Fatal("ReadAudit = nil error")
		}
	})
	t.Run("OutboxPending", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.OutboxAppend(context.Background(), OutboxItem{ID: pgITNewID(t), Kind: "k", Payload: []byte("{}"), CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "outbox", "created_at")
		if _, err := st.OutboxPending(context.Background()); err == nil {
			t.Fatal("OutboxPending = nil error")
		}
	})
	t.Run("ClaimOutbox", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.OutboxAppend(context.Background(), OutboxItem{ID: pgITNewID(t), Kind: "k", Payload: []byte("{}"), CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToArray(t, st, "outbox", "kind")
		if _, err := st.ClaimOutbox(context.Background(), "claimer", 10); err == nil {
			t.Fatal("ClaimOutbox = nil error")
		}
	})
	t.Run("ListSchedules", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.UpsertSchedule(context.Background(), Schedule{ID: pgITNewID(t), Repository: "r", Spec: "@daily", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "schedules", "created_at")
		if _, err := st.ListSchedules(context.Background()); err == nil {
			t.Fatal("ListSchedules = nil error")
		}
	})
	t.Run("ListOccurrences", func(t *testing.T) {
		st := pgITStore(t)
		schedID := pgITNewID(t)
		if err := st.UpsertSchedule(context.Background(), Schedule{ID: schedID, Repository: "r", Spec: "@daily", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ClaimScheduleOccurrence(context.Background(), schedID, time.Now().UTC().Truncate(time.Minute), pgITNewID(t)); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "schedule_occurrences", "nominal")
		if _, err := st.ListOccurrences(context.Background(), schedID); err == nil {
			t.Fatal("ListOccurrences = nil error")
		}
	})
	t.Run("ListArtifacts", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		if err := st.InsertArtifact(context.Background(), model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, Name: "bin", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "artifacts", "payload")
		if _, err := st.ListArtifacts(context.Background(), runID); err == nil {
			t.Fatal("ListArtifacts = nil error")
		}
	})
	t.Run("ListTestReports", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		if err := st.InsertTestReport(context.Background(), model.TestReport{ID: pgITNewID(t), RunID: runID, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "test_results", "payload")
		if _, err := st.ListTestReports(context.Background(), runID); err == nil {
			t.Fatal("ListTestReports = nil error")
		}
	})
	t.Run("ListDeploymentsByRun", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		if err := st.InsertDeployment(context.Background(), model.Deployment{ID: pgITNewID(t), RunID: runID, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "deployments", "payload")
		if _, err := st.ListDeploymentsByRun(context.Background(), runID); err == nil {
			t.Fatal("ListDeploymentsByRun = nil error")
		}
	})
	t.Run("ListSnapshotsByRun", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		if err := st.InsertSnapshotRecord(context.Background(), model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "workspace_snapshots", "payload")
		if _, err := st.ListSnapshotsByRun(context.Background(), runID); err == nil {
			t.Fatal("ListSnapshotsByRun = nil error")
		}
	})
}

// TestPostgresIntegrationRecomputeHelperBreaks drives the recompute helpers
// with a poisoned jobs/runs schema so each guarded return fires.
func TestPostgresIntegrationRecomputeHelperBreaks(t *testing.T) {
	t.Run("recomputeRunTx jobs query", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITDropColumn(t, st, "jobs", "status")
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := st.recomputeRunTx(context.Background(), tx, runID); err == nil {
			t.Fatal("recomputeRunTx over a broken jobs table = nil error")
		}
	})
	t.Run("recomputeRunTx job scan", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBreakColumn(t, st, "jobs", "started_at")
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := st.recomputeRunTx(context.Background(), tx, runID); err == nil {
			t.Fatal("recomputeRunTx scan failure = nil error")
		}
	})
	t.Run("recomputeRunTx run payload scan", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBreakColumn(t, st, "runs", "payload")
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := st.recomputeRunTx(context.Background(), tx, runID); err == nil {
			t.Fatal("recomputeRunTx run scan failure = nil error")
		}
	})
	t.Run("recomputeRunTx unchanged", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		// Cancel the run so recomputeRunStatus reports no change.
		if _, err := st.CancelRunJobs(context.Background(), runID, "test"); err != nil {
			t.Fatal(err)
		}
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := st.recomputeRunTx(context.Background(), tx, runID); err != nil {
			t.Fatalf("cancelled run = %v", err)
		}
	})
	t.Run("recomputeDependentTx job query", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITDropColumn(t, st, "jobs", "status")
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := st.recomputeDependentTx(context.Background(), tx, jobID, time.Now().UTC()); err == nil {
			t.Fatal("recomputeDependentTx over a broken jobs table = nil error")
		}
	})
	t.Run("supersededJobIDsTx runs query", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITDropColumn(t, st, "runs", "payload")
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := st.supersededJobIDsTx(context.Background(), tx, &SupersedePolicy{Repo: pgITRepo, ConcurrencyGroup: "g"}, "new-run"); err == nil {
			t.Fatal("supersededJobIDsTx runs query failure = nil error")
		}
	})
	t.Run("supersededJobIDsTx jobs query", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		req := InsertCompiledRunRequest{
			Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC(), ConcurrencyGroup: "g"},
			Jobs: map[string]model.Job{jobID: pgITJob(runID, jobID, pgITRepo)},
		}
		if err := st.InsertCompiledRun(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		pgITDropColumn(t, st, "jobs", "status")
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := st.supersededJobIDsTx(context.Background(), tx, &SupersedePolicy{Repo: pgITRepo, ConcurrencyGroup: "g"}, "new-run"); err == nil {
			t.Fatal("supersededJobIDsTx jobs query failure = nil error")
		}
	})
	t.Run("recomputeDependentsTx query", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITDropColumn(t, st, "job_dependencies", "depends_on")
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := st.recomputeDependentsTx(context.Background(), tx, jobID, time.Now().UTC()); err == nil {
			t.Fatal("recomputeDependentsTx query failure = nil error")
		}
	})
}

// TestPostgresIntegrationSimpleStatementFailures makes one statement fail at
// a time with BEFORE triggers so the store's guarded SQL returns fire.
func TestPostgresIntegrationSimpleStatementFailures(t *testing.T) {
	t.Run("InsertRun", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoom(t, st, "runs")
		ctx := context.Background()
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := st.insertRunTx(ctx, tx, model.Run{ID: pgITNewID(t), Status: model.StatusQueued, CreatedAt: time.Now().UTC()}); err == nil {
			t.Fatal("insertRunTx over a boom trigger = nil error")
		}
	})
	t.Run("InsertJob", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBoom(t, st, "jobs")
		if err := st.InsertJob(context.Background(), pgITJob(runID, pgITNewID(t), pgITRepo)); err == nil {
			t.Fatal("InsertJob over a boom trigger = nil error")
		}
	})
	t.Run("UpdateJob", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITBoom(t, st, "jobs")
		j := pgITJob(runID, jobID, pgITRepo)
		j.Status = model.StatusRunning
		if err := st.UpdateJob(context.Background(), j); err == nil {
			t.Fatal("UpdateJob over a boom trigger = nil error")
		}
	})
	t.Run("InsertArtifact", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBoom(t, st, "artifacts")
		if err := st.InsertArtifact(context.Background(), model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, Name: "bin"}); err == nil {
			t.Fatal("InsertArtifact over a boom trigger = nil error")
		}
	})
	t.Run("InsertArtifactOnce", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBoom(t, st, "artifacts")
		if _, _, err := st.InsertArtifactOnce(context.Background(), model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, Name: "bin"}); err == nil {
			t.Fatal("InsertArtifactOnce over a boom trigger = nil error")
		}
	})
	t.Run("InsertTestReport", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBoom(t, st, "test_results")
		if err := st.InsertTestReport(context.Background(), model.TestReport{ID: pgITNewID(t), RunID: runID, CreatedAt: time.Now().UTC()}); err == nil {
			t.Fatal("InsertTestReport over a boom trigger = nil error")
		}
	})
	t.Run("AppendAudit", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoom(t, st, "audit_events")
		if err := st.AppendAudit(context.Background(), model.AuditEvent{ID: pgITNewID(t), Action: "a", CreatedAt: time.Now().UTC()}); err == nil {
			t.Fatal("AppendAudit over a boom trigger = nil error")
		}
	})
	t.Run("OutboxAppend", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoom(t, st, "outbox")
		if err := st.OutboxAppend(context.Background(), OutboxItem{ID: pgITNewID(t), Kind: "k", Payload: []byte("{}"), CreatedAt: time.Now().UTC()}); err == nil {
			t.Fatal("OutboxAppend over a boom trigger = nil error")
		}
	})
	t.Run("InsertDeployment", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBoom(t, st, "deployments")
		if err := st.InsertDeployment(context.Background(), model.Deployment{ID: pgITNewID(t), RunID: runID, CreatedAt: time.Now().UTC()}); err == nil {
			t.Fatal("InsertDeployment over a boom trigger = nil error")
		}
	})
	t.Run("InsertSnapshotRecord", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBoom(t, st, "workspace_snapshots")
		if err := st.InsertSnapshotRecord(context.Background(), model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, CreatedAt: time.Now().UTC()}); err == nil {
			t.Fatal("InsertSnapshotRecord over a boom trigger = nil error")
		}
	})
	t.Run("InsertJobContracts", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITBoom(t, st, "jobs")
		if err := st.InsertJobContracts(context.Background(), jobID, map[string]ArtifactContract{"bin": {Name: "bin"}}); err == nil {
			t.Fatal("InsertJobContracts over a boom trigger = nil error")
		}
	})
	t.Run("SetQueueReasons", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITBoom(t, st, "jobs")
		if err := st.SetQueueReasons(context.Background(), map[string]string{jobID: "ENV"}); err == nil {
			t.Fatal("SetQueueReasons over a boom trigger = nil error")
		}
	})
	t.Run("PutCacheManifest", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoom(t, st, "cache_manifests")
		if err := st.PutCacheManifest(context.Background(), CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "k", BlobSHA256: "sum", CreatedAt: time.Now().UTC()}); err == nil {
			t.Fatal("PutCacheManifest over a boom trigger = nil error")
		}
	})
	t.Run("SetArtifactSidecars", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		artID := pgITNewID(t)
		if err := st.InsertArtifact(context.Background(), model.ArtifactRecord{ID: artID, RunID: runID, Name: "bin"}); err != nil {
			t.Fatal(err)
		}
		pgITBoom(t, st, "artifacts")
		if err := st.SetArtifactSidecars(context.Background(), artID, "p", "s", "", ""); err == nil {
			t.Fatal("SetArtifactSidecars over a boom trigger = nil error")
		}
	})
	t.Run("UpsertProfile", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoom(t, st, "runner_profiles")
		if err := st.UpsertProfile(context.Background(), model.RunnerProfile{ID: pgITNewID(t), CreatedAt: time.Now().UTC()}); err == nil {
			t.Fatal("UpsertProfile over a boom trigger = nil error")
		}
	})
	t.Run("PutEnrollGrant", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoom(t, st, "enrollment_grants")
		if err := st.PutEnrollGrant(context.Background(), "digest", time.Now().UTC().Add(time.Hour), nil); err == nil {
			t.Fatal("PutEnrollGrant over a boom trigger = nil error")
		}
	})
	t.Run("ConsumeEnrollGrant", func(t *testing.T) {
		st := pgITStore(t)
		digest := pgITNewID(t)
		if err := st.PutEnrollGrant(context.Background(), digest, time.Now().UTC().Add(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		pgITBoom(t, st, "enrollment_grants")
		if _, err := st.ConsumeEnrollGrant(context.Background(), digest, "cb"); err == nil {
			t.Fatal("ConsumeEnrollGrant over a boom trigger = nil error")
		}
	})
	t.Run("RevokeCert", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		if err := st.BindCertProfile(context.Background(), "serial-1", pgITNewID(t)); err != nil {
			t.Fatal(err)
		}
		if err := st.RevokeCert(context.Background(), "serial-1", runnerID, "reason"); err != nil {
			t.Fatal(err)
		}
		pgITBoom(t, st, "cert_revocations")
		if err := st.RevokeCert(context.Background(), "serial-2", runnerID, "reason"); err == nil {
			t.Fatal("RevokeCert over a boom trigger = nil error")
		}
	})
	t.Run("AdjustQuotaCounter", func(t *testing.T) {
		st := pgITStore(t)
		ctx := context.Background()
		if _, err := st.pool.Exec(ctx, `INSERT INTO quota_reservations (key, running, queued, updated_at) VALUES ('repo', 0, 0, now())`); err != nil {
			t.Fatal(err)
		}
		pgITBoom(t, st, "quota_reservations")
		if err := st.AdjustQuotaCounter(ctx, "repo", "team", 1, 1); err == nil {
			t.Fatal("AdjustQuotaCounter over a boom trigger = nil error")
		}
	})
	t.Run("InsertGeneratedJobs", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		pgITBoom(t, st, "jobs")
		child := pgITJob(runID, pgITNewID(t), pgITRepo)
		if err := st.InsertGeneratedJobs(context.Background(), parentID, 1, map[string]model.Job{child.ID: child}, map[string][]string{child.ID: {parentID}}); err == nil {
			t.Fatal("InsertGeneratedJobs over a boom trigger = nil error")
		}
	})
	t.Run("AppendDownstreamRun", func(t *testing.T) {
		st := pgITStore(t)
		runID, childID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBoom(t, st, "runs")
		if err := st.AppendDownstreamRun(context.Background(), runID, childID); err == nil {
			t.Fatal("AppendDownstreamRun over a boom trigger = nil error")
		}
	})
	t.Run("ReleaseRunnerJob", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITBoom(t, st, "jobs")
		if err := st.ReleaseRunnerJob(context.Background(), "missing-runner", jobID, model.StatusSuccess); err == nil {
			t.Fatal("ReleaseRunnerJob over a boom trigger = nil error")
		}
	})
	t.Run("UpdateDeploymentStatus", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		deploymentID := pgITNewID(t)
		if err := st.InsertDeployment(context.Background(), model.Deployment{ID: deploymentID, RunID: runID, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBoom(t, st, "deployments")
		if err := st.UpdateDeploymentStatus(context.Background(), deploymentID, model.StatusSuccess, nil); err == nil {
			t.Fatal("UpdateDeploymentStatus over a boom trigger = nil error")
		}
	})
	t.Run("ReserveDownstreamLaunch", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITBoom(t, st, "downstream_links")
		if _, err := st.ReserveDownstreamLaunch(context.Background(), jobID, "acme/child", "main", "tok"); err == nil {
			t.Fatal("ReserveDownstreamLaunch over a boom trigger = nil error")
		}
	})
	t.Run("LoadTestHistory", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(context.Background(), `ALTER TABLE test_history DROP COLUMN stats`); err != nil {
			t.Fatalf("drop stats: %v", err)
		}
		if _, _, err := st.LoadTestHistory(context.Background()); err == nil {
			t.Fatal("LoadTestHistory over a missing column = nil error")
		}
	})
}

// TestPostgresIntegrationLeadershipAndMigrateErrors covers the leadership,
// schema and migration error returns.
func TestPostgresIntegrationLeadershipAndMigrateErrors(t *testing.T) {
	t.Run("TryAcquireLeadership failure", func(t *testing.T) {
		st := pgITStore(t)
		_ = st
		if _, err := st.TryAcquireLeadership(context.Background(), "", time.Minute); err == nil {
			t.Fatal("TryAcquireLeadership with an empty key = nil error")
		}
		if _, err := st.TryAcquireLeadership(context.Background(), "k", 0); err == nil {
			t.Fatal("TryAcquireLeadership with a zero ttl = nil error")
		}
	})

	t.Run("TryAcquireLeadership connect failure", func(t *testing.T) {
		cfg, err := pgxpool.ParseConfig(pgITDSN(t))
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.Host = "127.0.0.1"
		cfg.ConnConfig.Port = 1
		cfg.ConnConfig.ConnectTimeout = time.Second
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		bad := &PostgresStore{pool: pool}
		if _, err := bad.TryAcquireLeadership(context.Background(), "k", time.Minute); err == nil {
			t.Fatal("TryAcquireLeadership against an unreachable host = nil error")
		}
	})
	t.Run("ReleaseLeadership broken leader connection", func(t *testing.T) {
		st := pgITStore(t)
		ctx := context.Background()
		if _, err := st.TryAcquireLeadership(ctx, "k", time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := st.TryAcquireLeadership(ctx, "k", time.Minute); err != nil {
			t.Fatal(err)
		}
		if st.leaderConn == nil {
			t.Fatal("no leadership connection")
		}
		_ = st.leaderConn.Close(ctx)
		if err := st.ReleaseLeadership(ctx, "k"); err == nil {
			t.Fatal("ReleaseLeadership over a closed leader connection = nil error")
		}
	})
	t.Run("SchemaVersion failure", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(context.Background(), `ALTER TABLE schema_migrations DROP COLUMN version`); err != nil {
			t.Fatalf("drop schema_migrations.version: %v", err)
		}
		if _, err := st.SchemaVersion(context.Background()); err == nil {
			t.Fatal("SchemaVersion over a broken table = nil error")
		}
	})
	t.Run("Migrate migration insert failure", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(context.Background(), `ALTER TABLE schema_migrations DROP COLUMN version`); err != nil {
			t.Fatalf("drop schema_migrations.version: %v", err)
		}
		if err := st.Migrate(context.Background()); err == nil {
			t.Fatal("Migrate over a broken schema_migrations = nil error")
		}
	})
	t.Run("open pool failure", func(t *testing.T) {
		// The DSN parses but the host cannot resolve, so the pool can never
		// establish a connection.
		if _, err := NewPostgresOpt(context.Background(), "postgres://nobody@nonexistent.invalid:5432/nope?sslmode=disable&connect_timeout=1"); err == nil {
			t.Fatal("NewPostgresOpt with an unresolvable host = nil error")
		}
	})
	t.Run("WithMaxConnections", func(t *testing.T) {
		cfg := poolConfigForTest()
		WithMaxConnections(0)(cfg)
		if cfg.MaxConns != 0 {
			t.Fatalf("WithMaxConnections(0) set %d", cfg.MaxConns)
		}
		WithMaxConnections(7)(cfg)
		if cfg.MaxConns != 7 {
			t.Fatalf("WithMaxConnections(7) set %d", cfg.MaxConns)
		}
	})
}

// TestPostgresIntegrationCloseThenSweep closes the pool and drives the
// first-statement error return of a broad sample of methods.
func TestPostgresIntegrationCloseThenSweep(t *testing.T) {
	st := pgITStore(t)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	runnerID := pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ctx := context.Background()
	if _, err := st.GetRun(ctx, runID); err == nil {
		t.Fatal("GetRun on a closed pool = nil error")
	}
	if _, err := st.GetJob(ctx, jobID); err == nil {
		t.Fatal("GetJob on a closed pool = nil error")
	}
	if _, err := st.ListRuns(ctx, 1); err == nil {
		t.Fatal("ListRuns on a closed pool = nil error")
	}
	if _, err := st.ListJobsByRun(ctx, runID); err == nil {
		t.Fatal("ListJobsByRun on a closed pool = nil error")
	}
	if _, err := st.ListQueuedJobs(ctx); err == nil {
		t.Fatal("ListQueuedJobs on a closed pool = nil error")
	}
	if _, err := st.ListRunners(ctx); err == nil {
		t.Fatal("ListRunners on a closed pool = nil error")
	}
	if _, err := st.ReadAudit(ctx, 1); err == nil {
		t.Fatal("ReadAudit on a closed pool = nil error")
	}
	if _, err := st.ReadLogs(ctx, runID, 0, 1); err == nil {
		t.Fatal("ReadLogs on a closed pool = nil error")
	}
	if _, err := st.ListSchedules(ctx); err == nil {
		t.Fatal("ListSchedules on a closed pool = nil error")
	}
	if _, err := st.ListArtifacts(ctx, runID); err == nil {
		t.Fatal("ListArtifacts on a closed pool = nil error")
	}
	if _, err := st.OutboxPending(ctx); err == nil {
		t.Fatal("OutboxPending on a closed pool = nil error")
	}
	if _, err := st.ClaimOutbox(ctx, "c", 1); err == nil {
		t.Fatal("ClaimOutbox on a closed pool = nil error")
	}
	if _, err := st.ListSnapshotsByRun(ctx, runID); err == nil {
		t.Fatal("ListSnapshotsByRun on a closed pool = nil error")
	}
	if _, err := st.ListDeploymentsByRun(ctx, runID); err == nil {
		t.Fatal("ListDeploymentsByRun on a closed pool = nil error")
	}
	if _, err := st.ListOccurrences(ctx, "s"); err == nil {
		t.Fatal("ListOccurrences on a closed pool = nil error")
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID}); err == nil {
		t.Fatal("UpsertRunner on a closed pool = nil error")
	}
	if err := st.AppendAudit(ctx, model.AuditEvent{ID: "a"}); err == nil {
		t.Fatal("AppendAudit on a closed pool = nil error")
	}
	if err := st.UpdateJob(ctx, model.Job{ID: jobID}); err == nil {
		t.Fatal("UpdateJob on a closed pool = nil error")
	}
	// ReleaseLeadership on a pool with no held leadership connection is a
	// documented no-op.
	if err := st.ReleaseLeadership(ctx, "k"); err != nil {
		t.Fatalf("ReleaseLeadership without a held lock = %v", err)
	}
	if _, err := st.SchemaVersion(ctx); err == nil {
		t.Fatal("SchemaVersion on a closed pool = nil error")
	}
	if _, _, err := st.LoadTestHistory(ctx); err == nil {
		t.Fatal("LoadTestHistory on a closed pool = nil error")
	}
	if err := st.AdjustQuotaCounter(ctx, "r", "t", 1, 1); err == nil {
		t.Fatal("AdjustQuotaCounter on a closed pool = nil error")
	}
	if err := st.PutEnrollGrant(ctx, "d", time.Now().UTC(), nil); err == nil {
		t.Fatal("PutEnrollGrant on a closed pool = nil error")
	}
	if _, err := st.ConsumeEnrollGrant(ctx, "d", "cb"); err == nil {
		t.Fatal("ConsumeEnrollGrant on a closed pool = nil error")
	}
	if err := st.PutCacheManifest(ctx, CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "k", CreatedAt: time.Now().UTC()}); err == nil {
		t.Fatal("PutCacheManifest on a closed pool = nil error")
	}
	if _, err := st.ListTestReports(ctx, runID); err == nil {
		t.Fatal("ListTestReports on a closed pool = nil error")
	}
	if _, err := st.ListJobsByEnvironment(ctx, pgITRepo, "prod"); err == nil {
		t.Fatal("ListJobsByEnvironment on a closed pool = nil error")
	}
	if _, err := st.ListJobsByRunner(ctx, runnerID); err == nil {
		t.Fatal("ListJobsByRunner on a closed pool = nil error")
	}
}

// poolConfigForTest returns a pgxpool.Config for WithMaxConnections tests.
func poolConfigForTest() *pgxpool.Config {
	return &pgxpool.Config{}
}

var _ = errors.New
var _ = pgx.ErrNoRows

// TestPostgresIntegrationClosedPoolBeginSweep drives every pool.Begin error
// return with a closed pool and valid arguments.
func TestPostgresIntegrationClosedPoolBeginSweep(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	runnerID := pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	profileID := pgITNewID(t)
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, MaxCapacity: 2, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	job := model.Job{ID: pgITNewID(t), RunID: runID, Key: "k", Status: model.StatusQueued, CreatedAt: now}
	run := model.Run{ID: pgITNewID(t), Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: now}
	claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, TokenHash: []byte("h"), ExpiresAt: now.Add(time.Hour), RunnerCapacity: 2}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: run, Jobs: map[string]model.Job{job.ID: job}}); err == nil {
		t.Fatal("InsertCompiledRun on a closed pool = nil error")
	}
	if err := st.InsertRun(ctx, run); err == nil {
		t.Fatal("InsertRun on a closed pool = nil error")
	}
	if err := st.UpdateRunStatus(ctx, runID, model.StatusRunning, &now, nil); err == nil {
		t.Fatal("UpdateRunStatus on a closed pool = nil error")
	}
	if err := st.InsertJob(ctx, job); err == nil {
		t.Fatal("InsertJob on a closed pool = nil error")
	}
	if err := st.UpdateJob(ctx, job); err == nil {
		t.Fatal("UpdateJob on a closed pool = nil error")
	}
	if _, err := st.AcquireLeaseAtomic(ctx, claim); err == nil {
		t.Fatal("AcquireLeaseAtomic on a closed pool = nil error")
	}
	if _, err := st.AcquireLease(ctx, jobID, runnerID, []byte("h"), 1, now.Add(time.Hour)); err == nil {
		t.Fatal("AcquireLease on a closed pool = nil error")
	}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{}); err == nil {
		t.Fatal("CompleteJob on a closed pool = nil error")
	}
	if err := st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusSuccess); err == nil {
		t.Fatal("ReleaseRunnerJob on a closed pool = nil error")
	}
	if _, err := st.CancelRunJobs(ctx, runID, "reason"); err == nil {
		t.Fatal("CancelRunJobs on a closed pool = nil error")
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: jobID, FragmentID: "f", LeaseGeneration: 1}, nil); err == nil {
		t.Fatal("InsertGeneratedFragmentTx on a closed pool = nil error")
	}
	if err := st.InsertGeneratedJobs(ctx, jobID, 1, map[string]model.Job{job.ID: job}, nil); err == nil {
		t.Fatal("InsertGeneratedJobs on a closed pool = nil error")
	}
	if err := st.InsertDeployment(ctx, model.Deployment{ID: pgITNewID(t), RunID: runID, CreatedAt: now}); err == nil {
		t.Fatal("InsertDeployment on a closed pool = nil error")
	}
	if err := st.InsertSnapshotRecord(ctx, model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, CreatedAt: now}); err == nil {
		t.Fatal("InsertSnapshotRecord on a closed pool = nil error")
	}
	if err := st.SetArtifactSidecars(ctx, "artifact", "p", "s", "", ""); err == nil {
		t.Fatal("SetArtifactSidecars on a closed pool = nil error")
	}
	if err := st.PutCacheManifest(ctx, CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "k"}); err == nil {
		t.Fatal("PutCacheManifest on a closed pool = nil error")
	}
	if err := st.AppendDownstreamRun(ctx, runID, pgITNewID(t)); err == nil {
		t.Fatal("AppendDownstreamRun on a closed pool = nil error")
	}
	if err := st.PutEnrollGrant(ctx, "digest", now.Add(time.Hour), nil); err == nil {
		t.Fatal("PutEnrollGrant on a closed pool = nil error")
	}
	if err := st.SetQueueReasons(ctx, map[string]string{jobID: "ENV"}); err == nil {
		t.Fatal("SetQueueReasons on a closed pool = nil error")
	}
	if err := st.InsertArtifact(ctx, model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, Name: "bin"}); err == nil {
		t.Fatal("InsertArtifact on a closed pool = nil error")
	}
	if _, _, err := st.InsertArtifactOnce(ctx, model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, Name: "bin"}); err == nil {
		t.Fatal("InsertArtifactOnce on a closed pool = nil error")
	}
	if err := st.AppendAudit(ctx, model.AuditEvent{ID: pgITNewID(t), Action: "a"}); err == nil {
		t.Fatal("AppendAudit on a closed pool = nil error")
	}
	if err := st.OutboxAppend(ctx, OutboxItem{ID: pgITNewID(t), Kind: "k", Payload: []byte("{}")}); err == nil {
		t.Fatal("OutboxAppend on a closed pool = nil error")
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Capacity: 1}); err == nil {
		t.Fatal("UpsertRunner on a closed pool = nil error")
	}
	if err := st.InsertJobContracts(ctx, jobID, map[string]ArtifactContract{"bin": {Name: "bin"}}); err == nil {
		t.Fatal("InsertJobContracts on a closed pool = nil error")
	}
	if err := st.HeartbeatLease(ctx, jobID, runnerID, 1, now); err == nil {
		t.Fatal("HeartbeatLease on a closed pool = nil error")
	}
	if err := st.UpdateDeploymentStatus(ctx, "d", model.StatusSuccess, nil); err == nil {
		t.Fatal("UpdateDeploymentStatus on a closed pool = nil error")
	}
	if _, err := st.ReserveDownstreamLaunch(ctx, jobID, "acme/child", "main", "tok"); err == nil {
		t.Fatal("ReserveDownstreamLaunch on a closed pool = nil error")
	}
	if err := st.RevokeCert(ctx, "serial", runnerID, "reason"); err == nil {
		t.Fatal("RevokeCert on a closed pool = nil error")
	}
	if _, err := st.ConsumeEnrollGrant(ctx, "digest", "cb"); err == nil {
		t.Fatal("ConsumeEnrollGrant on a closed pool = nil error")
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, CreatedAt: now}); err == nil {
		t.Fatal("UpsertProfile on a closed pool = nil error")
	}
	if _, err := st.ClaimScheduleOccurrence(ctx, pgITNewID(t), now, pgITNewID(t)); err == nil {
		t.Fatal("ClaimScheduleOccurrence on a closed pool = nil error")
	}
}

// TestPostgresIntegrationNaNPayloadMarshal drives the JSON marshal guards
// that only fail on un-encodable float values.
func TestPostgresIntegrationNaNPayloadMarshal(t *testing.T) {
	nan := math.NaN()
	ctx := context.Background()
	t.Run("InsertJob run payload", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		j := pgITJob(runID, pgITNewID(t), pgITRepo)
		j.CostRate = nan
		if err := st.InsertJob(ctx, j); err == nil {
			t.Fatal("InsertJob with NaN = nil error")
		}
	})
	t.Run("InsertGeneratedJobs job payload", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		j := pgITJob(runID, pgITNewID(t), pgITRepo)
		j.PowerWatts = nan
		if err := st.InsertGeneratedJobs(ctx, parentID, 1, map[string]model.Job{j.ID: j}, nil); err == nil {
			t.Fatal("InsertGeneratedJobs with NaN = nil error")
		}
	})
}

// TestPostgresIntegrationMiscStatementBreaks covers the remaining statement
// guards with per-statement schema damage.
func TestPostgresIntegrationMiscStatementBreaks(t *testing.T) {
	t.Run("LoadTestHistory missing row", func(t *testing.T) {
		st := pgITStore(t)
		v, stats, err := st.LoadTestHistory(context.Background())
		if err != nil || v != 0 || stats != nil {
			t.Fatalf("empty history = %v %v %v", v, stats, err)
		}
	})
	t.Run("claimDownstreamLaunchTx invalid child", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		if _, err := st.ReserveDownstreamLaunch(context.Background(), jobID, "acme/child", "main", "tok"); err != nil {
			t.Fatal(err)
		}
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := st.claimDownstreamLaunchTx(context.Background(), tx, &DownstreamLaunchClaim{LinkKey: jobID + "\x00acme/child\x00main", StableChildID: strings.Repeat("a", 64)}, "bad id!"); err == nil {
			t.Fatal("invalid child run id = nil error")
		}
	})
	t.Run("insertScheduleClaimTx occurrence read", func(t *testing.T) {
		st := pgITStore(t)
		schedID := pgITNewID(t)
		if err := st.UpsertSchedule(context.Background(), Schedule{ID: schedID, Repository: "r", Spec: "@daily", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBoom(t, st, "schedule_occurrences")
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := st.insertScheduleClaimTx(context.Background(), tx, &ScheduleClaim{ScheduleID: schedID, Nominal: time.Now().UTC()}, pgITNewID(t)); err == nil {
			t.Fatal("insertScheduleClaimTx over a broken table = nil error")
		}
	})
	t.Run("insertScheduleClaimTx fresh claim", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		schedID := pgITNewID(t)
		if err := st.UpsertSchedule(context.Background(), Schedule{ID: schedID, Repository: "r", Spec: "@daily", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := st.insertScheduleClaimTx(context.Background(), tx, &ScheduleClaim{ScheduleID: schedID, Nominal: time.Now().UTC()}, pgITNewID(t)); err != nil {
			t.Fatalf("fresh occurrence claim = %v", err)
		}
	})
	t.Run("claimQuotaTx failure", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoom(t, st, "quota_reservations")
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := st.claimQuotaTx(context.Background(), tx, "repo", 1, 1); err == nil {
			t.Fatal("claimQuotaTx over a boom trigger = nil error")
		}
	})
	t.Run("profileForSerialTx failure", func(t *testing.T) {
		st := pgITStore(t)
		serial := "serial-x"
		runnerID := pgITNewID(t)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		if err := st.BindCertProfile(context.Background(), serial, pgITNewID(t)); err != nil {
			t.Fatal(err)
		}
		if _, err := st.pool.Exec(context.Background(), `ALTER TABLE cert_profile_links DROP COLUMN profile_id`); err != nil {
			t.Fatalf("drop profile_id: %v", err)
		}
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, _, _, err := profileForSerialTx(context.Background(), tx, serial); err == nil {
			t.Fatal("profileForSerialTx over a broken table = nil error")
		}
	})
	t.Run("HeartbeatLease failure", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITDropColumn(t, st, "jobs", "status")
		if err := st.HeartbeatLease(context.Background(), jobID, "r", 1, time.Now().UTC()); err == nil {
			t.Fatal("HeartbeatLease over a broken jobs table = nil error")
		}
	})
	t.Run("CompleteJob receipt read failure", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITBoom(t, st, "completion_receipts")
		if err := st.CompleteJob(context.Background(), jobID, 1, "r", model.StatusSuccess, "", nil, model.CompletionReceipt{}); err == nil {
			t.Fatal("CompleteJob receipt read over a boom trigger = nil error")
		}
	})
	t.Run("CompleteJob run lock failure", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITDropColumn(t, st, "runs", "payload")
		if err := st.CompleteJob(context.Background(), jobID, 1, "r", model.StatusSuccess, "", nil, model.CompletionReceipt{}); err == nil {
			t.Fatal("CompleteJob run lock over a broken runs table = nil error")
		}
	})
	t.Run("CancelRunJobs query failure", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITDropColumn(t, st, "jobs", "lease_runner_id")
		if _, err := st.CancelRunJobs(context.Background(), runID, "reason"); err == nil {
			t.Fatal("CancelRunJobs query failure = nil error")
		}
	})
	t.Run("CancelRunJobs scan failure", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		if _, err := st.pool.Exec(context.Background(), `DROP INDEX jobs_environment_running_idx`); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToArray(t, st, "jobs", "status")
		if _, err := st.CancelRunJobs(context.Background(), runID, "reason"); err == nil {
			t.Fatal("CancelRunJobs scan failure = nil error")
		}
	})
	t.Run("CancelRunJobs run read failure", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		tx, err := st.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		pgITBreakColumnToArray(t, st, "runs", "status")
		if _, err := st.CancelRunJobs(context.Background(), runID, "reason"); err == nil {
			t.Fatal("CancelRunJobs run read failure = nil error")
		}
	})
	t.Run("ReleaseRunnerJob runner read failure", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		pgITBreakColumn(t, st, "runners", "last_seen")
		if err := st.ReleaseRunnerJob(context.Background(), runnerID, pgITNewID(t), model.StatusSuccess); err == nil {
			t.Fatal("ReleaseRunnerJob runner read failure = nil error")
		}
	})
	t.Run("ClaimScheduleOccurrence failure", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoom(t, st, "schedules")
		if _, err := st.ClaimScheduleOccurrence(context.Background(), "missing", time.Now().UTC(), pgITNewID(t)); err == nil {
			t.Fatal("ClaimScheduleOccurrence over a boom trigger = nil error")
		}
	})
	t.Run("InsertDeployment bad run", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.InsertDeployment(context.Background(), model.Deployment{ID: pgITNewID(t), RunID: "bad run id!"}); err == nil {
			t.Fatal("InsertDeployment with an invalid run id = nil error")
		}
	})
	t.Run("InsertSnapshotRecord bad run", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.InsertSnapshotRecord(context.Background(), model.SnapshotRecord{ID: pgITNewID(t), RunID: "bad run id!"}); err == nil {
			t.Fatal("InsertSnapshotRecord with an invalid run id = nil error")
		}
	})
	t.Run("AppendDownstreamRun failure", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		if _, err := st.pool.Exec(context.Background(), `ALTER TABLE runs DROP COLUMN payload`); err != nil {
			t.Fatalf("drop runs.payload: %v", err)
		}
		if err := st.AppendDownstreamRun(context.Background(), runID, pgITNewID(t)); err == nil {
			t.Fatal("AppendDownstreamRun over a missing payload = nil error")
		}
	})
	t.Run("ReserveDownstreamLaunch failures", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITBoomOp(t, st, "downstream_links", "INSERT")
		if _, err := st.ReserveDownstreamLaunch(context.Background(), jobID, "acme/child", "main", "tok"); err == nil {
			t.Fatal("ReserveDownstreamLaunch over a blocked insert = nil error")
		}
	})
	t.Run("Migrate broken advisory lock", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(context.Background(), `DROP TABLE schema_migrations`); err != nil {
			t.Fatalf("drop schema_migrations: %v", err)
		}
		if err := st.Migrate(context.Background()); err == nil {
			t.Fatal("Migrate against a dropped schema_migrations = nil error")
		}
	})
}
