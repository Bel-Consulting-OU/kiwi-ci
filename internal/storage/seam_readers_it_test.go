package storage

// Integration coverage for the reader scan-failure branches: a schema-typed
// column that cannot scan into the destination proves every list reader
// surfaces the store error instead of returning partial results.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresIntegrationReaderScanFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("ListRuns", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBreakColumn(t, st, "runs", "created_at")
		if _, err := st.ListRuns(ctx, 10); err == nil {
			t.Fatal("ListRuns with a mistyped column returned rows")
		}
	})
	t.Run("ListArtifacts", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		if err := st.InsertArtifact(ctx, model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "bin", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToArray(t, st, "artifacts", "payload")
		if _, err := st.ListArtifacts(ctx, runID); err == nil {
			t.Fatal("ListArtifacts with a mistyped column returned rows")
		}
	})
	t.Run("ListTestReports", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		if err := st.InsertTestReport(ctx, model.TestReport{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToArray(t, st, "test_results", "payload")
		if _, err := st.ListTestReports(ctx, runID); err == nil {
			t.Fatal("ListTestReports with a mistyped column returned rows")
		}
	})
	t.Run("ReadLogs", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		if err := st.AppendLog(ctx, model.LogEntry{Seq: 1, RunID: runID, JobID: jobID, JobKey: "build", Step: "s", Line: "hello", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "log_entries", "created_at")
		if _, err := st.ReadLogs(ctx, runID, 0, 10); err == nil {
			t.Fatal("ReadLogs with a mistyped column returned rows")
		}
	})
	t.Run("ListDeploymentsByRun", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		if err := st.InsertDeployment(ctx, model.Deployment{ID: pgITNewID(t), RunID: runID, JobID: jobID, Environment: "prod", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToArray(t, st, "deployments", "payload")
		if _, err := st.ListDeploymentsByRun(ctx, runID); err == nil {
			t.Fatal("ListDeploymentsByRun with a mistyped column returned rows")
		}
	})
	t.Run("ListSnapshotsByRun", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		if err := st.InsertSnapshotRecord(ctx, model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToArray(t, st, "workspace_snapshots", "payload")
		if _, err := st.ListSnapshotsByRun(ctx, runID); err == nil {
			t.Fatal("ListSnapshotsByRun with a mistyped column returned rows")
		}
	})
	t.Run("LoadTestHistory/missing", func(t *testing.T) {
		st := pgITStore(t)
		version, stats, err := st.LoadTestHistory(ctx)
		if err != nil || version != 0 || stats != nil {
			t.Fatalf("empty test history = %d, %v, %v; want 0, nil, nil", version, stats, err)
		}
	})
}
