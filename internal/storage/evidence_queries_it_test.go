package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationAttemptScopedEvidenceQueries proves the indexed
// attempt-scoped reads return exactly the requested (job, generation)
// evidence with other jobs and generations present in the same run.
func TestPostgresIntegrationAttemptScopedEvidenceQueries(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobA := pgITNewID(t)
	jobB := pgITNewID(t)
	// One run with two jobs: the scoped reads must separate the jobs even
	// inside a single run.
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run: model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{
			jobA: pgITJobKeyed(runID, jobA, "build-a", pgITRepo),
			jobB: pgITJobKeyed(runID, jobB, "build-b", pgITRepo),
		},
	}); err != nil {
		t.Fatalf("enqueue run: %v", err)
	}
	now := time.Now().UTC()

	artifacts := []model.ArtifactRecord{
		{ID: pgITNewID(t), RunID: runID, JobID: jobA, JobKey: "a", Name: "bin", Size: 1, SHA256: strings.Repeat("1", 64), LeaseGeneration: 1, CreatedAt: now},
		{ID: pgITNewID(t), RunID: runID, JobID: jobA, JobKey: "a", Name: "bin", Size: 2, SHA256: strings.Repeat("2", 64), LeaseGeneration: 2, CreatedAt: now},
		{ID: pgITNewID(t), RunID: runID, JobID: jobB, JobKey: "b", Name: "bin", Size: 3, SHA256: strings.Repeat("3", 64), LeaseGeneration: 1, CreatedAt: now},
	}
	for _, a := range artifacts {
		if _, _, err := st.InsertArtifactOnce(ctx, a); err != nil {
			t.Fatalf("insert artifact %s: %v", a.ID, err)
		}
	}
	gotArts, err := st.ListArtifactsByJobGeneration(ctx, jobA, 1)
	if err != nil {
		t.Fatalf("scoped artifacts: %v", err)
	}
	if len(gotArts) != 1 || gotArts[0].ID != artifacts[0].ID {
		t.Fatalf("scoped artifacts = %+v, want exactly %s", gotArts, artifacts[0].ID)
	}

	reports := []model.TestReport{
		{ID: pgITNewID(t), RunID: runID, JobID: jobA, JobKey: "a", LeaseGeneration: 1, CreatedAt: now},
		{ID: pgITNewID(t), RunID: runID, JobID: jobA, JobKey: "a", LeaseGeneration: 2, CreatedAt: now},
		{ID: pgITNewID(t), RunID: runID, JobID: jobB, JobKey: "b", LeaseGeneration: 1, CreatedAt: now},
	}
	for _, rep := range reports {
		if err := st.InsertTestReport(ctx, rep); err != nil {
			t.Fatalf("insert report %s: %v", rep.ID, err)
		}
	}
	gotReports, err := st.ListTestReportsByJobGeneration(ctx, jobA, 1)
	if err != nil {
		t.Fatalf("scoped reports: %v", err)
	}
	if len(gotReports) != 1 || gotReports[0].ID != reports[0].ID {
		t.Fatalf("scoped reports = %+v, want exactly %s", gotReports, reports[0].ID)
	}

	snapshots := []model.SnapshotRecord{
		{ID: pgITNewID(t), RunID: runID, JobID: jobA, JobKey: "a", Phase: model.SnapshotPhasePreJob, SHA256: strings.Repeat("4", 64), RootSHA256: strings.Repeat("5", 64), LeaseGeneration: 1, CreatedAt: now},
		{ID: pgITNewID(t), RunID: runID, JobID: jobA, JobKey: "a", Phase: model.SnapshotPhasePostJob, SHA256: strings.Repeat("6", 64), RootSHA256: strings.Repeat("7", 64), LeaseGeneration: 2, CreatedAt: now},
		{ID: pgITNewID(t), RunID: runID, JobID: jobB, JobKey: "b", Phase: model.SnapshotPhasePostJob, SHA256: strings.Repeat("8", 64), RootSHA256: strings.Repeat("9", 64), LeaseGeneration: 1, CreatedAt: now},
	}
	for _, rec := range snapshots {
		if err := st.InsertSnapshotRecord(ctx, rec); err != nil {
			t.Fatalf("insert snapshot %s: %v", rec.ID, err)
		}
	}
	gotSnaps, err := st.ListSnapshotsByJobGeneration(ctx, jobA, 1)
	if err != nil {
		t.Fatalf("scoped snapshots: %v", err)
	}
	if len(gotSnaps) != 1 || gotSnaps[0].ID != snapshots[0].ID {
		t.Fatalf("scoped snapshots = %+v, want exactly %s", gotSnaps, snapshots[0].ID)
	}

	// A generation with no evidence is empty, and the run-scoped lists still
	// contain everything (the scoped query is a strict subset).
	if none, err := st.ListArtifactsByJobGeneration(ctx, jobA, 9); err != nil || len(none) != 0 {
		t.Fatalf("missing generation = %+v err=%v, want empty", none, err)
	}
	all, err := st.ListArtifacts(ctx, runID)
	if err != nil || len(all) != len(artifacts) {
		t.Fatalf("run-scoped artifacts = %d err=%v, want %d", len(all), err, len(artifacts))
	}
}
