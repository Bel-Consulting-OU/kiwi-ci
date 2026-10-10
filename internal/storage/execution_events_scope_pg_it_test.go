package storage

// PostgreSQL integration tests for the scope-correct execution event
// contract (closure gate): the migration/trigger repository dimension, the
// scoped read and per-scope retention frontier, and the repository-scoped
// execution snapshot. Gated on KIWI_TEST_POSTGRES_URL like the other pgIT
// tests.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const (
	pgITScopeRepoA = "github.com/kiwi-it/scope-repo-a"
	pgITScopeRepoB = "github.com/kiwi-it/scope-repo-b"
)

// TestPostgresIntegrationExecutionEventRepoDimension proves the migration
// 0056 repository dimension on real PostgreSQL: trigger-appended run and job
// events capture the owning run's payload repo_id, the manual
// AppendExecutionEvent path fills an empty repo from the run, and the
// repository-scoped read returns only that repository's events.
func TestPostgresIntegrationExecutionEventRepoDimension(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runA, runB := pgITNewID(t), pgITNewID(t)
	jobA, jobB := pgITNewID(t), pgITNewID(t)
	for _, seed := range []struct {
		runID, jobID, repoID string
	}{
		{runA, jobA, pgITScopeRepoA},
		{runB, jobB, pgITScopeRepoB},
	} {
		if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
			Run:  model.Run{ID: seed.runID, Repo: pgITRepo, RepoID: seed.repoID, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
			Jobs: map[string]model.Job{seed.jobID: pgITJob(seed.runID, seed.jobID, pgITRepo)},
		}); err != nil {
			t.Fatalf("seed %s: %v", seed.runID, err)
		}
	}
	// Trigger-appended events (run.queued from the runs insert, job.queued
	// from the jobs insert) must carry the run's repository.
	for _, tc := range []struct {
		runID, repoID string
	}{
		{runA, pgITScopeRepoA},
		{runB, pgITScopeRepoB},
	} {
		events := pgITExecutionEvents(t, st, tc.runID)
		if len(events) == 0 {
			t.Fatalf("run %s has no events", tc.runID)
		}
		sawJob := false
		for _, e := range events {
			if e.RepoID != tc.repoID {
				t.Fatalf("trigger event %s/%s repo = %q, want %q: %+v", e.Type, e.JobID, e.RepoID, tc.repoID, e)
			}
			if e.Type == "job.queued" {
				sawJob = true
			}
		}
		if !sawJob {
			t.Fatalf("run %s has no job.queued trigger event: %+v", tc.runID, events)
		}
	}

	// A manual append without a repo (the semantic-writer shape) is filled
	// from the owning run.
	if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: runA, JobID: jobA, Type: "semantic.a"}); err != nil {
		t.Fatal(err)
	}

	// The repository scopes are disjoint and exact.
	pageA, _, retainedA, _, err := st.ReadExecutionEventsRetention(ctx, 0, MaxExecutionEventLimit, ExecutionEventScope{Kind: ExecutionEventScopeRepo, RepoID: pgITScopeRepoA})
	if err != nil {
		t.Fatal(err)
	}
	if retainedA != 0 {
		t.Fatalf("repo A frontier = %d, want 0", retainedA)
	}
	sawSemantic := false
	for _, e := range pageA {
		if e.RepoID != pgITScopeRepoA {
			t.Fatalf("repo A read leaked %+v", e)
		}
		if e.Type == "semantic.a" {
			sawSemantic = true
		}
	}
	if !sawSemantic {
		t.Fatalf("repo A read omitted the manual semantic event: %+v", pageA)
	}
	pageB, _, _, _, err := st.ReadExecutionEventsRetention(ctx, 0, MaxExecutionEventLimit, ExecutionEventScope{Kind: ExecutionEventScopeRepo, RepoID: pgITScopeRepoB})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range pageB {
		if e.RepoID != pgITScopeRepoB {
			t.Fatalf("repo B read leaked %+v", e)
		}
	}
	if len(pageA)+len(pageB) == 0 {
		t.Fatal("no scoped events at all")
	}

	// The repository-scoped snapshot exposes only that repository's run and
	// jobs while through_sequence stays the global cursor.
	snapA, err := st.ExecutionSnapshot(ctx, DefaultExecutionSnapshotRuns, pgITScopeRepoA)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapA.Runs) != 1 || snapA.Runs[0].ID != runA || snapA.Runs[0].RepoID != pgITScopeRepoA {
		t.Fatalf("repo A snapshot runs = %+v", snapA.Runs)
	}
	if snapA.Queued != 1 {
		t.Fatalf("repo A snapshot queued = %d, want exactly its one job", snapA.Queued)
	}
	if global, err := st.ExecutionSnapshot(ctx, DefaultExecutionSnapshotRuns, ""); err != nil || global.Cursor != snapA.Cursor {
		t.Fatalf("global snapshot cursor = %d err %v, want the same cursor %d", global.Cursor, err, snapA.Cursor)
	}
}

// TestPostgresIntegrationExecutionEventScopedRetentionFrontier proves the
// execution_event_pruned frontier on real PostgreSQL through the real prefix
// prune: a global prune that removed only repository B's (older) events
// advances the global retained_from past a repository A cursor while leaving
// A's scoped frontier at 0, so the scoped resume decision is resume_ok for A
// and expired for B.
func TestPostgresIntegrationExecutionEventScopedRetentionFrontier(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	for i := 0; i < 3; i++ {
		if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{
			RunID: "run-b", RepoID: pgITScopeRepoB, Type: "job.queued", CreatedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
	}
	var aSeqs []int64
	for i := 0; i < 3; i++ {
		if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{
			RunID: "run-a", RepoID: pgITScopeRepoA, Type: "job.queued", CreatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	eventsA, _, _, _, err := st.ReadExecutionEventsRetention(ctx, 0, 100, ExecutionEventScope{Kind: ExecutionEventScopeRepo, RepoID: pgITScopeRepoA})
	if err != nil || len(eventsA) != 3 {
		t.Fatalf("repo A seed read = %d err %v, want 3", len(eventsA), err)
	}
	for _, e := range eventsA {
		aSeqs = append(aSeqs, e.Seq)
	}

	pruned, globalRetained, err := st.PruneExecutionEvents(ctx, now.Add(-24*time.Hour), 100)
	if err != nil || pruned != 3 || globalRetained != aSeqs[0]-1 {
		t.Fatalf("prune = %d/%d err %v, want 3/%d (only repo B)", pruned, globalRetained, err, aSeqs[0]-1)
	}
	// The global watermark now passes a cursor below the repo A block.
	if globalRetained <= 0 || globalRetained >= aSeqs[0] {
		t.Fatalf("global watermark %d not inside the repo B block (A starts at %d)", globalRetained, aSeqs[0])
	}
	scopeA := ExecutionEventScope{Kind: ExecutionEventScopeRepo, RepoID: pgITScopeRepoA}
	scopeB := ExecutionEventScope{Kind: ExecutionEventScopeRepo, RepoID: pgITScopeRepoB}
	if got, err := st.ScopedRetainedFrom(ctx, scopeA); err != nil || got != 0 {
		t.Fatalf("repo A frontier = %d err %v, want 0", got, err)
	}
	if got, err := st.ScopedRetainedFrom(ctx, scopeB); err != nil || got != globalRetained {
		t.Fatalf("repo B frontier = %d err %v, want %d", got, err, globalRetained)
	}
	if got, err := st.ScopedRetainedFrom(ctx, ExecutionEventScope{Kind: ExecutionEventScopeRun, RepoID: pgITScopeRepoB, RunID: "run-b"}); err != nil || got != globalRetained {
		t.Fatalf("run B frontier = %d err %v, want %d", got, err, globalRetained)
	}
	// Repo A resumes just above its own cursor: resume_ok, survivors intact.
	page, cursor, retained, _, err := st.ReadExecutionEventsRetention(ctx, aSeqs[0]-1, 100, scopeA)
	if err != nil || retained != 0 || len(page) != 3 || page[0].Seq != aSeqs[0] || cursor != aSeqs[2] {
		t.Fatalf("repo A resume = %d events cursor %d retained %d err %v", len(page), cursor, retained, err)
	}
	if ExecutionEventCursorExpired(aSeqs[0]-1, retained) {
		t.Fatal("repo A cursor expired by the repo B prune")
	}
	// Repo B's cursor below its own frontier is expired.
	pageB, _, retainedB, _, err := st.ReadExecutionEventsRetention(ctx, 0, 100, scopeB)
	if err != nil || retainedB != globalRetained || len(pageB) != 0 {
		t.Fatalf("repo B read = %d events retained %d err %v", len(pageB), retainedB, err)
	}
	if !ExecutionEventCursorExpired(globalRetained-1, retainedB) {
		t.Fatalf("repo B cursor below frontier %d not expired", retainedB)
	}
}
