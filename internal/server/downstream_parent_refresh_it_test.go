package server

// Real-PostgreSQL regression for the downstream parent-refresh scan
// (refreshDownstreamParentsDB): a wait=true parent must be re-aggregated when
// its child finishes even when MORE than 10,000 newer runs exist, i.e. the
// parent sits outside any ListRuns(10000) window. The old implementation
// enumerated the newest 10,000 runs and therefore never saw the parent —
// permanently stale. Gated on KIWI_TEST_POSTGRES_URL like the other
// integration tests in this package.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITRefreshRepo is the repository identity the seeded parent/child runs
// carry.
const pgITRefreshRepo = "https://example.com/o/r.git"

// pgITRefreshBulkExec runs one statement on the test schema through a
// separate connection (the bulk filler runs are not written through the
// store API, matching a busy installation's older history).
func pgITRefreshBulkExec(t *testing.T, env *pgITServerEnv, statement string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.base)
	if err != nil {
		t.Fatalf("bulk connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "SET search_path TO "+pgx.Identifier{env.schema}.Sanitize()); err != nil {
		t.Fatalf("bulk search_path: %v", err)
	}
	if _, err := conn.Exec(ctx, statement); err != nil {
		t.Fatalf("bulk exec: %v", err)
	}
}

// pgITRefreshSeedParent seeds one wait=true parent run whose own job already
// succeeded, with a downstream edge to every childRunID and a launched link
// per child (the durable reverse index the refresh resolves through).
func pgITRefreshSeedParent(t *testing.T, st *storage.PostgresStore, parentRun, parentJob string, childRunIDs ...string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	job := model.Job{
		ID: parentJob, RunID: parentRun, Key: "build", RepoURL: pgITRefreshRepo,
		RepoFullName: "o/r", Status: model.StatusSuccess, CreatedAt: now,
	}
	if err := st.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
		Run:  model.Run{ID: parentRun, Repo: pgITRefreshRepo, RepoFullName: "o/r", Status: model.StatusRunning, CreatedAt: now},
		Jobs: map[string]model.Job{parentJob: job},
	}); err != nil {
		t.Fatalf("seed parent %s: %v", parentRun, err)
	}
	for i, childRunID := range childRunIDs {
		if err := st.AppendDownstreamRun(ctx, parentRun, childRunID); err != nil {
			t.Fatalf("append child %s: %v", childRunID, err)
		}
		if err := st.InsertDownstreamLink(ctx, storage.DownstreamLink{
			ParentJobID: parentJob, TargetRepo: "acme/child-" + pgITServerRandomHex(t, 6), TargetRef: "refs/heads/main",
			LaunchToken: "tok", ChildRunID: childRunID, CreatedAt: now.Add(time.Duration(i) * time.Millisecond),
		}); err != nil {
			t.Fatalf("seed link for %s: %v", childRunID, err)
		}
	}
}

// pgITRefreshSeedChild seeds one child run/job in the given terminal or
// in-flight state.
func pgITRefreshSeedChild(t *testing.T, st *storage.PostgresStore, childRun, childJob string, status model.Status) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	job := model.Job{
		ID: childJob, RunID: childRun, Key: "build", RepoURL: pgITRefreshRepo,
		RepoFullName: "o/r", Status: status, CreatedAt: now,
	}
	if status.Terminal() {
		fin := now
		job.FinishedAt = &fin
	}
	if err := st.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
		Run:  model.Run{ID: childRun, Repo: pgITRefreshRepo, RepoFullName: "o/r", Status: status, CreatedAt: now},
		Jobs: map[string]model.Job{childJob: job},
	}); err != nil {
		t.Fatalf("seed child %s: %v", childRun, err)
	}
}

// TestPostgresIntegrationDownstreamParentRefreshBeyondListRunsWindow is the
// P1 regression: >10,000 later runs must not hide an old wait=true parent
// from the child-completion re-aggregation. It also covers multiple parents
// for one child and a parent with several children.
func TestPostgresIntegrationDownstreamParentRefreshBeyondListRunsWindow(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	ctx := context.Background()

	parentA, parentB, parentC := pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32)
	jobA, jobB, jobC := pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32)
	child, child2a, child2b := pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32)
	jobChild, jobChild2a, jobChild2b := pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32)

	// Two parents wait on the same child; a third parent waits on two
	// children, one of which is still in flight.
	pgITRefreshSeedParent(t, st, parentA, jobA, child)
	pgITRefreshSeedParent(t, st, parentB, jobB, child)
	pgITRefreshSeedParent(t, st, parentC, jobC, child2a, child2b)
	pgITRefreshSeedChild(t, st, child, jobChild, model.StatusFailure)
	pgITRefreshSeedChild(t, st, child2a, jobChild2a, model.StatusFailure)
	pgITRefreshSeedChild(t, st, child2b, jobChild2b, model.StatusRunning)

	// 10,100 runs created AFTER every seeded run: the old ListRuns(10000)
	// window contains only these, so none of the parents is enumerable.
	pgITRefreshBulkExec(t, env, `INSERT INTO runs (id, status, created_at, payload)
		SELECT md5('refresh-filler-'||i), 'success', now() + (i || ' seconds')::interval, '{}'::jsonb
		FROM generate_series(1, 10100) AS i`)

	runs, err := st.ListRuns(ctx, 10000)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 10000 {
		t.Fatalf("ListRuns window = %d runs; want the full 10000 cap", len(runs))
	}
	inWindow := map[string]bool{}
	for _, r := range runs {
		inWindow[r.ID] = true
	}
	for _, parentRun := range []string{parentA, parentB, parentC} {
		if inWindow[parentRun] {
			t.Fatalf("parent %s unexpectedly inside the 10k window; the regression setup is wrong", parentRun)
		}
	}

	// The child completion effect re-aggregates the child's run and every
	// parent that waits on it — exactly what a real completion runs.
	if err := s.effectRunAggregate(ctx, model.Job{ID: jobChild, RunID: child, Key: "build", Status: model.StatusFailure}); err != nil {
		t.Fatalf("effectRunAggregate(child) = %v", err)
	}
	for _, parentRun := range []string{parentA, parentB} {
		run, err := st.GetRun(ctx, parentRun)
		if err != nil {
			t.Fatalf("GetRun(%s): %v", parentRun, err)
		}
		if run.Status != model.StatusFailure || run.FinishedAt == nil {
			t.Fatalf("parent %s after child failure = %+v; want finalized failure (previously stale: outside the 10k window)", parentRun, run)
		}
	}
	// The multi-child parent stays open while child2b is in flight.
	runC, err := st.GetRun(ctx, parentC)
	if err != nil {
		t.Fatalf("GetRun(parentC): %v", err)
	}
	if runC.Status != model.StatusRunning || runC.FinishedAt != nil {
		t.Fatalf("parent with an in-flight child = %+v; want still running", runC)
	}

	// The last child finishing finalizes the multi-child parent too.
	fin := time.Now().UTC()
	if err := st.UpdateRunStatus(ctx, child2b, model.StatusFailure, nil, &fin); err != nil {
		t.Fatalf("UpdateRunStatus(child2b): %v", err)
	}
	if err := s.effectRunAggregate(ctx, model.Job{ID: jobChild2b, RunID: child2b, Key: "build", Status: model.StatusFailure}); err != nil {
		t.Fatalf("effectRunAggregate(child2b) = %v", err)
	}
	runC, err = st.GetRun(ctx, parentC)
	if err != nil {
		t.Fatalf("GetRun(parentC): %v", err)
	}
	if runC.Status != model.StatusFailure || runC.FinishedAt == nil {
		t.Fatalf("multi-child parent after last child = %+v; want finalized failure", runC)
	}
}
