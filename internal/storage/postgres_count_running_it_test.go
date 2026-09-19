package storage

// Real-PostgreSQL test for the S1B drain count: CountRunningJobs is one
// aggregate over the jobs table and must not depend on ListRuns pagination or
// per-run scans (the old drain walk used ListRuns(10000) plus per-run
// ListJobsByRun with silent skips, so a running job beyond the page or a
// failing read could be invisible). Gated on KIWI_TEST_POSTGRES_URL.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationCountRunningJobs proves the aggregate is correct,
// ignores non-running statuses, and still sees a running job whose run is
// older than every row a ListRuns(10000) page returns.
func TestPostgresIntegrationCountRunningJobs(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	if n, err := st.CountRunningJobs(ctx); err != nil || n != 0 {
		t.Fatalf("empty CountRunningJobs = %d, %v; want 0", n, err)
	}

	// More runs than the old 10000 ceiling, all newer and terminal, so a
	// paginated walk would look at them and skip every one.
	const bulkRuns = 10050
	if _, err := st.pool.Exec(ctx, `INSERT INTO runs (id, status, created_at, payload)
		SELECT 'zz-bulk-' || lpad(g::text, 6, '0'), 'success', now(), '{}'::jsonb
		FROM generate_series(1, $1) g`, bulkRuns); err != nil {
		t.Fatalf("bulk-seed %d runs: %v", bulkRuns, err)
	}
	// The only running job lives in the OLDEST run, outside any ListRuns
	// page the old drain walk consumed.
	oldRunID := pgITNewID(t)
	runningJobID := pgITNewID(t)
	created := time.Now().Add(-24 * time.Hour).UTC()
	if err := st.InsertRun(ctx, model.Run{ID: oldRunID, Status: model.StatusRunning, CreatedAt: created}); err != nil {
		t.Fatalf("insert old run: %v", err)
	}
	if err := st.InsertJob(ctx, model.Job{ID: runningJobID, RunID: oldRunID, Key: "build", RepoURL: pgITRepo, RepoFullName: "kiwi-it/repo", Status: model.StatusRunning, CreatedAt: created}); err != nil {
		t.Fatalf("insert running job: %v", err)
	}

	// Pin the premise: the running job's run is NOT inside the first page.
	runs, err := st.ListRuns(ctx, 10000)
	if err != nil {
		t.Fatalf("ListRuns(10000): %v", err)
	}
	for _, r := range runs {
		if r.ID == oldRunID {
			t.Fatalf("premise broken: running job's run is inside the ListRuns(10000) page")
		}
	}

	if n, err := st.CountRunningJobs(ctx); err != nil || n != 1 {
		t.Fatalf("CountRunningJobs with running job beyond the run page = %d, %v; want 1", n, err)
	}

	// Non-running statuses never count, even in the run that holds the
	// running job (no per-run/status filtering in the aggregate).
	if err := st.InsertJob(ctx, model.Job{ID: pgITNewID(t), RunID: oldRunID, Key: "done", RepoURL: pgITRepo, RepoFullName: "kiwi-it/repo", Status: model.StatusSuccess, CreatedAt: created}); err != nil {
		t.Fatalf("insert terminal job: %v", err)
	}
	if err := st.InsertJob(ctx, model.Job{ID: pgITNewID(t), RunID: oldRunID, Key: "waiting", RepoURL: pgITRepo, RepoFullName: "kiwi-it/repo", Status: model.StatusQueued, CreatedAt: created}); err != nil {
		t.Fatalf("insert queued job: %v", err)
	}
	if n, err := st.CountRunningJobs(ctx); err != nil || n != 1 {
		t.Fatalf("CountRunningJobs with terminal/queued jobs = %d, %v; want 1", n, err)
	}

	// A running job in a FRESH run is counted as well: the aggregate is
	// global, independent of run status and ordering.
	newRunID := pgITNewID(t)
	if err := st.InsertRun(ctx, model.Run{ID: newRunID, Status: model.StatusRunning, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("insert fresh run: %v", err)
	}
	if err := st.InsertJob(ctx, model.Job{ID: pgITNewID(t), RunID: newRunID, Key: "build", RepoURL: pgITRepo, RepoFullName: "kiwi-it/repo", Status: model.StatusRunning, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("insert fresh running job: %v", err)
	}
	if n, err := st.CountRunningJobs(ctx); err != nil || n != 2 {
		t.Fatalf("CountRunningJobs after a second running job = %d, %v; want 2", n, err)
	}
}
