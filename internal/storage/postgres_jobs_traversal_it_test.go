package storage

// Real-PostgreSQL integration tests for the immutable-creation-order traversal
// (QueuedJobTraversalStore). Gated on KIWI_TEST_POSTGRES_URL like the other
// integration tests: skipped when the variable is unset and in -short mode.
//
// The tests pin the properties the scheduler's round-robin sweep relies on:
// a walk over many pages returns every eligible queued job exactly once in
// creation order (created_at ASC, id ASC) regardless of priority or
// queue_boost, HasMore/Last are exact, the persisted queue_deadline pushdown
// excludes elapsed rows, memStore and Postgres agree, and the plan is an
// index-backed early stop on jobs_queued_boost_sweep_idx.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationQueuedJobsTraversalBoundedWalk walks the real queue
// in seven-row creation-order pages: every eligible job appears exactly once,
// the walk order equals the full creation sort (which deliberately disagrees
// with the aged order), boundaries are exact, and an elapsed persisted queue
// deadline is pushed out while a future one stays.
func TestPostgresIntegrationQueuedJobsTraversalBoundedWalk(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour)}})

	const total = 120
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)
	jobs := make([]model.Job, 0, total+2)
	for i := 0; i < total; i++ {
		jobs = append(jobs, model.Job{
			ID:     fmt.Sprintf("%032x", i+1),
			RunID:  runID,
			Key:    "build",
			Status: model.StatusQueued,
			// Priorities are inverse to age, so the aged order is the REVERSE
			// of the creation order and cannot accidentally satisfy this test.
			Priority:  10 - i%11,
			CreatedAt: now.Add(-time.Duration(i) * time.Minute),
		})
	}
	pastID := fmt.Sprintf("%032x", total+1)
	futureID := fmt.Sprintf("%032x", total+2)
	jobs = append(jobs,
		model.Job{ID: pastID, RunID: runID, Key: "build", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour), QueueDeadline: &past},
		model.Job{ID: futureID, RunID: runID, Key: "build", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour), QueueDeadline: &future},
	)
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)

	expectedJobs := make([]model.Job, 0, total+1)
	for _, j := range jobs {
		if j.ID == pastID {
			continue
		}
		expectedJobs = append(expectedJobs, j)
	}
	sortQueuedJobsByCreation(expectedJobs)
	expected := make([]string, 0, len(expectedJobs))
	for _, j := range expectedJobs {
		expected = append(expected, j.ID)
	}

	const pageSize = 7
	var seen []string
	var after *QueuedJobTraversalCursor
	pages := 0
	for {
		page, err := st.ListQueuedJobsByCreation(ctx, QueuedJobFilter{}, after, pageSize, now)
		if err != nil {
			t.Fatalf("page %d: %v", pages+1, err)
		}
		pages++
		wantLen := pageSize
		if remaining := len(expected) - len(seen); remaining < wantLen {
			wantLen = remaining
		}
		if len(page.Jobs) != wantLen {
			t.Fatalf("page %d returned %d jobs, want %d", pages, len(page.Jobs), wantLen)
		}
		for _, j := range page.Jobs {
			seen = append(seen, j.ID)
		}
		if page.HasMore != (len(seen) < len(expected)) {
			t.Fatalf("page %d HasMore = %v with %d/%d seen", pages, page.HasMore, len(seen), len(expected))
		}
		if len(page.Jobs) > 0 {
			last := page.Jobs[len(page.Jobs)-1]
			if page.Last.ID != last.ID || !page.Last.CreatedAt.Equal(last.CreatedAt) {
				t.Fatalf("page %d Last = %+v, want cursor of %s", pages, page.Last, last.ID)
			}
		}
		if !page.HasMore {
			break
		}
		cursor := page.Last
		after = &cursor
	}
	if pages != len(expected)/pageSize+1 {
		t.Fatalf("pages = %d, want %d", pages, len(expected)/pageSize+1)
	}
	for i, id := range seen {
		if id != expected[i] {
			t.Fatalf("walk[%d] = %s, want %s", i, id, expected[i])
		}
	}
	seenIDs := map[string]bool{}
	for _, id := range seen {
		if seenIDs[id] {
			t.Fatalf("duplicate job %s in the walk", id)
		}
		seenIDs[id] = true
	}
	if seenIDs[pastID] {
		t.Fatal("elapsed persisted deadline was returned as a traversal candidate")
	}
	if !seenIDs[futureID] {
		t.Fatal("future deadline candidate missing from the traversal walk")
	}
}

// TestPostgresIntegrationQueuedJobsTraversalMemoryParity runs the same seed
// and creation-order cursor walk against memStore and PostgresStore and
// requires identical page contents and boundaries.
func TestPostgresIntegrationQueuedJobsTraversalMemoryParity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour)}})

	const total = 25
	jobs := make([]model.Job, 0, total)
	for i := 0; i < total; i++ {
		jobs = append(jobs, model.Job{
			ID:        fmt.Sprintf("%032x", i+1),
			RunID:     runID,
			Key:       "build",
			Status:    model.StatusQueued,
			Priority:  i % 3,
			CreatedAt: now.Add(-time.Duration((i*7)%total) * 30 * time.Second),
		})
	}
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)
	mem := newMemStore()
	for _, j := range jobs {
		if err := mem.InsertJob(ctx, j); err != nil {
			t.Fatalf("mem seed: %v", err)
		}
	}
	var after *QueuedJobTraversalCursor
	for page := 1; ; page++ {
		pgPage, err := st.ListQueuedJobsByCreation(ctx, QueuedJobFilter{}, after, 4, now)
		if err != nil {
			t.Fatalf("pg page %d: %v", page, err)
		}
		memPage, err := mem.ListQueuedJobsByCreation(ctx, QueuedJobFilter{}, after, 4, now)
		if err != nil {
			t.Fatalf("mem page %d: %v", page, err)
		}
		lastEqual := pgPage.Last.ID == memPage.Last.ID && pgPage.Last.CreatedAt.Equal(memPage.Last.CreatedAt)
		if len(pgPage.Jobs) != len(memPage.Jobs) || pgPage.HasMore != memPage.HasMore || !lastEqual {
			t.Fatalf("page %d differs: pg %d/%v/%+v mem %d/%v/%+v",
				page, len(pgPage.Jobs), pgPage.HasMore, pgPage.Last, len(memPage.Jobs), memPage.HasMore, memPage.Last)
		}
		for i := range pgPage.Jobs {
			if pgPage.Jobs[i].ID != memPage.Jobs[i].ID {
				t.Fatalf("page %d row %d: pg %s mem %s", page, i, pgPage.Jobs[i].ID, memPage.Jobs[i].ID)
			}
		}
		if !pgPage.HasMore {
			break
		}
		cursor := pgPage.Last
		after = &cursor
	}
}

// TestPostgresIntegrationQueuedJobsTraversalExplain seeds ~20k queued rows
// with unique created_at values and proves the creation-order page is an
// index-backed early stop on jobs_queued_boost_sweep_idx: no sequential scan,
// an index scan on that index, and at most 2048 actually examined rows for
// limit 256 (which excludes both a full and an incremental sort, since either
// would have to materialize the whole queued population first).
func TestPostgresIntegrationQueuedJobsTraversalExplain(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{
		ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour),
	}})

	const total = 20000
	jobs := pgITBoostSeed(runID, total, now, func(i int, j *model.Job) {
		// Unique created_at: the (created_at, queue_boost, id) index order is
		// then exactly the requested (created_at, id) order.
		j.CreatedAt = now.Add(-time.Duration(i+1) * time.Second)
	})
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)
	if _, err := st.pool.Exec(ctx, `ANALYZE jobs`); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	query, args := queuedJobsTraversalQuery(QueuedJobFilter{}, nil, 256, now)
	plan := pgITExplain(t, st, query, args...)

	if n, found := pgITFindNode(plan, func(n explainNode) bool {
		return n.NodeType == "Seq Scan" || n.NodeType == "Parallel Seq Scan"
	}); found {
		t.Fatalf("traversal plan sequentially scans: %+v", n)
	}
	sweep, found := pgITFindNode(plan, func(n explainNode) bool {
		return (n.NodeType == "Index Scan" || n.NodeType == "Index Only Scan") && n.IndexName == "jobs_queued_boost_sweep_idx"
	})
	if !found {
		t.Fatalf("traversal plan has no index scan on jobs_queued_boost_sweep_idx\nplan: %+v", plan)
	}
	if sweep.ActualRows > 2048 {
		t.Fatalf("creation-order index scan examined %.0f rows, want <= 2048 (bounded early stop)", sweep.ActualRows)
	}
	pgITWalkPlan(plan, func(n explainNode) {
		if n.RelationName == "jobs" && n.ActualRows > 2048 {
			t.Fatalf("scan node %q on jobs examined %.0f rows, want <= 2048 (bounded path)", n.NodeType, n.ActualRows)
		}
	})
}
