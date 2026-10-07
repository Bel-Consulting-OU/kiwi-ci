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
// index-backed early stop on the dedicated jobs_queued_traversal_idx
// (migration 0042) with no Sort or Incremental Sort — including when many
// rows share created_at with mixed queue_boost values, the case that made the
// old promotion-sweep index look correct only by incrementally sorting each
// timestamp group.

import (
	"context"
	"fmt"
	"strings"
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
// index-backed early stop on jobs_queued_traversal_idx: no sequential scan,
// no Sort/Incremental Sort anywhere, an index scan on that index, and at most
// 2048 actually examined rows for limit 256 (which excludes a full or
// incremental sort, since either would have to materialize the whole queued
// population first).
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
		// Unique created_at: every index order is then trivially compatible,
		// so this case isolates the index selection from tie handling (the
		// tied adversarial case is TestPostgresIntegrationQueuedJobsTraversalTiedTimestamps).
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
	if n, found := pgITFindNode(plan, func(n explainNode) bool {
		return strings.Contains(n.NodeType, "Sort")
	}); found {
		t.Fatalf("traversal plan contains a %s node; the creation order must come from %s with no sort\nplan: %+v",
			n.NodeType, queuedJobTraversalIndexName, plan)
	}
	scan, found := pgITFindNode(plan, func(n explainNode) bool {
		return (n.NodeType == "Index Scan" || n.NodeType == "Index Only Scan") && n.IndexName == queuedJobTraversalIndexName
	})
	if !found {
		t.Fatalf("traversal plan has no index scan on %s\nplan: %+v", queuedJobTraversalIndexName, plan)
	}
	if scan.ActualRows > 2048 {
		t.Fatalf("creation-order index scan examined %.0f rows, want <= 2048 (bounded early stop)", scan.ActualRows)
	}
	pgITWalkPlan(plan, func(n explainNode) {
		if n.RelationName == "jobs" && n.ActualRows > 2048 {
			t.Fatalf("scan node %q on jobs examined %.0f rows, want <= 2048 (bounded path)", n.NodeType, n.ActualRows)
		}
	})
}

// pgITPlanBuffers sums the shared-buffer touches of every plan node, the
// measure of how much of the table one traversal page physically reads.
func pgITPlanBuffers(plan explainNode) float64 {
	total := 0.0
	pgITWalkPlan(plan, func(n explainNode) {
		total += n.SharedHit + n.SharedRead
	})
	return total
}

// TestPostgresIntegrationQueuedJobsTraversalTiedTimestamps is the audit's
// exact false positive: 100k queued rows share created_at in groups of 100
// with MIXED queue_boost values inside each group. The old traversal reused
// jobs_queued_boost_sweep_idx (created_at, queue_boost, id); from that index
// the requested (created_at, id) order differs inside every tie group, so the
// plan could keep an index scan's bounded "loops/rows" while paying an
// Incremental Sort over each group — the early stop was not the index's. The
// dedicated jobs_queued_traversal_idx (created_at, id) WHERE status='queued'
// removes the sort entirely, and this test proves it with a production-query
// EXPLAIN (ANALYZE, BUFFERS) plus an exact keyset walk over the ties.
func TestPostgresIntegrationQueuedJobsTraversalTiedTimestamps(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{
		ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour),
	}})

	const groups = 1000
	const perGroup = 100
	base := now.Add(-2 * time.Hour)
	jobs := pgITBoostSeed(runID, groups*perGroup, now, func(i int, j *model.Job) {
		g, r := i/perGroup, i%perGroup
		j.CreatedAt = base.Add(time.Duration(g) * time.Second)
		// Mixed boosts inside the tie group: the promotion sweep index order
		// (created_at, queue_boost, id) interleaves the group, so streaming
		// (created_at, id) from it would need an Incremental Sort.
		j.QueueBoost = (r*7 + 3) % 11
		j.BoostKnown = true
	})
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)
	if _, err := st.pool.Exec(ctx, `ANALYZE jobs`); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	// 1. The production traversal query for limit 256 must be a plain index
	// scan on the dedicated traversal index: no Sort/Incremental Sort node
	// anywhere, bounded examined rows and buffers.
	query, args := queuedJobsTraversalQuery(QueuedJobFilter{}, nil, 256, now)
	plan := pgITExplain(t, st, query, args...)
	if n, found := pgITFindNode(plan, func(n explainNode) bool {
		return strings.Contains(n.NodeType, "Sort")
	}); found {
		t.Fatalf("tied traversal plan contains a %s node; (created_at, id) must stream from %s\nplan: %+v",
			n.NodeType, queuedJobTraversalIndexName, plan)
	}
	if n, found := pgITFindNode(plan, func(n explainNode) bool {
		return n.NodeType == "Seq Scan" || n.NodeType == "Parallel Seq Scan"
	}); found {
		t.Fatalf("tied traversal plan sequentially scans: %+v", n)
	}
	if n, found := pgITFindNode(plan, func(n explainNode) bool {
		return n.NodeType == "Index Scan" && n.IndexName == "jobs_queued_boost_sweep_idx"
	}); found {
		t.Fatalf("tied traversal plan uses the promotion sweep index instead of %s: %+v", queuedJobTraversalIndexName, n)
	}
	scan, found := pgITFindNode(plan, func(n explainNode) bool {
		return (n.NodeType == "Index Scan" || n.NodeType == "Index Only Scan") && n.IndexName == queuedJobTraversalIndexName
	})
	if !found {
		t.Fatalf("tied traversal plan has no index scan on %s\nplan: %+v", queuedJobTraversalIndexName, plan)
	}
	if scan.ActualRows > 2048 {
		t.Fatalf("tied traversal index scan examined %.0f rows, want <= 2048 (limit+1 bounded early stop)", scan.ActualRows)
	}
	if buffers := pgITPlanBuffers(plan); buffers > 256 {
		t.Fatalf("tied traversal plan touched %.0f buffers, want <= 256 (bounded by the page, not %d queued rows)", buffers, groups*perGroup)
	} else {
		t.Logf("tied traversal plan: rows=%.0f buffers=%.0f index=%s", scan.ActualRows, buffers, scan.IndexName)
	}

	// 2. Several keyset pages walk the ties in exact (created_at, id) order
	// with no duplicates and no gaps, even though each tie group mixes boosts.
	expected := make([]model.Job, len(jobs))
	copy(expected, jobs)
	sortQueuedJobsByCreation(expected)
	const pageSize = 100
	const pages = 8
	seen := make(map[string]bool, pageSize*pages)
	var after *QueuedJobTraversalCursor
	for page := 0; page < pages; page++ {
		got, err := st.ListQueuedJobsByCreation(ctx, QueuedJobFilter{}, after, pageSize, now)
		if err != nil {
			t.Fatalf("page %d: %v", page+1, err)
		}
		if len(got.Jobs) != pageSize {
			t.Fatalf("page %d returned %d jobs, want %d", page+1, len(got.Jobs), pageSize)
		}
		for i, j := range got.Jobs {
			want := expected[page*pageSize+i]
			if j.ID != want.ID || !j.CreatedAt.Equal(want.CreatedAt) {
				t.Fatalf("page %d row %d = (%s, %s), want (%s, %s)",
					page+1, i, j.ID, j.CreatedAt, want.ID, want.CreatedAt)
			}
			if seen[j.ID] {
				t.Fatalf("duplicate job %s in the tied walk", j.ID)
			}
			seen[j.ID] = true
		}
		last := got.Jobs[len(got.Jobs)-1]
		if got.Last.ID != last.ID || !got.Last.CreatedAt.Equal(last.CreatedAt) {
			t.Fatalf("page %d Last = %+v, want cursor of %s", page+1, got.Last, last.ID)
		}
		if !got.HasMore {
			t.Fatalf("page %d HasMore = false with %d queued rows behind it", page+1, len(expected)-len(seen))
		}
		cursor := got.Last
		after = &cursor
	}

	// 3. Memory parity on a small version of the same fixture: the first
	// 3000 tied rows walked through memStore must page identically to the
	// Postgres prefix (the same IDs, boundaries and HasMore).
	const parityRows = 3000
	mem := newMemStore()
	for i := 0; i < parityRows; i++ {
		if err := mem.InsertJob(ctx, jobs[i]); err != nil {
			t.Fatalf("mem seed %d: %v", i, err)
		}
	}
	var pgAfter, memAfter *QueuedJobTraversalCursor
	for page := 0; page < pages; page++ {
		pgPage, err := st.ListQueuedJobsByCreation(ctx, QueuedJobFilter{}, pgAfter, pageSize, now)
		if err != nil {
			t.Fatalf("parity pg page %d: %v", page+1, err)
		}
		memPage, err := mem.ListQueuedJobsByCreation(ctx, QueuedJobFilter{}, memAfter, pageSize, now)
		if err != nil {
			t.Fatalf("parity mem page %d: %v", page+1, err)
		}
		if len(pgPage.Jobs) != len(memPage.Jobs) || pgPage.HasMore != memPage.HasMore ||
			pgPage.Last.ID != memPage.Last.ID || !pgPage.Last.CreatedAt.Equal(memPage.Last.CreatedAt) {
			t.Fatalf("parity page %d differs: pg %d/%v/%+v mem %d/%v/%+v",
				page+1, len(pgPage.Jobs), pgPage.HasMore, pgPage.Last, len(memPage.Jobs), memPage.HasMore, memPage.Last)
		}
		for i := range pgPage.Jobs {
			if pgPage.Jobs[i].ID != memPage.Jobs[i].ID || !pgPage.Jobs[i].CreatedAt.Equal(memPage.Jobs[i].CreatedAt) {
				t.Fatalf("parity page %d row %d: pg %s mem %s", page+1, i, pgPage.Jobs[i].ID, memPage.Jobs[i].ID)
			}
		}
		cursor := pgPage.Last
		pgAfter = &cursor
		memCursor := memPage.Last
		memAfter = &memCursor
	}
}
