package storage

// Real-PostgreSQL integration tests for the materialized queued scheduling
// key (jobs.queue_boost), the bounded PromoteQueuedJobBoosts sweep and the
// runner-coarse QueuedJobFilter pushdown. Gated on KIWI_TEST_POSTGRES_URL like
// the other integration tests. Run these individually (they are not part of
// the whole Integration lane), e.g.:
//
//	KIWI_TEST_POSTGRES_URL=... go test ./internal/storage -run TestPostgresIntegrationQueuedBoost -count=1
//
// The EXPLAIN tests pin the plan properties the page walk relies on: the
// exact aged ORDER BY is served by jobs_queued_aged_idx (no Sort node) and a
// selective runtime filter is served by jobs_queued_runtime_idx with a
// bounded number of examined rows. The label containment predicate
// (required_labels <@ runnerLabels) is applied as a recheck FILTER because
// the built-in jsonb GIN opclass (jsonb_ops) implements @>/??/?&/?| but NOT
// the <@ containment strategy, so the jobs_queued_labels_idx GIN index cannot
// serve it (documented here precisely).

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITBoostSeed builds n queued jobs with deterministic ages: job i waits i
// seconds, so its promoted boost is floor(i/600). The eligible/label knobs are
// applied by the caller through mutate.
func pgITBoostSeed(runID string, n int, now time.Time, mutate func(i int, j *model.Job)) []model.Job {
	jobs := make([]model.Job, 0, n)
	for i := 0; i < n; i++ {
		j := model.Job{
			ID:        fmt.Sprintf("%032x", i+1),
			RunID:     runID,
			Key:       "build",
			Status:    model.StatusQueued,
			CreatedAt: now.Add(-time.Duration(i+1) * time.Second),
			Priority:  i % 4,
		}
		if mutate != nil {
			mutate(i, &j)
		}
		jobs = append(jobs, j)
	}
	return jobs
}

func pgITRuntimePayload(runtime string) *model.CompiledJobPayload {
	return &model.CompiledJobPayload{
		SchemaVersion: 1,
		EffectiveJob:  json.RawMessage(`{"job":{"runtime":"` + runtime + `"}}`),
	}
}

// TestPostgresIntegrationQueuedBoostPromotion pins PromoteQueuedJobBoosts:
// stale queued rows are promoted to floor(age/600), the recomputation is
// idempotent, non-queued rows are untouched and the batch limit bounds one
// call.
func TestPostgresIntegrationQueuedBoostPromotion(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{
		ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour),
	}})

	type seed struct {
		age    time.Duration
		boost  int
		status model.Status
	}
	seeds := []seed{
		{5 * time.Minute, 0, model.StatusQueued},    // still in its first bucket
		{15 * time.Minute, 1, model.StatusQueued},   // 1
		{25 * time.Minute, 2, model.StatusQueued},   // 2
		{65 * time.Minute, 6, model.StatusQueued},   // 6
		{601 * time.Minute, 60, model.StatusQueued}, // 60
		{65 * time.Minute, 6, model.StatusRunning},  // not a queued candidate
	}
	jobs := make([]model.Job, 0, len(seeds))
	for i, s := range seeds {
		jobs = append(jobs, model.Job{
			ID: fmt.Sprintf("%032x", i+1), RunID: runID, Key: "build",
			Status: model.StatusQueued, CreatedAt: now.Add(-s.age),
		})
	}
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)
	// The promotion test needs explicit stale zeros on every seeded row.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET queue_boost = 0 WHERE run_id=$1`, runID); err != nil {
		t.Fatalf("zero boosts: %v", err)
	}
	for i, s := range seeds {
		if s.status == model.StatusRunning {
			if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='running' WHERE id=$1`, jobs[i].ID); err != nil {
				t.Fatalf("mark running: %v", err)
			}
		}
	}

	promoted, err := st.PromoteQueuedJobBoosts(ctx, now, 100)
	if err != nil {
		t.Fatalf("PromoteQueuedJobBoosts: %v", err)
	}
	// Four queued rows have a non-zero computed boost; the 5-minute row keeps
	// 0 (already correct) and the running row is never touched.
	if promoted != 4 {
		t.Fatalf("promoted = %d, want 4", promoted)
	}
	for i, s := range seeds {
		var got int
		if err := st.pool.QueryRow(ctx, `SELECT queue_boost FROM jobs WHERE id=$1`, jobs[i].ID).Scan(&got); err != nil {
			t.Fatalf("read boost %d: %v", i, err)
		}
		if s.status == model.StatusRunning {
			if got != 0 {
				t.Fatalf("running row boost = %d, want untouched 0", got)
			}
			continue
		}
		if got != s.boost {
			t.Fatalf("job %s (age %s) boost = %d, want %d", jobs[i].ID, s.age, got, s.boost)
		}
	}

	// Idempotent: nothing is stale anymore.
	if again, err := st.PromoteQueuedJobBoosts(ctx, now, 100); err != nil || again != 0 {
		t.Fatalf("second call = %d, %v; want 0, nil", again, err)
	}

	// Batch limit: reset the four promoted rows and require the calls to
	// consume the stale set in bounded batches.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET queue_boost = 0 WHERE run_id=$1 AND status='queued'`, runID); err != nil {
		t.Fatalf("reset boosts: %v", err)
	}
	var promotedTotal int64
	for _, want := range []int64{2, 2, 0, 0} {
		n, err := st.PromoteQueuedJobBoosts(ctx, now, 2)
		if err != nil {
			t.Fatalf("batched promote: %v", err)
		}
		if n != want {
			t.Fatalf("batched promote = %d, want %d", n, want)
		}
		promotedTotal += n
	}
	if promotedTotal != 4 {
		t.Fatalf("batched total = %d, want 4", promotedTotal)
	}
}

// explainNode is the subset of an EXPLAIN (FORMAT JSON) plan node the tests
// assert on (recursively flattened).
type explainNode struct {
	NodeType     string        `json:"Node Type"`
	RelationName string        `json:"Relation Name"`
	IndexName    string        `json:"Index Name"`
	ActualRows   float64       `json:"Actual Rows"`
	ActualLoops  float64       `json:"Actual Loops"`
	Plans        []explainNode `json:"Plans"`
}

type explainRoot struct {
	Plan explainNode `json:"Plan"`
}

func pgITExplain(t *testing.T, st *PostgresStore, query string, args ...any) explainNode {
	t.Helper()
	var raw []byte
	if err := st.pool.QueryRow(context.Background(), `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+query, args...).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	var roots []explainRoot
	if err := json.Unmarshal(raw, &roots); err != nil {
		t.Fatalf("decode EXPLAIN JSON: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("EXPLAIN returned %d plans, want 1", len(roots))
	}
	return roots[0].Plan
}

func pgITWalkPlan(n explainNode, fn func(explainNode)) {
	fn(n)
	for _, child := range n.Plans {
		pgITWalkPlan(child, fn)
	}
}

func pgITFindNode(n explainNode, pred func(explainNode) bool) (explainNode, bool) {
	if pred(n) {
		return n, true
	}
	for _, child := range n.Plans {
		if got, ok := pgITFindNode(child, pred); ok {
			return got, true
		}
	}
	return explainNode{}, false
}

// TestPostgresIntegrationQueuedJobsPageUnfilteredExplain seeds ~50k queued
// rows and proves the unfiltered page query is an index-only-order early stop:
// no Sort/Incremental Sort node anywhere, an Index Scan on jobs_queued_aged_idx,
// and at most 2048 actually examined index rows for limit 256.
func TestPostgresIntegrationQueuedJobsPageUnfilteredExplain(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{
		ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour),
	}})

	const total = 50000
	jobs := pgITBoostSeed(runID, total, now, func(i int, j *model.Job) {
		j.CompiledJobPayload = pgITRuntimePayload("native")
		j.RequiredLabels = []string{"linux"}
	})
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)
	if _, err := st.pool.Exec(ctx, `ANALYZE jobs`); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	query, args := queuedJobsPageQuery(QueuedJobFilter{}, nil, 256, now)
	plan := pgITExplain(t, st, query, args...)

	if n, found := pgITFindNode(plan, func(n explainNode) bool { return strings.Contains(n.NodeType, "Sort") }); found {
		t.Fatalf("unfiltered plan contains a %s node; the aged order must come from jobs_queued_aged_idx\nplan: %+v", n.NodeType, plan)
	}
	scan, found := pgITFindNode(plan, func(n explainNode) bool {
		return n.NodeType == "Index Scan" && n.IndexName == "jobs_queued_aged_idx"
	})
	if !found {
		t.Fatalf("unfiltered plan has no Index Scan on jobs_queued_aged_idx\nplan: %+v", plan)
	}
	if scan.ActualRows > 2048 {
		t.Fatalf("aged index scan examined %.0f rows, want <= 2048 (bounded early stop)", scan.ActualRows)
	}
}

// TestPostgresIntegrationQueuedJobsPageFilteredExplain seeds 4096
// label-ineligible (and runtime-container) rows plus ONE eligible
// runtime-native/label-linux row and pins the bounded filtered path: the
// selective runtime expression index serves the query, no node sequentially
// scans jobs, every scan on jobs examines at most 2048 rows, and the page
// returns exactly the eligible row.
//
// Precise limitation (asserted, not hidden): the label clause
// (required_labels IS NULL OR required_labels <@ runnerLabels) is applied as
// an index FILTER because jsonb_ops GIN has no <@ strategy. The bounded path
// asserted here is therefore jobs_queued_runtime_idx; the labels GIN index is
// left for operators that CAN use it (@>, ??, ?&, ?|).
func TestPostgresIntegrationQueuedJobsPageFilteredExplain(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{
		ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour),
	}})

	const ineligible = 4096
	const eligibleID = "00000000000000000000000000001001" // the 4097th seed
	jobs := pgITBoostSeed(runID, ineligible+1, now, func(i int, j *model.Job) {
		if j.ID == eligibleID {
			j.CompiledJobPayload = pgITRuntimePayload("native")
			j.RequiredLabels = []string{"linux"}
			return
		}
		j.CompiledJobPayload = pgITRuntimePayload("container")
		j.RequiredLabels = []string{"gpu"}
	})
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)
	if _, err := st.pool.Exec(ctx, `ANALYZE jobs`); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	filter := QueuedJobFilter{Runtimes: []string{"native"}, RunnerLabels: []string{"linux"}}
	query, args := queuedJobsPageQuery(filter, nil, 256, now)
	plan := pgITExplain(t, st, query, args...)

	if n, found := pgITFindNode(plan, func(n explainNode) bool {
		return (n.NodeType == "Seq Scan" || n.NodeType == "Parallel Seq Scan") && n.RelationName == "jobs"
	}); found {
		t.Fatalf("filtered plan sequentially scans jobs (%s); the selective runtime index must serve it\nplan: %+v", n.NodeType, plan)
	}
	runtimeScan := false
	pgITWalkPlan(plan, func(n explainNode) {
		if n.IndexName == "jobs_queued_runtime_idx" {
			runtimeScan = true
		}
		if n.RelationName == "jobs" && n.ActualRows > 2048 {
			t.Fatalf("scan node %q on jobs examined %.0f rows, want <= 2048 (bounded path)", n.NodeType, n.ActualRows)
		}
	})
	if !runtimeScan {
		t.Fatalf("filtered plan does not use jobs_queued_runtime_idx\nplan: %+v", plan)
	}

	page, err := st.ListQueuedJobsPage(ctx, filter, nil, 256, now)
	if err != nil {
		t.Fatalf("ListQueuedJobsPage(filtered): %v", err)
	}
	if len(page.Jobs) != 1 || page.Jobs[0].ID != eligibleID {
		got := make([]string, 0, len(page.Jobs))
		for _, j := range page.Jobs {
			got = append(got, j.ID)
		}
		t.Fatalf("filtered page = %v, want exactly [%s]", got, eligibleID)
	}
}

// TestPostgresIntegrationQueuedJobsPageRuntimeFilter verifies the runtime
// pushdown over a mixed queue: only matching rows (including legacy
// payload-less rows, which are native) are returned, and a selective runtime
// page is bounded.
func TestPostgresIntegrationQueuedJobsPageRuntimeFilter(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{
		ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour),
	}})

	jobs := pgITBoostSeed(runID, 10, now, nil)
	byID := map[string]*model.Job{}
	for i := range jobs {
		byID[jobs[i].ID] = &jobs[i]
	}
	// IDs 1-4: container, 5-7: native, 8-9: legacy payload (native), 10: running.
	// ID 1 carries placement region "us", ID 5 carries "eu"; the rest carry no
	// placement list (the empty-region rule must include them).
	for i := 0; i < 10; i++ {
		j := byID[fmt.Sprintf("%032x", i+1)]
		switch i {
		case 0, 1, 2, 3:
			j.CompiledJobPayload = pgITRuntimePayload("container")
		case 4, 5, 6:
			j.CompiledJobPayload = pgITRuntimePayload("native")
		case 9:
			j.Status = model.StatusRunning
		}
	}
	byID[fmt.Sprintf("%032x", 1)].PlacementRegions = []string{"us"}
	byID[fmt.Sprintf("%032x", 5)].PlacementRegions = []string{"eu"}
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)
	// The helper always inserts queued rows; flip the last one to running.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='running' WHERE id=$1`, fmt.Sprintf("%032x", 10)); err != nil {
		t.Fatalf("mark running: %v", err)
	}

	native, err := st.ListQueuedJobsPage(ctx, QueuedJobFilter{Runtimes: []string{"native"}}, nil, 100, now)
	if err != nil {
		t.Fatalf("native page: %v", err)
	}
	got := map[string]bool{}
	for _, j := range native.Jobs {
		got[j.ID] = true
	}
	for _, want := range []string{fmt.Sprintf("%032x", 6), fmt.Sprintf("%032x", 7), fmt.Sprintf("%032x", 8), fmt.Sprintf("%032x", 9)} {
		if !got[want] {
			t.Fatalf("native page %v missing %s", got, want)
		}
	}
	// ID 5 is native but carries the "eu" placement list, and the empty
	// RunnerRegion rule admits only region-less jobs; container and running
	// rows are excluded too.
	if len(got) != 4 {
		t.Fatalf("native page has %d rows, want 4 (container, running and placed excluded): %v", len(got), got)
	}

	container, err := st.ListQueuedJobsPage(ctx, QueuedJobFilter{Runtimes: []string{"container"}}, nil, 100, now)
	if err != nil {
		t.Fatalf("container page: %v", err)
	}
	// ID 1 is container but placed in "us", so the empty-region rule drops it.
	if len(container.Jobs) != 3 {
		t.Fatalf("container page has %d rows, want 3", len(container.Jobs))
	}
	for _, j := range container.Jobs {
		if j.CompiledJobPayload == nil {
			t.Fatalf("container page contains a legacy row %s", j.ID)
		}
	}

	// Region pushdown exercises the ?| branch: "eu" admits the region-less
	// jobs plus ID 5 and excludes the "us" job.
	eu, err := st.ListQueuedJobsPage(ctx, QueuedJobFilter{RunnerRegion: "eu"}, nil, 100, now)
	if err != nil {
		t.Fatalf("eu page: %v", err)
	}
	euIDs := map[string]bool{}
	for _, j := range eu.Jobs {
		euIDs[j.ID] = true
	}
	if !euIDs[fmt.Sprintf("%032x", 5)] || euIDs[fmt.Sprintf("%032x", 1)] {
		t.Fatalf("eu page = %v, want region-less + eu, without the us job", euIDs)
	}
	if len(euIDs) != 8 { // 9 queued rows, minus the "us" job
		t.Fatalf("eu page has %d rows, want 8: %v", len(euIDs), euIDs)
	}
	us, err := st.ListQueuedJobsPage(ctx, QueuedJobFilter{RunnerRegion: "us"}, nil, 100, now)
	if err != nil {
		t.Fatalf("us page: %v", err)
	}
	usIDs := map[string]bool{}
	for _, j := range us.Jobs {
		usIDs[j.ID] = true
	}
	if !usIDs[fmt.Sprintf("%032x", 1)] || usIDs[fmt.Sprintf("%032x", 5)] {
		t.Fatalf("us page = %v, want region-less + us, without the eu job", usIDs)
	}
}
