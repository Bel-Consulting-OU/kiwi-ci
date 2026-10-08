package storage

// Real-PostgreSQL planner regression matrix for the bounded queued page
// query (release blocker D). The production queuedJobsPageQuery is planned
// and executed against a seeded queue for every common/rare filter
// permutation; each plan must be index-driven, must not sequentially scan
// jobs, and its heap/buffer work must stay bounded by the indexed match set
// instead of by the queued population.
//
// Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here. Run the
// default matrix alone (never the whole Integration lane) with:
//
//	KIWI_TEST_POSTGRES_URL='postgres://postgres:postgres@127.0.0.1:5433/kiwi_it?sslmode=disable' \
//	  go test ./internal/storage -run TestPostgresIntegrationQueuedJobsPagePlannerMatrix -count=1 -v
//
// The 1m-scale run is opt-in because seeding a million rows (and shrinking it
// by status flips) is not something CI should pay for by default:
//
//	KIWI_TEST_PLANNER_SCALE=1m KIWI_TEST_POSTGRES_URL=... \
//	  go test ./internal/storage -run TestPostgresIntegrationQueuedJobsPagePlannerMatrix -count=1 -v
//
// The Seed: one queue whose first 400 rows carry the rare values and whose
// remainder is the common bulk. Permutation filters:
//
//	a) runtime common / labels rare           (100 linux-x64 among "other")
//	b) runtime common / region rare           (100 eu-west among "global")
//	c) runtime common / CPU rare              (100 cpu=1 among cpu=8, cap 2)
//	d) labels common / memory rare            (100 mem=256 among 4096, cap 2048)
//	e) all filters common                     (all but the region/label outliers)
//	f) zero matches                           (absent label key)
//	f2) zero matches on a resource            (memory cap below every request)
//	g) job-scoped cgroup CPU rare             (IgnoreServiceEnvelope own request)
//
// The 10k/100k/1m sizes are derived from ONE seed by flipping id > size to
// 'cancelled' and re-analyzing, so the rare sets are always inside the first
// 10k rows and every size keeps the same shape.

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITPlannerCase is one permutation and its expected eligible count at a
// given queue size. wantIndex, when set, additionally pins the index that
// must serve the plan (used where the SQL expression makes the choice
// unambiguous).
type pgITPlannerCase struct {
	name      string
	filter    QueuedJobFilter
	expected  func(size int) int
	zero      bool
	wantIndex string
}

// pgITPlannerRange counts the seeded rows with 0-based index in [lo, hi)
// that are present at the given queue size.
func pgITPlannerRange(size, lo, hi int) int {
	if size <= lo {
		return 0
	}
	if size < hi {
		return size - lo
	}
	return hi - lo
}

func pgITPlannerCases() []pgITPlannerCase {
	return []pgITPlannerCase{
		{
			// runtime common (every row native), labels rare: only the first
			// 100 rows carry linux-x64, and their region is the common
			// "global" one, so the label dimension is the only rare filter.
			name: "a_runtime_common_labels_rare",
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"linux-x64"},
				RunnerRegion: "global",
			},
			expected:  func(size int) int { return pgITPlannerRange(size, 0, 100) },
			wantIndex: "jobs_queued_labels_arr_idx",
		},
		{
			// runtime common, region rare: labels are the common "other"
			// value, only 100 rows carry eu-west.
			name: "b_runtime_common_region_rare",
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"other"},
				RunnerRegion: "eu-west",
			},
			expected:  func(size int) int { return pgITPlannerRange(size, 100, 200) },
			wantIndex: "jobs_queued_regions_arr_idx",
		},
		{
			// runtime common, CPU rare: cap 2 admits only the 100 rows with
			// cpu_request=1 while the bulk requests 8.
			name: "c_runtime_common_cpu_rare",
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"other"},
				RunnerRegion: "global",
				MaxRequested: model.ResourceCapacity{CPU: 2},
			},
			expected:  func(size int) int { return pgITPlannerRange(size, 200, 300) },
			wantIndex: "jobs_queued_cpu_idx",
		},
		{
			// labels common (the bulk is "other"), memory rare: cap 2048
			// admits only the 100 rows with memory_request=256.
			name: "d_labels_common_memory_rare",
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"other"},
				RunnerRegion: "global",
				MaxRequested: model.ResourceCapacity{Memory: 2048},
			},
			expected:  func(size int) int { return pgITPlannerRange(size, 300, 400) },
			wantIndex: "jobs_queued_memory_idx",
		},
		{
			// every dimension admits its bulk value: only the region outliers
			// (100..200) and the label outliers (0..100) are excluded.
			name: "e_all_filters_common",
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"other"},
				RunnerRegion: "global",
				MaxRequested: model.ResourceCapacity{CPU: 8, Memory: 4096},
			},
			expected: func(size int) int { return pgITPlannerRange(size, 200, size) },
		},
		{
			// no seeded job requires the absent label, so the label GIN arm
			// is empty; the plan must stay index-driven and bounded.
			name: "f_zero_matches",
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"absent-label"},
				RunnerRegion: "global",
			},
			expected: func(size int) int { return 0 },
			zero:     true,
		},
		{
			// zero match on a RESOURCE dimension: labels/region/runtime are
			// common, but no row requests less than 256 memory, so cap 1
			// matches nothing and the memory index must prove it without
			// examining the queue.
			name: "f2_zero_matches_resource",
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"other"},
				RunnerRegion: "global",
				MaxRequested: model.ResourceCapacity{Memory: 1},
			},
			expected:  func(size int) int { return 0 },
			zero:      true,
			wantIndex: "jobs_queued_memory_idx",
		},
		{
			// job-scoped cgroup runner: the resource predicate is the JOB's
			// own request (IgnoreServiceEnvelope), served by the _own
			// expression index, so a rare CPU capacity stays bounded without
			// the service-envelope sum.
			name: "g_ignore_envelope_cpu_rare",
			filter: QueuedJobFilter{
				Runtimes:              []string{"native"},
				RunnerLabels:          []string{"other"},
				RunnerRegion:          "global",
				MaxRequested:          model.ResourceCapacity{CPU: 2},
				IgnoreServiceEnvelope: true,
			},
			expected:  func(size int) int { return pgITPlannerRange(size, 200, 300) },
			wantIndex: "jobs_queued_cpu_own_idx",
		},
	}
}

// pgITPlannerSeedGo seeds the matrix queue through the existing bulk-insert
// helper (the same single INSERT ... unnest statement the other page tests
// use). The rows are compact: one native runtime payload, one label/region
// per row and the four request values the permutations switch on.
func pgITPlannerSeedGo(t *testing.T, st *PostgresStore, runID string, n int, now time.Time) {
	t.Helper()
	native := pgITRuntimePayload("native")
	linux := []string{"linux-x64"}
	other := []string{"other"}
	global := []string{"global"}
	euWest := []string{"eu-west"}
	jobs := make([]model.Job, 0, n)
	for i := 0; i < n; i++ {
		j := model.Job{
			ID:                 fmt.Sprintf("%032x", i+1),
			RunID:              runID,
			Key:                fmt.Sprintf("build-%d", i+1),
			Status:             model.StatusQueued,
			CreatedAt:          now.Add(-time.Duration(i+1) * time.Second),
			Priority:           i % 4,
			CompiledJobPayload: native,
			CPURequest:         8,
			MemoryRequest:      4096,
		}
		switch {
		case i < 100:
			j.RequiredLabels = linux
			j.PlacementRegions = global
		case i < 200:
			j.RequiredLabels = other
			j.PlacementRegions = euWest
		default:
			j.RequiredLabels = other
			j.PlacementRegions = global
		}
		if i >= 200 && i < 300 {
			j.CPURequest = 1
		}
		if i >= 300 && i < 400 {
			j.MemoryRequest = 256
		}
		jobs = append(jobs, j)
	}
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)
}

// pgITPlannerSeedSQL is the compact SQL mirror of pgITPlannerSeedGo for the
// gated 1m scale, where materializing a million model.Job values would cost
// more memory than the plan assertions are worth. It writes exactly the same
// rows: same ids, ages, priorities, boosts, labels, regions and requests.
func pgITPlannerSeedSQL(t *testing.T, st *PostgresStore, runID string, n int, now time.Time) {
	t.Helper()
	_, err := st.pool.Exec(context.Background(), `
		INSERT INTO jobs (id, run_id, key, status, dependency_status, priority, queue_boost, attempts, created_at, required_labels, placement_regions, payload)
		SELECT lpad(to_hex(i), 32, '0'), $1, 'build-' || i, 'queued', 'success', (i - 1) % 4, i / 600, 0,
		       $2::timestamptz - (i * interval '1 second'),
		       CASE WHEN i <= 100 THEN ARRAY['linux-x64']::text[] ELSE ARRAY['other']::text[] END,
		       CASE WHEN i > 100 AND i <= 200 THEN ARRAY['eu-west']::text[] ELSE ARRAY['global']::text[] END,
		       jsonb_build_object(
		           'required_labels', CASE WHEN i <= 100 THEN '["linux-x64"]'::jsonb ELSE '["other"]'::jsonb END,
		           'placement_regions', CASE WHEN i > 100 AND i <= 200 THEN '["eu-west"]'::jsonb ELSE '["global"]'::jsonb END,
		           'cpu_request', CASE WHEN i > 200 AND i <= 300 THEN 1 ELSE 8 END,
		           'memory_request', CASE WHEN i > 300 AND i <= 400 THEN 256 ELSE 4096 END,
		           'compiled_job_payload', '{"effective_job":{"job":{"runtime":"native"}}}'::jsonb)
		FROM generate_series(1, $3::int) AS g(i)`, runID, now, n)
	if err != nil {
		t.Fatalf("planner SQL seed %d rows: %v", n, err)
	}
}

// pgITPlannerShrink drops the queue down to size rows by flipping every
// higher id to a non-queued status. Ids are fixed-width lowercase hex, so the
// text comparison orders exactly like the numeric index.
func pgITPlannerShrink(t *testing.T, st *PostgresStore, size int) {
	t.Helper()
	if _, err := st.pool.Exec(context.Background(), `UPDATE jobs SET status='cancelled' WHERE status='queued' AND id > lpad(to_hex($1::int), 32, '0')`, size); err != nil {
		t.Fatalf("planner shrink to %d: %v", size, err)
	}
}

// pgITPlannerPrepare flushes the GIN pending lists and refreshes the planner
// statistics (including the migration 0041 extended statistics) after a seed
// or shrink, so the measured plan reflects the steady-state catalog.
func pgITPlannerPrepare(t *testing.T, st *PostgresStore) {
	t.Helper()
	if _, err := st.pool.Exec(context.Background(), `VACUUM (ANALYZE) jobs`); err != nil {
		t.Fatalf("VACUUM ANALYZE jobs: %v", err)
	}
}

// pgITExplainExec runs EXPLAIN through the SAME execution mode the production
// page queries use (unnamed statement, planned with the bound values), so the
// pinned plan is the production plan.
func pgITExplainExec(t *testing.T, st *PostgresStore, query string, args ...any) (explainNode, float64) {
	t.Helper()
	var raw []byte
	callArgs := append([]any{pgx.QueryExecModeExec}, args...)
	if err := st.pool.QueryRow(context.Background(), `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+query, callArgs...).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	var roots []explainRoot
	if err := json.Unmarshal(raw, &roots); err != nil {
		t.Fatalf("decode EXPLAIN JSON: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("EXPLAIN returned %d plans, want 1", len(roots))
	}
	return roots[0].Plan, roots[0].ExecutionTime
}

// pgITPlannerMetrics is the boundedness evidence of one measured plan.
type pgITPlannerMetrics struct {
	name       string
	size       int
	indexes    []string
	seqScan    bool
	removed    float64
	buffers    float64
	examined   float64
	execMillis float64
}

// pgITPlannerPlanMetrics flattens the plan into the asserted counters.
// Rows Removed by Filter and shared buffers are summed over EVERY node (the
// task's bound is on the whole plan); examined approximates the tuples the
// executor touched reading jobs, returned plus dropped.
func pgITPlannerPlanMetrics(plan explainNode) (seqScan bool, indexes []string, removed, buffers, examined float64) {
	indexSet := map[string]bool{}
	pgITWalkPlan(plan, func(n explainNode) {
		if strings.HasPrefix(n.IndexName, "jobs_queued_") {
			indexSet[n.IndexName] = true
		}
		loops := n.ActualLoops
		if loops < 1 {
			loops = 1
		}
		removed += n.RowsRemoved
		buffers += n.SharedHit + n.SharedRead
		if n.RelationName != "jobs" {
			return
		}
		if strings.Contains(n.NodeType, "Seq Scan") {
			seqScan = true
		}
		examined += n.ActualRows * loops
	})
	for name := range indexSet {
		indexes = append(indexes, name)
	}
	sort.Strings(indexes)
	return seqScan, indexes, removed, buffers, examined
}

// pgITPlannerMeasure plans and measures one permutation at one size, then
// runs the production API and requires its page to contain exactly the
// indexed match set (capped at the limit) with exact HasMore. Every returned
// row must also pass the in-memory mirror of the filter, so the SQL column
// predicates and the Go payload decisions agree.
func pgITPlannerMeasure(t *testing.T, st *PostgresStore, tc pgITPlannerCase, size int, now time.Time) pgITPlannerMetrics {
	t.Helper()
	query, args := queuedJobsPageQuery(tc.filter, nil, 256, now)
	plan, execMillis := pgITExplainExec(t, st, query, args...)
	seqScan, indexes, removed, buffers, examined := pgITPlannerPlanMetrics(plan)
	m := pgITPlannerMetrics{
		name: tc.name, size: size, indexes: indexes, seqScan: seqScan,
		removed: removed, buffers: buffers, examined: examined, execMillis: execMillis,
	}
	t.Logf("perm=%s size=%d indexes=%v removed=%.0f buffers=%.0f examined=%.0f exec=%.2fms",
		m.name, m.size, m.indexes, m.removed, m.buffers, m.examined, m.execMillis)

	if m.seqScan {
		t.Fatalf("perm=%s size=%d plan sequentially scans jobs; the filter must be index-driven\nplan: %+v", m.name, m.size, plan)
	}
	if len(m.indexes) == 0 {
		t.Fatalf("perm=%s size=%d plan uses no jobs_queued_* index\nplan: %+v", m.name, m.size, plan)
	}
	if tc.wantIndex != "" && !containsString(m.indexes, tc.wantIndex) {
		t.Fatalf("perm=%s size=%d plan indexes %v, want %s\nplan: %+v", m.name, m.size, m.indexes, tc.wantIndex, plan)
	}
	removedBudget := float64(size) / 5
	if tc.zero {
		removedBudget = 4096
	}
	if m.removed > removedBudget {
		t.Fatalf("perm=%s size=%d removed %.0f heap rows, budget %.0f (scan must stay bounded by the indexed match set)\nplan: %+v",
			m.name, m.size, m.removed, removedBudget, plan)
	}
	bufferBudget := 4096 + float64(size)/25
	if m.buffers > bufferBudget {
		t.Fatalf("perm=%s size=%d touched %.0f shared buffers, budget %.0f\nplan: %+v", m.name, m.size, m.buffers, bufferBudget, plan)
	}
	if tc.zero && m.examined > 4096 {
		t.Fatalf("perm=%s size=%d examined %.0f tuples for a zero-match filter, want <= 4096 (queue-size independent)\nplan: %+v",
			m.name, m.size, m.examined, plan)
	}

	page, err := st.ListQueuedJobsPage(context.Background(), tc.filter, nil, 256, now)
	if err != nil {
		t.Fatalf("perm=%s size=%d ListQueuedJobsPage: %v", m.name, m.size, err)
	}
	want := tc.expected(size)
	if want > 256 {
		want = 256
	}
	if len(page.Jobs) != want {
		t.Fatalf("perm=%s size=%d page returned %d rows, want %d", m.name, m.size, len(page.Jobs), want)
	}
	if page.HasMore != (tc.expected(size) > 256) {
		t.Fatalf("perm=%s size=%d HasMore=%v, want %v", m.name, m.size, page.HasMore, tc.expected(size) > 256)
	}
	for _, j := range page.Jobs {
		if !QueuedJobMatchesFilter(j, tc.filter) {
			t.Fatalf("perm=%s size=%d page returned %s which the in-memory filter rejects (SQL column vs payload divergence)",
				m.name, m.size, j.ID)
		}
	}
	return m
}

// TestPostgresIntegrationQueuedJobsPagePlannerMatrix runs the full
// permutation/size matrix. Assertions per permutation: no Seq Scan on jobs,
// at least one jobs_queued_* index drives the plan, dropped-heap-row and
// buffer budgets that scale with the queue, and for the zero-match case an
// examined-tuple count that stays <= 4096 AND grows at most ~3x from 10k to
// 100k (not linearly with the queue).
func TestPostgresIntegrationQueuedJobsPagePlannerMatrix(t *testing.T) {
	st := pgITStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour)}})

	maxRows := 100000
	switch scale := strings.TrimSpace(os.Getenv("KIWI_TEST_PLANNER_SCALE")); scale {
	case "":
	case "1m":
		maxRows = 1000000
	default:
		t.Fatalf("KIWI_TEST_PLANNER_SCALE=%q, want empty or \"1m\"", scale)
	}

	seedStart := time.Now()
	if maxRows <= 100000 {
		pgITPlannerSeedGo(t, st, runID, maxRows, now)
	} else {
		pgITPlannerSeedSQL(t, st, runID, maxRows, now)
	}
	t.Logf("seeded %d queued rows in %s", maxRows, time.Since(seedStart).Round(time.Millisecond))

	sizes := []int{100000, 10000}
	if maxRows > 100000 {
		sizes = []int{1000000, 100000, 10000}
	}
	cases := pgITPlannerCases()
	byCase := map[string]map[int]pgITPlannerMetrics{}
	for _, size := range sizes {
		if size < maxRows {
			pgITPlannerShrink(t, st, size)
		}
		pgITPlannerPrepare(t, st)
		for _, tc := range cases {
			m := pgITPlannerMeasure(t, st, tc, size, now)
			if byCase[tc.name] == nil {
				byCase[tc.name] = map[int]pgITPlannerMetrics{}
			}
			byCase[tc.name][size] = m
		}
	}

	// Every zero-match permutation must not scale with the queue: the workload
	// at 100k may be at most ~3x the 10k workload (examined tuples and shared
	// buffers), not 10x.
	for _, tc := range cases {
		if !tc.zero {
			continue
		}
		bySize := byCase[tc.name]
		small, okSmall := bySize[10000]
		big, okBig := bySize[100000]
		if !okSmall || !okBig {
			continue
		}
		if big.examined > 3*math.Max(small.examined, 1) {
			t.Fatalf("perm=%s examined %.0f tuples at 100k vs %.0f at 10k (ratio %.1fx); must not scale linearly",
				tc.name, big.examined, small.examined, big.examined/math.Max(small.examined, 1))
		}
		if big.buffers > 3*math.Max(small.buffers, 1) {
			t.Fatalf("perm=%s touched %.0f buffers at 100k vs %.0f at 10k (ratio %.1fx); must not scale linearly",
				tc.name, big.buffers, small.buffers, big.buffers/math.Max(small.buffers, 1))
		}
	}
}

// TestPostgresIntegrationQueuedJobsPlannerIndexContract pins the schema
// contract the queued page query relies on: every predicate it can emit is
// backed by a jobs_queued_* index whose definition names the same
// column/expression, the replaced jsonb GIN indexes are gone, and the
// extended statistics objects exist for the runtime and resource
// expressions (an expression index alone gives the planner no clause
// selectivity, see migration 0041).
func TestPostgresIntegrationQueuedJobsPlannerIndexContract(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	rows, err := st.pool.Query(ctx, `SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND tablename='jobs'`)
	if err != nil {
		t.Fatalf("read pg_indexes: %v", err)
	}
	defer rows.Close()
	defs := map[string]string{}
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			t.Fatalf("scan pg_indexes: %v", err)
		}
		defs[name] = def
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("pg_indexes rows: %v", err)
	}

	// Each predicate dimension maps to the index that must serve it and the
	// fragments its pg_get_indexdef rendering must contain.
	for _, want := range []struct {
		index    string
		fragment []string
	}{
		{"jobs_queued_aged_idx", []string{"priority + queue_boost", "created_at", "id", "status = 'queued'"}},
		// (created_at, queue_boost, id) is the PROMOTION sweep's order only
		// (PromoteQueuedJobBoosts); the immutable traversal is served by
		// jobs_queued_traversal_idx below, whose key is the traversal order.
		{"jobs_queued_boost_sweep_idx", []string{"created_at", "queue_boost", "status = 'queued'"}},
		{"jobs_queued_traversal_idx", []string{"created_at", "id", "status = 'queued'"}},
		{"jobs_queued_runtime_idx", []string{"compiled_job_payload", "effective_job", "native", "status = 'queued'"}},
		{"jobs_queued_labels_arr_idx", []string{"gin", "required_labels", "status = 'queued'"}},
		{"jobs_queued_regions_arr_idx", []string{"gin", "placement_regions", "status = 'queued'"}},
		{"jobs_queued_cpu_idx", []string{"cpu_request", "service_envelope_request", "jsonb_typeof", "numeric", "status = 'queued'"}},
		{"jobs_queued_memory_idx", []string{"memory_request", "service_envelope_request", "jsonb_typeof", "numeric", "status = 'queued'"}},
		{"jobs_queued_pids_idx", []string{"pids_request", "service_envelope_request", "jsonb_typeof", "numeric", "status = 'queued'"}},
		{"jobs_queued_disk_idx", []string{"disk_request", "service_envelope_request", "jsonb_typeof", "numeric", "status = 'queued'"}},
		{"jobs_queued_cpu_own_idx", []string{"cpu_request", "jsonb_typeof", "numeric", "status = 'queued'"}},
		{"jobs_queued_memory_own_idx", []string{"memory_request", "jsonb_typeof", "numeric", "status = 'queued'"}},
		{"jobs_queued_pids_own_idx", []string{"pids_request", "jsonb_typeof", "numeric", "status = 'queued'"}},
		{"jobs_queued_disk_own_idx", []string{"disk_request", "jsonb_typeof", "numeric", "status = 'queued'"}},
	} {
		def, ok := defs[want.index]
		if !ok {
			t.Errorf("jobs index %s is missing; pg_indexes has %v", want.index, sortedKeys(defs))
			continue
		}
		for _, frag := range want.fragment {
			if !strings.Contains(def, frag) {
				t.Errorf("index %s definition %q is missing %q", want.index, def, frag)
			}
		}
	}
	for _, replaced := range []string{"jobs_queued_labels_idx", "jobs_queued_regions_idx"} {
		if def, ok := defs[replaced]; ok {
			t.Errorf("replaced jsonb index %s still exists: %q", replaced, def)
		}
	}
	// The _own indexes must be the job-only expression: a service-envelope
	// key there would make the IgnoreServiceEnvelope predicate unservable.
	for _, own := range []string{"jobs_queued_cpu_own_idx", "jobs_queued_memory_own_idx", "jobs_queued_pids_own_idx", "jobs_queued_disk_own_idx"} {
		if def, ok := defs[own]; ok && strings.Contains(def, "service_envelope_request") {
			t.Errorf("job-only index %s must not reference the service envelope: %q", own, def)
		}
	}

	// The extended statistics objects must exist and name the same
	// expressions, because they are what makes the planner estimate a
	// request/capacity clause from the actual index statistics.
	statRows, err := st.pool.Query(ctx, `
		SELECT stxname, pg_get_statisticsobjdef(oid)
		FROM pg_statistic_ext WHERE stxrelid = 'jobs'::regclass`)
	if err != nil {
		t.Fatalf("read pg_statistic_ext: %v", err)
	}
	defer statRows.Close()
	stats := map[string]string{}
	for statRows.Next() {
		var name, def string
		if err := statRows.Scan(&name, &def); err != nil {
			t.Fatalf("scan pg_statistic_ext: %v", err)
		}
		stats[name] = def
	}
	if err := statRows.Err(); err != nil {
		t.Fatalf("pg_statistic_ext rows: %v", err)
	}
	for _, want := range []struct {
		stats    string
		fragment []string
	}{
		{"jobs_queued_runtime_stats", []string{"compiled_job_payload", "native"}},
		{"jobs_queued_cpu_stats", []string{"cpu_request", "service_envelope_request"}},
		{"jobs_queued_memory_stats", []string{"memory_request", "service_envelope_request"}},
		{"jobs_queued_pids_stats", []string{"pids_request", "service_envelope_request"}},
		{"jobs_queued_disk_stats", []string{"disk_request", "service_envelope_request"}},
		{"jobs_queued_cpu_own_stats", []string{"cpu_request"}},
		{"jobs_queued_memory_own_stats", []string{"memory_request"}},
		{"jobs_queued_pids_own_stats", []string{"pids_request"}},
		{"jobs_queued_disk_own_stats", []string{"disk_request"}},
	} {
		def, ok := stats[want.stats]
		if !ok {
			t.Errorf("statistics object %s is missing; pg_statistic_ext has %v", want.stats, sortedKeys(stats))
			continue
		}
		for _, frag := range want.fragment {
			if !strings.Contains(def, frag) {
				t.Errorf("statistics %s definition %q is missing %q", want.stats, def, frag)
			}
		}
	}

	// Finally, the live predicate SQL must reference the indexed columns, so
	// the catalog contract and the query builder cannot drift apart.
	filter := QueuedJobFilter{
		Runtimes:     []string{"native"},
		RunnerLabels: []string{"linux"},
		RunnerRegion: "eu-west",
		MaxRequested: model.ResourceCapacity{CPU: 1, Memory: 2, Disk: 3, PIDs: 4},
	}
	query, _ := queuedJobsPageQuery(filter, nil, 256, time.Now().UTC())
	for _, frag := range []string{
		"required_labels <@ ",
		"placement_regions = '{}'::text[]",
		"placement_regions && ",
		queuedJobRuntimeSQLExpr,
		"payload->'cpu_request'", "payload->'service_envelope_request'->'cpu'",
		"payload->'memory_request'", "payload->'service_envelope_request'->'memory'",
		"payload->'disk_request'", "payload->'service_envelope_request'->'disk'",
		"payload->'pids_request'", "payload->'service_envelope_request'->'pids'",
	} {
		if !strings.Contains(query, frag) {
			t.Errorf("queuedJobsPageQuery is missing predicate fragment %q", frag)
		}
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestPostgresIntegrationQueuedJobsPageNormalizedColumnsParity proves the
// canonical write paths stamp the normalized filter columns from the same
// model fields the payload carries: InsertJob, UpdateJob (including a
// label/region change) and the ApproveJob queued transition (which restores a
// legacy row whose column was still '{}' when it becomes queued). The queued
// page's SQL reads the column while the scheduler's Go mirror reads the
// payload, so the two must agree for every row this binary writes.
func TestPostgresIntegrationQueuedJobsPageNormalizedColumnsParity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{ID: runID, Status: model.StatusQueued, CreatedAt: now}})

	readCols := func(id string) (labels, regions []string) {
		t.Helper()
		if err := st.pool.QueryRow(ctx, `SELECT required_labels, placement_regions FROM jobs WHERE id=$1`, id).Scan(&labels, &regions); err != nil {
			t.Fatalf("read normalized columns of %s: %v", id, err)
		}
		return labels, regions
	}
	equal := func(id string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("job %s list = %v, want %v", id, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("job %s list = %v, want %v", id, got, want)
			}
		}
	}

	// InsertJob stamps both columns.
	inserted := model.Job{
		ID: pgITNewID(t), RunID: runID, Key: "build-inserted", Status: model.StatusQueued, CreatedAt: now,
		RequiredLabels: []string{"linux", "x64"}, PlacementRegions: []string{"eu-west"},
	}
	if err := st.InsertJob(ctx, inserted); err != nil {
		t.Fatalf("InsertJob: %v", err)
	}
	labels, regions := readCols(inserted.ID)
	equal(inserted.ID, labels, inserted.RequiredLabels)
	equal(inserted.ID, regions, inserted.PlacementRegions)

	// A nil list is stored as '{}' (NOT NULL), exactly the model zero value.
	plain := model.Job{ID: pgITNewID(t), RunID: runID, Key: "build-plain", Status: model.StatusQueued, CreatedAt: now}
	if err := st.InsertJob(ctx, plain); err != nil {
		t.Fatalf("InsertJob(plain): %v", err)
	}
	labels, regions = readCols(plain.ID)
	if labels == nil || regions == nil || len(labels) != 0 || len(regions) != 0 {
		t.Fatalf("plain job columns = %v/%v, want empty non-NULL arrays", labels, regions)
	}

	// UpdateJob follows a payload field change.
	inserted.RequiredLabels = []string{"other"}
	inserted.PlacementRegions = nil
	if err := st.UpdateJob(ctx, inserted); err != nil {
		t.Fatalf("UpdateJob: %v", err)
	}
	labels, regions = readCols(inserted.ID)
	equal(inserted.ID, labels, []string{"other"})
	if regions == nil || len(regions) != 0 {
		t.Fatalf("updated job regions = %v, want empty non-NULL array", regions)
	}

	// ApproveJob restores the column on the waiting_approval -> queued
	// transition. Simulate a pre-0041 row by resetting the columns to '{}'
	// behind the store: the payload is authoritative and the approval path
	// must re-derive the column from it.
	approved := model.Job{
		ID: pgITNewID(t), RunID: runID, Key: "build-approved", Status: model.StatusWaitingApproval,
		ApprovalRequired: true, CreatedAt: now,
		RequiredLabels: []string{"gpu"}, PlacementRegions: []string{"us"},
	}
	if err := st.InsertJob(ctx, approved); err != nil {
		t.Fatalf("InsertJob(approval): %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET required_labels='{}', placement_regions='{}' WHERE id=$1`, approved.ID); err != nil {
		t.Fatalf("reset approval columns: %v", err)
	}
	j, err := st.ApproveJob(ctx, approved.ID, "tester")
	if err != nil {
		t.Fatalf("ApproveJob: %v", err)
	}
	if j.Status != model.StatusQueued {
		t.Fatalf("approved status = %s, want queued", j.Status)
	}
	labels, regions = readCols(approved.ID)
	equal(approved.ID, labels, []string{"gpu"})
	equal(approved.ID, regions, []string{"us"})

	page, err := st.ListQueuedJobsPage(ctx, QueuedJobFilter{
		Runtimes:     []string{"native"},
		RunnerLabels: []string{"gpu"},
		RunnerRegion: "us",
	}, nil, 10, now)
	if err != nil {
		t.Fatalf("ListQueuedJobsPage(approved): %v", err)
	}
	// The plain job (empty labels/regions) legitimately matches too — the
	// filter is a superset of {gpu}/{us} for label-less, region-less rows.
	foundApproved := false
	for _, j := range page.Jobs {
		if j.ID == approved.ID {
			foundApproved = true
		}
	}
	if !foundApproved {
		t.Fatalf("approved job %s is not visible to the normalized page filter: %v", approved.ID, queuedJobsPageIDs(page))
	}
}
