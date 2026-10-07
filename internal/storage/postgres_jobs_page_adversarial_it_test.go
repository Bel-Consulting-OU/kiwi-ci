package storage

// Adversarial planner matrix for the bounded queued page query: the
// distributions the original common/rare matrix (postgres_jobs_page_planner_
// it_test.go) does not cover. The original matrix varies ONE rare dimension at
// a time on a queue whose other dimensions are saturated common; that never
// exercises the real invariant — a poll from a runner with NO eligible job
// must not become proportional to the total queued-job cardinality — under
// COMBINED, correlated selectivity, and it never exercises a plan that is
// good on one distribution but hostile on another.
//
// Every distribution below is seeded alone (one SQL fixture per size, shrunk
// from the largest size by the same status flip the original matrix uses), so
// its percentages are exact and its match set is known:
//
//	a) runtime 95% / region 95% / labels 0.01% / memory 5%, correlated so the
//	   intersection is EMPTY (every rare-label row sits in the 5% region
//	   mismatch): the planner sees three broad arms and an ultra-rare one and
//	   must not walk the queue.
//	b) runtime 100% / labels 100% / CPU eliminates 99.9%: the only filtering
//	   arm is the combined CPU expression index; the runtime and label indexes
//	   match the whole queue and a plan that starts from them examines it all.
//	c) runtime 95% / region 5% / labels 95% / CPU 95%: moderate selectivity on
//	   every dimension; the region arm (5%) is the only actually-filtering
//	   dimension, and the work must stay bounded by its match set instead of
//	   degenerating into a full aged walk.
//	d) the original zero-match permutations with the rare dimension NOT first
//	   in the WHERE clause, measured twice: canonical order and fully reversed
//	   predicate order (via queuedJobPredicateOrderOverride), proving clause
//	   order cannot decide plan semantics.
//	e) a perfectly uniform queue where EVERY predicate matches (the pure
//	   ORDER BY LIMIT case; examined work must stay at the ~LIMIT bound), and
//	   a queue whose ONLY eligible row sits at the very END of the aged order
//	   (the aged walk must not be chosen, because reaching it would scan the
//	   whole queue).
//
// Measurement harness: each permutation/size is EXPLAINed (ANALYZE, BUFFERS,
// FORMAT JSON) N=3 times; the test records all three execution times plus
// their median and, from the plan tree, total Rows Removed by Filter (and by
// index recheck), the actual rows of every relation scan node (heap rows and
// bitmap index tuples), Shared Hit/Read blocks, heap fetches, and every
// Sort/Incremental Sort node WITH its input row count. Assertions: no Seq Scan
// on jobs, a jobs_queued_* index (or a bitmap combination of them) drives the
// plan, examined/removed work stays within 4x the indexed match set plus a
// 4096 constant, any Sort/Incremental Sort is fed by the indexed match set
// rather than the queue (a GIN/expression index cannot provide the aged
// order, so a bounded sort over the match set is the correct plan; a sort of
// the queue population is the regression this matrix exists to catch — the
// literal "no sort" reading is impossible for a selective index and is
// measured, logged and bounded here instead), the 10k->100k scaling of the
// zero/rare cases stays under max(3x, 5000) for examined tuples and
// max(3x, 4096) for buffers and removed rows, and the median execution at
// 100k stays far below a 250ms sanity bound.
//
// Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here. Run only this
// matrix (never the whole Integration lane):
//
//	KIWI_TEST_POSTGRES_URL='postgres://postgres:postgres@127.0.0.1:5433/kiwi_it?sslmode=disable' \
//	  go test ./internal/storage -run TestPostgresIntegrationQueuedJobsPagePlannerAdversarialMatrix -count=1 -v
//
// The 1m run honors the same opt-in gate as the original matrix:
//
//	KIWI_TEST_PLANNER_SCALE=1m KIWI_TEST_POSTGRES_URL=... go test ... -run ...AdversarialMatrix -count=1 -v

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

const (
	// pgITAdvRuns is the EXPLAIN (ANALYZE) repetition count per permutation.
	pgITAdvRuns = 3
	// pgITAdvLimit is the page size every measured query uses.
	pgITAdvLimit = 256
	// pgITAdvBudgetSlack is the constant work allowance every examined/removed
	// budget carries, so index overheads and page rechecks can never be
	// mistaken for queue-proportional work.
	pgITAdvBudgetSlack = 4096
	// pgITAdvExaminedFloor is the absolute floor of the cross-size scaling
	// bound: a case may grow up to this many examined tuples from 10k to 100k
	// even when its 10k baseline was tiny.
	pgITAdvExaminedFloor = 5000
	// pgITAdvBufferFloor is the same floor for shared buffers and removed rows.
	pgITAdvBufferFloor = 4096
	// pgITAdvWallSanity is the generous wall-clock sanity bound at >=100k rows:
	// it exists to catch a plan regression (an accidental full walk), not to
	// benchmark.
	pgITAdvWallSanity = 250 * time.Millisecond
)

// pgITAdvScan is one measured scan node (relation scan or bitmap index scan).
type pgITAdvScan struct {
	nodeType    string
	relation    string
	index       string
	actualRows  float64
	removed     float64
	recheck     float64
	sharedHit   float64
	sharedRead  float64
	heapFetches float64
}

// pgITAdvMetrics is the measured boundedness evidence of one permutation at
// one size.
type pgITAdvMetrics struct {
	name        string
	reversed    bool
	size        int
	eligible    int
	indexes     []string
	sortNodes   []string
	sortRows    float64
	seqScan     bool
	removed     float64
	recheck     float64
	hitBlocks   float64
	readBlocks  float64
	buffers     float64
	heapRows    float64
	indexTuples float64
	examined    float64
	heapFetches float64
	scans       []pgITAdvScan
	execMs      []float64
	medianMs    float64
}

// pgITAdvDistribution is one adversarial queue shape and the filter that
// probes it. matches(i) must mirror the SQL fixture exactly; the seeded page
// count is derived from it and cross-checked against the real query result, so
// a fixture/expectation divergence cannot pass silently.
type pgITAdvDistribution struct {
	name        string
	seed        func(t *testing.T, st *PostgresStore, runID string, n int, now time.Time)
	filter      QueuedJobFilter
	matches     func(i int) bool
	noEligible  bool
	rare        bool
	allMatch    bool
	reverseAlso bool
	wantIndexes []string
}

// pgITAdvShape is the per-row SQL of one distribution fixture. Every
// expression is evaluated over generate_series(i); labels and regions must
// render a text[] (the normalized column and, through to_jsonb, the payload
// key agree by construction).
type pgITAdvShape struct {
	labels  string
	regions string
	cpu     string
	memory  string
	runtime string
}

// pgITAdvSeedShape seeds n queued rows of one shape in a single statement.
// Ages are i seconds (boost floor(i/600) exactly like the promotion sweep),
// so the aged order is stable and the materialized scheduling key matches the
// index statistics a production queue would have.
func pgITAdvSeedShape(t *testing.T, st *PostgresStore, runID string, n int, now time.Time, shape pgITAdvShape) {
	t.Helper()
	_, err := st.pool.Exec(context.Background(), `
		INSERT INTO jobs (id, run_id, key, status, dependency_status, priority, queue_boost, attempts, created_at, required_labels, placement_regions, payload)
		SELECT lpad(to_hex(i), 32, '0'), $1, 'build', 'queued', 'success', (i % 4), (i / 600), 0,
		       $2::timestamptz - (i * interval '1 second'),
		       `+shape.labels+`,
		       `+shape.regions+`,
		       jsonb_build_object(
		           'required_labels', to_jsonb(`+shape.labels+`),
		           'placement_regions', to_jsonb(`+shape.regions+`),
		           'cpu_request', `+shape.cpu+`,
		           'memory_request', `+shape.memory+`,
		           'compiled_job_payload', jsonb_build_object(
		               'effective_job', jsonb_build_object(
		                   'job', jsonb_build_object('runtime', `+shape.runtime+`))))
		FROM generate_series(1, $3::int) AS g(i)`, runID, now, n)
	if err != nil {
		t.Fatalf("adversarial seed %d rows: %v", n, err)
	}
}

// pgITAdvExplainRuns plans and executes query pgITAdvRuns times through the
// production execution mode (unnamed statement, planned with the bound
// values) and returns the last plan plus every measured execution time in run
// order.
func pgITAdvExplainRuns(t *testing.T, st *PostgresStore, query string, args []any) (explainNode, []float64) {
	t.Helper()
	var plan explainNode
	times := make([]float64, 0, pgITAdvRuns)
	callArgs := append([]any{pgx.QueryExecModeExec}, args...)
	for run := 1; run <= pgITAdvRuns; run++ {
		var raw []byte
		if err := st.pool.QueryRow(context.Background(), `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+query, callArgs...).Scan(&raw); err != nil {
			t.Fatalf("EXPLAIN run %d: %v", run, err)
		}
		var roots []explainRoot
		if err := json.Unmarshal(raw, &roots); err != nil {
			t.Fatalf("decode EXPLAIN JSON run %d: %v", run, err)
		}
		if len(roots) != 1 {
			t.Fatalf("EXPLAIN run %d returned %d plans, want 1", run, len(roots))
		}
		plan = roots[0].Plan
		times = append(times, roots[0].ExecutionTime)
	}
	return plan, times
}

// pgITAdvPlanMetrics flattens one plan into the measured counters: every scan
// node is captured individually, Rows Removed by Filter (and by index
// recheck) and shared buffers are summed over the whole tree, and examined
// counts every tuple the executor actually touched reading jobs — surviving
// heap rows, rows dropped at the scan by filter/recheck, plus bitmap index
// tuples. Sort/Incremental Sort nodes are captured with the number of rows
// actually FED to them (the child node's output, because a Sort under a Limit
// only reports the limited number of rows it returned), because a bounded
// sort over the indexed match set is the correct plan for a selective index
// that cannot provide the aged order; only a queue-proportional sort input is
// a regression.
func pgITAdvPlanMetrics(plan explainNode) pgITAdvMetrics {
	var m pgITAdvMetrics
	indexSet := map[string]bool{}
	var walk func(n explainNode)
	walk = func(n explainNode) {
		loops := n.ActualLoops
		if loops < 1 {
			loops = 1
		}
		if strings.HasPrefix(n.IndexName, "jobs_queued_") {
			indexSet[n.IndexName] = true
		}
		if n.NodeType == "Sort" || n.NodeType == "Incremental Sort" {
			// The sort INPUT is the child's output: under a Limit the sort's
			// own Actual Rows is capped at the limit, which would hide a
			// queue-sized sort behind a 257-row page.
			inputRows := n.ActualRows * loops
			if len(n.Plans) > 0 {
				childLoops := n.Plans[0].ActualLoops
				if childLoops < 1 {
					childLoops = 1
				}
				inputRows = n.Plans[0].ActualRows * childLoops
			}
			m.sortNodes = append(m.sortNodes, fmt.Sprintf("%s(%s) inputRows=%.0f", n.NodeType, strings.Join(n.SortKeys, ", "), inputRows))
			m.sortRows += inputRows
		}
		m.removed += n.RowsRemoved
		m.recheck += n.RemovedRecheck
		m.hitBlocks += n.SharedHit
		m.readBlocks += n.SharedRead
		m.heapFetches += n.HeapFetches
		if n.RelationName == "jobs" && strings.Contains(n.NodeType, "Seq Scan") {
			m.seqScan = true
		}
		isIndexTupleScan := strings.Contains(n.NodeType, "Bitmap Index Scan") || strings.Contains(n.NodeType, "Index Only Scan")
		isRelationScan := n.RelationName == "jobs" && !isIndexTupleScan && strings.Contains(n.NodeType, "Scan")
		if isRelationScan || isIndexTupleScan {
			rows := n.ActualRows * loops
			m.scans = append(m.scans, pgITAdvScan{
				nodeType: n.NodeType, relation: n.RelationName, index: n.IndexName,
				actualRows: rows, removed: n.RowsRemoved, recheck: n.RemovedRecheck,
				sharedHit: n.SharedHit, sharedRead: n.SharedRead, heapFetches: n.HeapFetches,
			})
			if isRelationScan {
				m.heapRows += rows
				// The tuples a filtered relation scan had to read and drop.
				m.examined += (n.RowsRemoved + n.RemovedRecheck) * loops
			}
			if isIndexTupleScan {
				m.indexTuples += rows
			}
		}
		for _, child := range n.Plans {
			walk(child)
		}
	}
	walk(plan)
	m.buffers = m.hitBlocks + m.readBlocks
	m.examined += m.heapRows + m.indexTuples
	for name := range indexSet {
		m.indexes = append(m.indexes, name)
	}
	sort.Strings(m.indexes)
	return m
}

// pgITAdvEligible counts the seeded rows in 1..size the distribution's Go
// mirror accepts; the measured page must agree with it.
func pgITAdvEligible(dist pgITAdvDistribution, size int) int {
	n := 0
	for i := 1; i <= size; i++ {
		if dist.matches(i) {
			n++
		}
	}
	return n
}

// pgITAdvSetPredicateOrder installs the clause-order permutation when
// reversed and returns the restore function (deferred by the caller).
func pgITAdvSetPredicateOrder(reversed bool) func() {
	if !reversed {
		return func() {}
	}
	prev := queuedJobPredicateOrderOverride
	queuedJobPredicateOrderOverride = func(frags []string) []string {
		out := make([]string, len(frags))
		for i := range frags {
			out[i] = frags[len(frags)-1-i]
		}
		return out
	}
	return func() { queuedJobPredicateOrderOverride = prev }
}

// pgITAdvMeasure plans, measures (N=3) and asserts one permutation at one
// size, then runs the production API and requires the page to contain exactly
// min(eligible, limit) rows with exact HasMore and every returned row passing
// the in-memory filter mirror.
func pgITAdvMeasure(t *testing.T, st *PostgresStore, dist pgITAdvDistribution, size int, now time.Time, reversed bool) pgITAdvMetrics {
	t.Helper()
	restore := pgITAdvSetPredicateOrder(reversed)
	defer restore()
	query, args := queuedJobsPageQuery(dist.filter, nil, pgITAdvLimit, now)
	plan, times := pgITAdvExplainRuns(t, st, query, args)
	m := pgITAdvPlanMetrics(plan)
	m.name, m.reversed, m.size = dist.name, reversed, size
	m.eligible = pgITAdvEligible(dist, size)
	m.execMs = times
	sorted := append([]float64(nil), times...)
	sort.Float64s(sorted)
	m.medianMs = sorted[len(sorted)/2]

	label := ""
	if reversed {
		label = " order=reversed"
	}
	t.Logf("adv=%s%s size=%d eligible=%d indexes=%v removed=%.0f recheck=%.0f buffers=%.0f (hit=%.0f read=%.0f) heapRows=%.0f indexTuples=%.0f examined=%.0f heapFetches=%.0f sorts=%v sortRows=%.0f execMs=%v medianMs=%.2f",
		m.name, label, m.size, m.eligible, m.indexes, m.removed, m.recheck, m.buffers, m.hitBlocks, m.readBlocks,
		m.heapRows, m.indexTuples, m.examined, m.heapFetches, m.sortNodes, m.sortRows, m.execMs, m.medianMs)
	for _, s := range m.scans {
		t.Logf("adv=%s%s size=%d scan node=%q rel=%q index=%q rows=%.0f removed=%.0f recheck=%.0f hit=%.0f read=%.0f heapFetches=%.0f",
			m.name, label, m.size, s.nodeType, s.relation, s.index, s.actualRows, s.removed, s.recheck, s.sharedHit, s.sharedRead, s.heapFetches)
	}

	if m.seqScan {
		t.Fatalf("adv=%s%s size=%d plan sequentially scans jobs; the filter must be index-driven\nplan: %+v",
			m.name, label, m.size, plan)
	}
	if len(m.indexes) == 0 {
		t.Fatalf("adv=%s%s size=%d plan uses no jobs_queued_* index\nplan: %+v", m.name, label, m.size, plan)
	}
	if len(dist.wantIndexes) > 0 && !pgITAdvOverlap(m.indexes, dist.wantIndexes) {
		t.Fatalf("adv=%s%s size=%d plan indexes %v, want one of %v\nplan: %+v",
			m.name, label, m.size, m.indexes, dist.wantIndexes, plan)
	}

	// Examined work is bounded by the indexed match set: 4x the eligible set
	// plus a constant. For the all-match case the bound collapses to the
	// ORDER BY LIMIT early stop instead.
	examinedBound := 4*float64(m.eligible) + pgITAdvBudgetSlack
	if dist.allMatch {
		examinedBound = 2*float64(pgITAdvLimit) + pgITAdvLimit
	}
	if m.examined > examinedBound {
		t.Fatalf("adv=%s%s size=%d examined %.0f tuples (heap rows %.0f + scan-drop %.0f + index tuples %.0f), budget %.0f; work must stay bounded by the indexed match set (eligible=%d)\nplan: %+v",
			m.name, label, m.size, m.examined, m.heapRows, m.removed+m.recheck, m.indexTuples, examinedBound, m.eligible, plan)
	}
	// A Sort/Incremental Sort is only admissible when its INPUT is the
	// indexed match set (the normal plan for a GIN/expression index that
	// cannot provide the aged order). A sort of the queue population is the
	// regression the whole matrix exists to catch.
	if m.sortRows > examinedBound {
		t.Fatalf("adv=%s%s size=%d sorts %v over %.0f input rows, budget %.0f: the sort input must be the indexed match set, not the queue\nplan: %+v",
			m.name, label, m.size, m.sortNodes, m.sortRows, examinedBound, plan)
	}
	if removedBound := 4*float64(m.eligible) + pgITAdvBudgetSlack; m.removed > removedBound {
		t.Fatalf("adv=%s%s size=%d removed %.0f heap rows, budget %.0f (eligible=%d)\nplan: %+v",
			m.name, label, m.size, m.removed, removedBound, m.eligible, plan)
	}
	if bufferBound := pgITAdvBudgetSlack + float64(size)/25; m.buffers > bufferBound {
		t.Fatalf("adv=%s%s size=%d touched %.0f shared buffers, budget %.0f\nplan: %+v",
			m.name, label, m.size, m.buffers, bufferBound, plan)
	}
	if size >= 100000 && m.medianMs > float64(pgITAdvWallSanity.Milliseconds()) {
		t.Fatalf("adv=%s%s size=%d median execution %.2fms exceeds the %s sanity bound (plan regression, not a benchmark)\nplan: %+v",
			m.name, label, m.size, m.medianMs, pgITAdvWallSanity, plan)
	}

	page, err := st.ListQueuedJobsPage(context.Background(), dist.filter, nil, pgITAdvLimit, now)
	if err != nil {
		t.Fatalf("adv=%s%s size=%d ListQueuedJobsPage: %v", m.name, label, m.size, err)
	}
	want := m.eligible
	if want > pgITAdvLimit {
		want = pgITAdvLimit
	}
	if len(page.Jobs) != want {
		t.Fatalf("adv=%s%s size=%d page returned %d rows, want %d (eligible=%d)", m.name, label, m.size, len(page.Jobs), want, m.eligible)
	}
	if page.HasMore != (m.eligible > pgITAdvLimit) {
		t.Fatalf("adv=%s%s size=%d HasMore=%v, want %v", m.name, label, m.size, page.HasMore, m.eligible > pgITAdvLimit)
	}
	for _, j := range page.Jobs {
		if !QueuedJobMatchesFilter(j, dist.filter) {
			t.Fatalf("adv=%s%s size=%d page returned %s which the in-memory filter rejects (SQL column vs payload divergence)",
				m.name, label, m.size, j.ID)
		}
	}
	return m
}

// pgITAdvOverlap reports whether any measured index is in want.
func pgITAdvOverlap(have, want []string) bool {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}

// pgITAdvOrderInvarianceAssert bounds the reversed-clause plan against the
// canonical one: rendering the same conjunction with the rare dimension last
// (or first) must not change the plan's semantics, i.e. the reversed plan
// must share the driving index and stay in the same bounded work class. A
// clause permutation that flips the planner into a queue-proportional plan
// fails here as loudly as it would in the canonical direction.
func pgITAdvOrderInvarianceAssert(t *testing.T, dist pgITAdvDistribution, size int, canonical, reversed pgITAdvMetrics) {
	t.Helper()
	if !pgITAdvOverlap(canonical.indexes, reversed.indexes) {
		t.Fatalf("adv=%s size=%d clause order changed the driving index: canonical %v vs reversed %v",
			dist.name, size, canonical.indexes, reversed.indexes)
	}
	if reversed.examined > math.Max(3*canonical.examined, pgITAdvExaminedFloor) {
		t.Fatalf("adv=%s size=%d clause order changed examined work: canonical %.0f vs reversed %.0f tuples",
			dist.name, size, canonical.examined, reversed.examined)
	}
	if reversed.buffers > math.Max(3*canonical.buffers, pgITAdvBufferFloor) {
		t.Fatalf("adv=%s size=%d clause order changed buffers: canonical %.0f vs reversed %.0f",
			dist.name, size, canonical.buffers, reversed.buffers)
	}
	if reversed.removed > math.Max(3*canonical.removed, pgITAdvBufferFloor) {
		t.Fatalf("adv=%s size=%d clause order changed removed rows: canonical %.0f vs reversed %.0f",
			dist.name, size, canonical.removed, reversed.removed)
	}
}

// pgITAdvScalingAssert bounds the growth of the zero/rare cases between
// consecutive measured sizes: examined tuples may grow at most 3x (with a
// 5000 absolute floor), buffers and removed rows at most 3x (4096 floor).
func pgITAdvScalingAssert(t *testing.T, dist pgITAdvDistribution, bySize map[int]pgITAdvMetrics) {
	t.Helper()
	if !dist.noEligible && !dist.rare {
		return
	}
	sizes := make([]int, 0, len(bySize))
	for size := range bySize {
		sizes = append(sizes, size)
	}
	sort.Ints(sizes)
	for i := 1; i < len(sizes); i++ {
		small, big := bySize[sizes[i-1]], bySize[sizes[i]]
		if big.examined > math.Max(3*small.examined, pgITAdvExaminedFloor) {
			t.Fatalf("adv=%s size=%d->%d examined %.0f -> %.0f tuples (ratio %.1fx); a no-eligible/rare poll must not scale with the queue",
				dist.name, sizes[i-1], sizes[i], small.examined, big.examined, big.examined/math.Max(small.examined, 1))
		}
		if big.buffers > math.Max(3*small.buffers, pgITAdvBufferFloor) {
			t.Fatalf("adv=%s size=%d->%d buffers %.0f -> %.0f (ratio %.1fx); a no-eligible/rare poll must not scale with the queue",
				dist.name, sizes[i-1], sizes[i], small.buffers, big.buffers, big.buffers/math.Max(small.buffers, 1))
		}
		if big.removed > math.Max(3*small.removed, pgITAdvBufferFloor) {
			t.Fatalf("adv=%s size=%d->%d removed %.0f -> %.0f heap rows (ratio %.1fx); a no-eligible/rare poll must not scale with the queue",
				dist.name, sizes[i-1], sizes[i], small.removed, big.removed, big.removed/math.Max(small.removed, 1))
		}
	}
}

// pgITAdvDistributions builds the adversarial shapes. The exact percentages
// are the ones the release audit named; the residue patterns interleave each
// dimension across the whole id range, so the same proportions hold after the
// status-flip shrink to every smaller size.
func pgITAdvDistributions() []pgITAdvDistribution {
	textArray := func(elems ...string) string {
		parts := make([]string, len(elems))
		for i, e := range elems {
			parts[i] = "'" + e + "'"
		}
		return "ARRAY[" + strings.Join(parts, ",") + "]::text[]"
	}
	return []pgITAdvDistribution{
		{
			// a) 95% runtime / 95% region / 0.01% labels / 5% memory, with the
			// rare-label rows correlated into the region mismatch: every arm
			// but region passes them, so the intersection is empty and only
			// the label or region index can prove it without walking.
			name: "a_runtime95_region95_labels001_memory5_empty",
			seed: func(t *testing.T, st *PostgresStore, runID string, n int, now time.Time) {
				pgITAdvSeedShape(t, st, runID, n, now, pgITAdvShape{
					labels:  "CASE WHEN i % 10000 = 0 THEN " + textArray("rare-a") + " ELSE " + textArray("lbl-a") + " END",
					regions: "CASE WHEN i % 20 = 0 THEN " + textArray("xreg-a") + " ELSE " + textArray("reg-a") + " END",
					cpu:     "8",
					memory:  "CASE WHEN i % 20 = 0 THEN 256 ELSE 4096 END",
					runtime: "CASE WHEN i % 20 = 1 THEN 'container' ELSE 'native' END",
				})
			},
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"rare-a"},
				RunnerRegion: "reg-a",
				MaxRequested: model.ResourceCapacity{Memory: 2048},
			},
			matches: func(i int) bool {
				runtimePass := i%20 != 1
				labelPass := i%10000 == 0
				regionPass := i%20 != 0
				memoryPass := 256 <= 2048
				return runtimePass && labelPass && regionPass && memoryPass
			},
			noEligible:  true,
			wantIndexes: []string{"jobs_queued_labels_arr_idx", "jobs_queued_regions_arr_idx"},
		},
		{
			// b) runtime and labels match the whole queue; the combined CPU
			// expression eliminates 99.9%, so the CPU index must own the plan.
			name: "b_runtime100_labels100_cpu999_rare",
			seed: func(t *testing.T, st *PostgresStore, runID string, n int, now time.Time) {
				pgITAdvSeedShape(t, st, runID, n, now, pgITAdvShape{
					labels:  textArray("lbl-b"),
					regions: textArray("reg-b"),
					cpu:     "CASE WHEN i % 1000 = 0 THEN 1 ELSE 8 END",
					memory:  "4096",
					runtime: "'native'",
				})
			},
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"lbl-b"},
				RunnerRegion: "reg-b",
				MaxRequested: model.ResourceCapacity{CPU: 2},
			},
			matches: func(i int) bool {
				if i%1000 == 0 {
					return 1 <= 2 // the rare rows request cpu=1 and fit the cap
				}
				return 8 <= 2 // the 99.9% bulk requests cpu=8 and is eliminated
			},
			rare:        true,
			wantIndexes: []string{"jobs_queued_cpu_idx"},
		},
		{
			// c) every dimension moderate: runtime 95%, region 5%, labels 95%,
			// CPU 95%. The region arm is the only actually-filtering one, and
			// a plan must stay within a small multiple of its 5% match set.
			name: "c_runtime95_region5_labels95_cpu95",
			seed: func(t *testing.T, st *PostgresStore, runID string, n int, now time.Time) {
				pgITAdvSeedShape(t, st, runID, n, now, pgITAdvShape{
					labels:  "CASE WHEN i % 20 = 2 THEN " + textArray("bad-c") + " ELSE " + textArray("lbl-c") + " END",
					regions: "CASE WHEN i % 20 = 0 THEN " + textArray("reg-c") + " ELSE " + textArray("xreg-c") + " END",
					cpu:     "CASE WHEN i % 20 = 3 THEN 8 ELSE 1 END",
					memory:  "4096",
					runtime: "CASE WHEN i % 20 = 1 THEN 'container' ELSE 'native' END",
				})
			},
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"lbl-c"},
				RunnerRegion: "reg-c",
				MaxRequested: model.ResourceCapacity{CPU: 2},
			},
			matches: func(i int) bool {
				runtimePass := i%20 != 1
				labelPass := i%20 != 2
				regionPass := i%20 == 0
				cpuPass := i%20 != 3
				return runtimePass && labelPass && regionPass && cpuPass
			},
			wantIndexes: []string{"jobs_queued_regions_arr_idx", "jobs_queued_aged_idx"},
		},
		{
			// d1) zero-match on the LABEL predicate, which is the SECOND
			// predicate in the canonical WHERE; measured canonical and fully
			// reversed (rare dimension last/first).
			name: "d1_zero_label_not_first",
			seed: func(t *testing.T, st *PostgresStore, runID string, n int, now time.Time) {
				pgITAdvSeedShape(t, st, runID, n, now, pgITAdvShape{
					labels:  textArray("lbl-d"),
					regions: textArray("reg-d"),
					cpu:     "8",
					memory:  "4096",
					runtime: "'native'",
				})
			},
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"absent-d"},
				RunnerRegion: "reg-d",
			},
			matches:     func(i int) bool { return false },
			noEligible:  true,
			reverseAlso: true,
			wantIndexes: []string{"jobs_queued_labels_arr_idx"},
		},
		{
			// d2) zero-match on the MEMORY resource predicate, which is the
			// LAST predicate in the canonical WHERE; measured canonical and
			// fully reversed (rare dimension first).
			name: "d2_zero_memory_not_first",
			seed: func(t *testing.T, st *PostgresStore, runID string, n int, now time.Time) {
				pgITAdvSeedShape(t, st, runID, n, now, pgITAdvShape{
					labels:  textArray("lbl-d"),
					regions: textArray("reg-d"),
					cpu:     "8",
					memory:  "4096",
					runtime: "'native'",
				})
			},
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"lbl-d"},
				RunnerRegion: "reg-d",
				MaxRequested: model.ResourceCapacity{Memory: 1},
			},
			matches:     func(i int) bool { return false },
			noEligible:  true,
			reverseAlso: true,
			wantIndexes: []string{"jobs_queued_memory_idx"},
		},
		{
			// e) perfectly uniform: every predicate matches every row. The
			// plan is the pure ORDER BY + LIMIT early stop and examined work
			// must stay at the ~LIMIT bound, never at the queue bound.
			name: "e_all_match_uniform",
			seed: func(t *testing.T, st *PostgresStore, runID string, n int, now time.Time) {
				pgITAdvSeedShape(t, st, runID, n, now, pgITAdvShape{
					labels:  textArray("lbl-e"),
					regions: textArray("reg-e"),
					cpu:     "1",
					memory:  "256",
					runtime: "'native'",
				})
			},
			filter: QueuedJobFilter{
				Runtimes:     []string{"native"},
				RunnerLabels: []string{"lbl-e"},
				RunnerRegion: "reg-e",
				MaxRequested: model.ResourceCapacity{CPU: 2, Memory: 2048},
			},
			matches:     func(i int) bool { return true },
			allMatch:    true,
			wantIndexes: []string{"jobs_queued_aged_idx"},
		},
	}
}

// pgITAdvSingleEndDistribution builds the "only eligible row at the end of
// the aged order" queue: every row matches runtime/region/CPU, exactly ONE
// row (id 10000, inside every measured size) carries the runner's label, and
// that row is pinned to the LAST aged position (priority 0, boost 0) while
// every other row sits at aged 15. A plan that walks the aged order therefore
// scans the whole queue before reaching it; only the label index is bounded.
func pgITAdvSingleEndDistribution() pgITAdvDistribution {
	const special = 10000
	return pgITAdvDistribution{
		name: "f_single_eligible_at_aged_end",
		seed: func(t *testing.T, st *PostgresStore, runID string, n int, now time.Time) {
			t.Helper()
			_, err := st.pool.Exec(context.Background(), `
				INSERT INTO jobs (id, run_id, key, status, dependency_status, priority, queue_boost, attempts, created_at, required_labels, placement_regions, payload)
				SELECT lpad(to_hex(i), 32, '0'), $1, 'build', 'queued', 'success',
				       CASE WHEN i = `+fmt.Sprint(special)+` THEN 0 ELSE 3 END,
				       CASE WHEN i = `+fmt.Sprint(special)+` THEN 0 ELSE 12 END,
				       0,
				       CASE WHEN i = `+fmt.Sprint(special)+` THEN $2::timestamptz ELSE $2::timestamptz - interval '2 hours' END,
				       CASE WHEN i = `+fmt.Sprint(special)+` THEN ARRAY['lbl-f']::text[] ELSE ARRAY['bad-f']::text[] END,
				       ARRAY['reg-f']::text[],
				       jsonb_build_object(
				           'required_labels', CASE WHEN i = `+fmt.Sprint(special)+` THEN '["lbl-f"]'::jsonb ELSE '["bad-f"]'::jsonb END,
				           'placement_regions', '["reg-f"]'::jsonb,
				           'cpu_request', 1,
				           'memory_request', 256,
				           'compiled_job_payload', '{"effective_job":{"job":{"runtime":"native"}}}'::jsonb)
				FROM generate_series(1, $3::int) AS g(i)`, runID, now, n)
			if err != nil {
				t.Fatalf("adversarial single-end seed %d rows: %v", n, err)
			}
		},
		filter: QueuedJobFilter{
			Runtimes:     []string{"native"},
			RunnerLabels: []string{"lbl-f"},
			RunnerRegion: "reg-f",
			MaxRequested: model.ResourceCapacity{CPU: 2},
		},
		matches:     func(i int) bool { return i == special },
		rare:        true,
		wantIndexes: []string{"jobs_queued_labels_arr_idx"},
	}
}

// TestPostgresIntegrationQueuedJobsPagePlannerAdversarialMatrix runs every
// adversarial distribution in its own cloned database at 100k and 10k (plus
// 1m under the opt-in gate), asserting per permutation/size the plan shape
// and work bounds documented at the top of this file, and the cross-size
// sublinearity of the zero/rare cases.
func TestPostgresIntegrationQueuedJobsPagePlannerAdversarialMatrix(t *testing.T) {
	maxRows := 100000
	switch scale := strings.TrimSpace(os.Getenv("KIWI_TEST_PLANNER_SCALE")); scale {
	case "":
	case "1m":
		maxRows = 1000000
	default:
		t.Fatalf("KIWI_TEST_PLANNER_SCALE=%q, want empty or \"1m\"", scale)
	}
	sizes := []int{100000, 10000}
	if maxRows > 100000 {
		sizes = []int{1000000, 100000, 10000}
	}

	distributions := append(pgITAdvDistributions(), pgITAdvSingleEndDistribution())
	for _, dist := range distributions {
		t.Run(dist.name, func(t *testing.T) {
			st := pgITStore(t)
			now := time.Now().UTC().Truncate(time.Microsecond)
			runID := pgITNewID(t)
			pgITBulkInsertRuns(t, st, []model.Run{{ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour)}})

			seedStart := time.Now()
			dist.seed(t, st, runID, maxRows, now)
			t.Logf("adv=%s seeded %d rows in %s", dist.name, maxRows, time.Since(seedStart).Round(time.Millisecond))

			bySize := map[int]pgITAdvMetrics{}
			for _, size := range sizes {
				if size < maxRows {
					pgITPlannerShrink(t, st, size)
				}
				pgITPlannerPrepare(t, st)
				m := pgITAdvMeasure(t, st, dist, size, now, false)
				bySize[size] = m
				if dist.reverseAlso {
					reversed := pgITAdvMeasure(t, st, dist, size, now, true)
					pgITAdvOrderInvarianceAssert(t, dist, size, m, reversed)
				}
			}
			pgITAdvScalingAssert(t, dist, bySize)
		})
	}
}
