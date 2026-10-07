package storage

// Unit contract tests (no PostgreSQL) binding the queued page query's SQL to
// the migration 0041/0042 schema objects it depends on. The migration indexes
// must carry the query's EXACT expressions: the resource index/statistics
// expressions are generated here from the same queuedJobNumberSQL renderer
// the query uses, and the traversal ORDER BY is compared against the
// dedicated migration 0042 index definition, so editing the query without
// editing the migration (or the reverse) fails before any integration run.

import (
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// queuedResourceDimensionExpression is the combined job+envelope expression
// the query renders for one constrained dimension.
func queuedResourceDimensionExpression(d queuedJobResourceDimension) string {
	return `(` + queuedJobNumberSQL(d.jobJSON, d.jobText) + ` + ` + queuedJobNumberSQL(d.envJSON, d.envText) + `)`
}

func TestQueuedJobsPagePredicateSQLShape(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	filter := QueuedJobFilter{
		Runtimes:     []string{"native"},
		RunnerLabels: []string{"linux", "x64"},
		RunnerRegion: "eu-west",
		MaxRequested: model.ResourceCapacity{CPU: 2, Memory: 2048, Disk: 10, PIDs: 64},
	}
	query, _ := queuedJobsPageQuery(filter, nil, 32, now)

	for _, want := range []string{
		queuedJobRuntimeSQLExpr + ` = ANY($`,
		`required_labels <@ $`,
		`placement_regions = '{}'::text[] OR placement_regions && $`,
	} {
		if !strings.Contains(query, want) {
			t.Errorf("constrained query missing %q:\n%s", want, query)
		}
	}
	if strings.Contains(query, "payload->'required_labels'") || strings.Contains(query, "payload->'placement_regions'") {
		t.Errorf("query still filters the list dimensions through the payload jsonb:\n%s", query)
	}
	for _, d := range queuedJobResourceDimensions {
		want := ` AND ` + queuedResourceDimensionExpression(d) + ` <= $`
		if !strings.Contains(query, want) {
			t.Errorf("constrained query missing %s predicate %q:\n%s", d.name, want, query)
		}
	}

	// An empty RunnerRegion applies only the region-less arm when another
	// dimension makes the filter constrained; nil RunnerLabels adds no label
	// predicate; IgnoreServiceEnvelope drops the envelope sum.
	regionless := QueuedJobFilter{Runtimes: []string{"native"}}
	q, _ := queuedJobsPageQuery(regionless, nil, 32, now)
	if !strings.Contains(q, `placement_regions = '{}'::text[]`) || strings.Contains(q, "placement_regions &&") {
		t.Errorf("empty-region query lost the region-less-only predicate:\n%s", q)
	}
	q, _ = queuedJobsPageQuery(QueuedJobFilter{Runtimes: []string{"native"}}, nil, 32, now)
	if strings.Contains(q, "required_labels") {
		t.Errorf("nil RunnerLabels must add no label predicate:\n%s", q)
	}
	own := QueuedJobFilter{RunnerRegion: "eu-west", MaxRequested: model.ResourceCapacity{CPU: 2}, IgnoreServiceEnvelope: true}
	q, _ = queuedJobsPageQuery(own, nil, 32, now)
	wantCPU := ` AND ` + queuedJobNumberSQL("payload->'cpu_request'", "payload->>'cpu_request'") + ` <= $`
	if !strings.Contains(q, wantCPU) {
		t.Errorf("IgnoreServiceEnvelope query must bound the job's own request %q:\n%s", wantCPU, q)
	}
	if strings.Contains(q, "service_envelope_request") {
		t.Errorf("IgnoreServiceEnvelope query must not sum the envelope:\n%s", q)
	}
	if !strings.Contains(q, `placement_regions = '{}'::text[] OR placement_regions &&`) {
		t.Errorf("non-empty RunnerRegion must apply the OR of the region-less and overlap arms:\n%s", q)
	}
}

func TestJobNormalizedFilterLists(t *testing.T) {
	labels, regions := jobNormalizedFilterLists(model.Job{})
	if labels == nil || regions == nil || len(labels) != 0 || len(regions) != 0 {
		t.Fatalf("nil lists normalize to %v/%v, want empty non-nil arrays", labels, regions)
	}
	in := model.Job{RequiredLabels: []string{"a"}, PlacementRegions: []string{"b"}}
	labels, regions = jobNormalizedFilterLists(in)
	if len(labels) != 1 || labels[0] != "a" || len(regions) != 1 || regions[0] != "b" {
		t.Fatalf("lists normalize to %v/%v, want passthrough", labels, regions)
	}
}

// normalizeSQLSpace collapses whitespace runs so a migration statement can be
// matched across its line wrapping.
func normalizeSQLSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func TestQueuedJobsPageMigrationIndexExpressionParity(t *testing.T) {
	raw41, err := migrations.FS.ReadFile("0041_queued_filter_normalization.sql")
	if err != nil {
		t.Fatalf("read migration 0041: %v", err)
	}
	m41 := normalizeSQLSpace(string(raw41))
	raw39, err := migrations.FS.ReadFile("0039_queued_scheduling_key.sql")
	if err != nil {
		t.Fatalf("read migration 0039: %v", err)
	}
	m39 := normalizeSQLSpace(string(raw39))

	// The runtime index lives in 0039 and its statistics object in 0041,
	// both on the exact expression the query compares.
	if want := normalizeSQLSpace("CREATE INDEX IF NOT EXISTS jobs_queued_runtime_idx ON jobs (" + queuedJobRuntimeSQLExpr + ")"); !strings.Contains(m39, want) {
		t.Errorf("0039 runtime index must be on the query's runtime expression:\nwant %s", want)
	}
	if want := normalizeSQLSpace("CREATE STATISTICS jobs_queued_runtime_stats ON (" + queuedJobRuntimeSQLExpr + ") FROM jobs"); !strings.Contains(m41, want) {
		t.Errorf("0041 runtime statistics must be on the query's runtime expression:\nwant %s", want)
	}

	// The list dimensions must be the normalized columns, served by array
	// GIN indexes with the operators the query uses.
	for _, want := range []string{
		"CREATE INDEX IF NOT EXISTS jobs_queued_labels_arr_idx ON jobs USING gin (required_labels) WHERE status='queued'",
		"CREATE INDEX IF NOT EXISTS jobs_queued_regions_arr_idx ON jobs USING gin (placement_regions) WHERE status='queued'",
		"DROP INDEX IF EXISTS jobs_queued_labels_idx",
		"DROP INDEX IF EXISTS jobs_queued_regions_idx",
	} {
		if !strings.Contains(m41, normalizeSQLSpace(want)) {
			t.Errorf("0041 missing %q", want)
		}
	}

	// Every resource dimension's combined-expression index and statistics
	// object, plus the job-only (_own) pair IgnoreServiceEnvelope queries
	// use, must be on the exact expressions the query constrains.
	for _, d := range queuedJobResourceDimensions {
		expr := queuedResourceDimensionExpression(d)
		if want := normalizeSQLSpace("CREATE INDEX IF NOT EXISTS jobs_queued_" + d.name + "_idx ON jobs (" + expr + ") WHERE status='queued'"); !strings.Contains(m41, want) {
			t.Errorf("0041 %s index must be on the query's expression:\nwant %s", d.name, want)
		}
		if want := normalizeSQLSpace("CREATE STATISTICS jobs_queued_" + d.name + "_stats ON (" + expr + ") FROM jobs"); !strings.Contains(m41, want) {
			t.Errorf("0041 %s statistics must be on the query's expression:\nwant %s", d.name, want)
		}
		own := queuedJobNumberSQL(d.jobJSON, d.jobText)
		if want := normalizeSQLSpace("CREATE INDEX IF NOT EXISTS jobs_queued_" + d.name + "_own_idx ON jobs (" + own + ") WHERE status='queued'"); !strings.Contains(m41, want) {
			t.Errorf("0041 %s own index must be on the query's job-only expression:\nwant %s", d.name, want)
		}
		if want := normalizeSQLSpace("CREATE STATISTICS jobs_queued_" + d.name + "_own_stats ON (" + own + ") FROM jobs"); !strings.Contains(m41, want) {
			t.Errorf("0041 %s own statistics must be on the query's job-only expression:\nwant %s", d.name, want)
		}
	}

	// The backfills guard the set-returning cast so a malformed payload can
	// not abort the migration.
	for _, want := range []string{
		"jsonb_typeof(payload->'required_labels') = 'array'",
		"jsonb_typeof(payload->'placement_regions') = 'array'",
	} {
		if !strings.Contains(m41, want) {
			t.Errorf("0041 backfill guard missing %q", want)
		}
	}
}

// TestQueuedJobsTraversalIndexOrderParity pins the immutable traversal's SQL
// to its dedicated migration 0042 index. The traversal query ORDER BY and the
// index key are both rendered from queuedJobTraversalOrderSQL, and the
// migration text is compared against that same constant, so a query that
// falls back to the promotion sweep's (created_at, queue_boost, id) ordering
// (which would force an Incremental Sort inside every created_at tie group)
// fails this unit contract before the database is involved.
func TestQueuedJobsTraversalIndexOrderParity(t *testing.T) {
	raw42, err := migrations.FS.ReadFile("0042_queued_traversal_index.sql")
	if err != nil {
		t.Fatalf("read migration 0042: %v", err)
	}
	m42 := normalizeSQLSpace(string(raw42))

	wantIndex := normalizeSQLSpace("CREATE INDEX IF NOT EXISTS " + queuedJobTraversalIndexName +
		" ON jobs (" + queuedJobTraversalOrderSQL + ") WHERE status='queued'")
	if !strings.Contains(m42, wantIndex) {
		t.Errorf("migration 0042 must define the traversal index on the query's exact ordering:\nwant %s", wantIndex)
	}
	// The promotion sweep index stays owned by the promotion order; 0042 must
	// not redefine it as a traversal index.
	if strings.Contains(normalizeSQLSpace(removeSQLComments(string(raw42))), "CREATE INDEX IF NOT EXISTS jobs_queued_boost_sweep_idx") {
		t.Errorf("0042 must not (re)create the promotion sweep index")
	}

	query, _ := queuedJobsTraversalQuery(QueuedJobFilter{}, nil, 256, time.Now().UTC())
	if !strings.Contains(query, " ORDER BY "+queuedJobTraversalOrderSQL+" LIMIT ") {
		t.Errorf("traversal query must order by the dedicated index key %q:\n%s", queuedJobTraversalOrderSQL, query)
	}
}

// removeSQLComments strips whole-line SQL comments so migration comments can
// be excluded from statement-shape assertions.
func removeSQLComments(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
