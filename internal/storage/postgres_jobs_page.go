package storage

// Bounded keyset pagination for queued lease candidates.
//
// The scheduler's lease walk used to materialize the ENTIRE queued set from
// Postgres (ListQueuedJobs) and sort it in Go on every /next poll, so under a
// backlog one poll's work grew with the backlog it was draining (O(R×Q) at
// R runners). QueuedJobPageStore is the optional bounded candidate-selection
// contract: the store returns the next page of queued jobs in the SAME aged
// scheduling order the scheduler's orderQueuedJobs defines — aged priority
// (priority + queue_boost, the materialized wait/10min term) DESC,
// created_at ASC, id ASC — with a keyset cursor naming the last returned job,
// so a caller can scan the queue in fixed-size pages instead of materializing
// it whole. Stores that do not implement it keep the historical ListQueuedJobs
// fallback.
//
// The ordering mirrors the Go policy exactly: floor(max(0, now -
// created_at)/600) truncated toward zero for a positive wait and clamped to
// zero otherwise, i.e. FLOOR for the positive domain with GREATEST(0, ...)
// covering clock skew and the exact-zero boundary. On the SQL path that wait
// term is the MATERIALIZED jobs.queue_boost column (migration 0039, maintained
// by PromoteQueuedJobBoosts), so ORDER BY (priority + queue_boost) is served
// directly by the jobs_queued_aged_idx expression index and the page stops
// after limit+1 index entries. id is pinned to COLLATE "C" in the cursor
// comparison (see PostgresStore.ListQueuedJobsPage) so the SQL walk matches
// Go's byte-order id tiebreak; job ids are ASCII hex, so the ORDER BY under
// the database collation agrees in practice and the pinned comparison keeps
// the boundary deterministic.
//
// The page also pushes the definitely-expired queue deadline into SQL
// (`queue_deadline IS NULL OR queue_deadline > now`): a row past its persisted
// deadline is never a lease candidate. The scheduler still applies
// QueueDeadlineFor in Go, because a legacy row can carry its deadline only in
// the compiled payload.
//
// Filter boundedness (release blocker D, migration 0041): every predicate the
// runner-coarse filter can add is backed by a jobs_queued_* index, and the
// page query is planned with the runner's ACTUAL values (queuedJobPageExecMode
// below), so the planner sees real selectivity — the list dimensions through
// the normalized required_labels/placement_regions columns (array GIN), the
// runtime and the combined-request / job-only resource expressions through
// expression indexes plus their CREATE STATISTICS objects. A rare filter
// therefore drives the plan through its own index (a bitmap scan or a
// BitmapOr for the region disjunction) and a common one falls back to the
// aged-order early stop; a zero-match filter terminates on an empty index
// scan instead of walking the queue. The planner regression matrix in
// postgres_jobs_page_planner_it_test.go pins that contract per permutation
// and size; queued_jobs_page_sql_test.go pins that the migration's indexed
// expressions are the exact ones this file renders.

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// QueuedJobCursor names the last candidate of a previous page in the aged
// scheduling order (aged priority DESC, created_at ASC, id ASC).
type QueuedJobCursor struct {
	AgedPriority int
	CreatedAt    time.Time
	ID           string
}

// QueuedJobPage is one bounded page of queued lease candidates.
type QueuedJobPage struct {
	Jobs    []model.Job
	HasMore bool
	Last    QueuedJobCursor
}

// QueuedJobFilter is the runner-coarse eligibility pushdown for one bounded
// page read. Every dimension is optional and every predicate it adds mirrors
// the scheduler's own Go decision exactly (storage.LeasePredicate /
// storage.ClaimAllowsRunner and storage.ResourceAdmission), so a filtered page
// can only skip candidates the runner would have rejected anyway.
//
// The entirely zero value (nil slices, empty region, zero capacity) is the
// documented UNCONSTRAINED filter: it applies no predicate at all and matches
// every queued job, including jobs with placement regions. That is what the
// fleet-global queue-reason annotation passes, because it needs to explain
// every queued job; the runner-derived "no region" rule below applies to any
// non-zero filter.
type QueuedJobFilter struct {
	// Runtimes, when non-nil, restricts to these runtimes. NULL/empty
	// payload runtimes are treated as "native" exactly like
	// storage.JobRuntime + storage.RuntimeAllowed do. Callers pass nil when
	// the runner is legacy-unrestricted (RuntimeAllowed with
	// !Enforced && empty caps).
	Runtimes []string
	// RunnerLabels is the runner's label key set; a job passes when every
	// RequiredLabel is present (the normalized jobs.required_labels column
	// <@ runnerLabels, served by jobs_queued_labels_arr_idx). A legacy
	// payload without the key is '{}' and passes.
	RunnerLabels []string
	// RunnerRegion is the single placement region; empty means the runner
	// has no region, so only jobs WITHOUT placement regions pass.
	RunnerRegion string
	// MaxRequested is the runner's total capacity; 0 dimensions are
	// unconstrained. A job passes when its EFFECTIVE request (job request +
	// service envelope unless IgnoreServiceEnvelope) fits every constrained
	// dimension. This mirrors storage.ResourceAdmission.EverSatisfiable.
	MaxRequested model.ResourceCapacity
	// IgnoreServiceEnvelope drops the service envelope from the effective
	// request (the runner establishes a job-scoped parent cgroup, see
	// model.CapabilityJobCgroup), exactly like
	// storage.LeaseClaim.IgnoreServiceEnvelope.
	IgnoreServiceEnvelope bool
}

// QueuedJobPageStore is the optional bounded candidate-selection contract.
// Stores that implement it let the scheduler scan the queue in bounded
// keyset pages instead of materializing it whole; stores that do not keep
// the historical ListQueuedJobs fallback.
type QueuedJobPageStore interface {
	// ListQueuedJobsPage returns at most limit queued candidates that pass
	// filter, strictly after the cursor position, in the aged scheduling
	// order. after == nil starts at the first candidate. now is the
	// scheduling clock the aged priority is computed with (the same instant
	// the caller's own ordering uses). Jobs is never nil; Last names the last
	// RETURNED candidate (zero on an empty page); HasMore reports whether a
	// candidate exists past the page.
	ListQueuedJobsPage(ctx context.Context, filter QueuedJobFilter, after *QueuedJobCursor, limit int, now time.Time) (QueuedJobPage, error)
}

// QueuedJobTraversalCursor names the last candidate of a previous traversal
// page in the IMMUTABLE creation order (created_at ASC, id ASC). Unlike
// QueuedJobCursor it carries no scheduling key that can change underneath a
// paused walk: a row's created_at and id are fixed at insert, so a job can
// never move from after this cursor to before it.
type QueuedJobTraversalCursor struct {
	CreatedAt time.Time
	ID        string
}

// QueuedJobTraversalPage is one bounded page of the immutable traversal.
type QueuedJobTraversalPage struct {
	Jobs    []model.Job
	HasMore bool
	Last    QueuedJobTraversalCursor
}

// QueuedJobTraversalStore is the optional ROUND-ROBIN traversal contract: the
// same bounded candidate selection as QueuedJobPageStore, but ordered by the
// immutable creation key (created_at ASC, id ASC) with a (CreatedAt, ID)
// keyset cursor. The aged page (QueuedJobPageStore) orders by
// priority + queue_boost, and queue_boost changes asynchronously in
// PromoteQueuedJobBoosts: a continuation cursor over that mutable key can be
// jumped by a promoted row (or skip one that lost its position), so a runner
// parked behind a long ineligible prefix could never reach rows that crossed
// its cursor boundary. The creation-order walk has no such moving boundary.
//
// The traversal applies the SAME runner-coarse QueuedJobFilter, the same
// status='queued' predicate and the same persisted queue-deadline pushdown as
// ListQueuedJobsPage, so both orders expose the same candidate set.
type QueuedJobTraversalStore interface {
	// ListQueuedJobsByCreation returns at most limit queued candidates that
	// pass filter, strictly after the cursor position, in the immutable
	// creation order. after == nil starts at the first (oldest) candidate.
	// now is the caller's scheduling clock, used for the same
	// definitely-expired queue-deadline pushdown ListQueuedJobsPage applies
	// (a legacy payload-only deadline is still evaluated in Go by the
	// caller). Jobs is never nil; Last names the last RETURNED candidate
	// (zero on an empty page); HasMore reports whether a candidate exists
	// past the page.
	ListQueuedJobsByCreation(ctx context.Context, filter QueuedJobFilter, after *QueuedJobTraversalCursor, limit int, now time.Time) (QueuedJobTraversalPage, error)
}

// Queued candidate page bounds: the scheduler's own defaults are 256/4096,
// so the store default stays well below its per-request row cap.
const (
	// QueuedJobPageDefaultLimit is the page size used when a caller passes
	// no limit.
	QueuedJobPageDefaultLimit = 256
	// QueuedJobPageMaxLimit is the hard upper bound on one page.
	QueuedJobPageMaxLimit = 1000
)

// NormalizeQueuedJobPageLimit applies the shared bound to a requested page
// size: non-positive selects QueuedJobPageDefaultLimit, above-cap clamps to
// QueuedJobPageMaxLimit.
func NormalizeQueuedJobPageLimit(limit int) int {
	if limit <= 0 {
		return QueuedJobPageDefaultLimit
	}
	if limit > QueuedJobPageMaxLimit {
		return QueuedJobPageMaxLimit
	}
	return limit
}

// queuedJobAgedOrderSQL is the exact aged scheduling key the
// jobs_queued_aged_idx expression index serves: the materialized wait term
// (queue_boost) added to the static priority. ORDER BY, the keyset cursor
// predicate and the index definition all use this same parenthesized text, so
// the planner can satisfy the ordering from the index instead of sorting.
const queuedJobAgedOrderSQL = "((priority + queue_boost))"

// queuedJobRuntimeSQLExpr is the SQL mirror of storage.JobRuntime: the
// compiled payload's effective job runtime, defaulting to "native" when the
// payload (or the key) is absent — the same "" -> native normalization
// storage.RuntimeAllowed applies.
const queuedJobRuntimeSQLExpr = `(COALESCE(NULLIF(payload->'compiled_job_payload'->'effective_job'->'job'->>'runtime',''),'native'))`

// queuedJobLabelsColumn / queuedJobRegionsColumn are the normalized TEXT[]
// columns migration 0041 materializes from the payload (nil/missing ->
// '{}'). The array GIN opclass implements the operators the page predicates
// use — <@ for labels, = and && for the region disjunction — so both
// dimensions are index-driven instead of being heap filters over whatever
// index drives the scan (the jsonb GIN indexes 0039 created could serve
// NEITHER predicate, see 0041's header). The columns are written by the
// canonical job write path from the same model fields the payload carries,
// so for every row this binary writes the payload field and the column agree.
const (
	queuedJobLabelsColumn  = `required_labels`
	queuedJobRegionsColumn = `placement_regions`
)

// queuedJobComputedBoost is the Go aged-wait term floor(max(0, wait)/10min)
// used for memory rows (and for any row whose materialized boost is unknown):
// a non-positive wait (fresh or clock-skewed) contributes nothing.
func queuedJobComputedBoost(j model.Job, now time.Time) int {
	wait := now.Sub(j.CreatedAt)
	if wait <= 0 {
		return 0
	}
	return int(wait / (10 * time.Minute))
}

// queuedJobAgedPriority is the aged-priority expression in Go: the static
// priority plus the wait term. SQL rows carry the materialized queue_boost
// column (BoostKnown true), which is authoritative; memory rows compute the
// same term on the fly.
func queuedJobAgedPriority(j model.Job, now time.Time) int {
	if j.BoostKnown {
		return j.Priority + j.QueueBoost
	}
	return j.Priority + queuedJobComputedBoost(j, now)
}

// queuedJobAfterCursor reports whether j sorts strictly after the cursor in
// the aged order (aged DESC, created_at ASC, id ASC): the in-memory
// equivalent of the SQL keyset predicate.
func queuedJobAfterCursor(j model.Job, c QueuedJobCursor, now time.Time) bool {
	ap := queuedJobAgedPriority(j, now)
	if ap != c.AgedPriority {
		return ap < c.AgedPriority
	}
	if !j.CreatedAt.Equal(c.CreatedAt) {
		return j.CreatedAt.After(c.CreatedAt)
	}
	return j.ID > c.ID
}

// sortQueuedJobsAged orders candidates by aged priority DESC, created_at
// ASC, id ASC — the total order every QueuedJobPageStore returns. The
// per-job rule (stored boost when BoostKnown, computed wait otherwise) is the
// same rule the SQL ORDER BY applies.
func sortQueuedJobsAged(jobs []model.Job, now time.Time) {
	sort.Slice(jobs, func(i, j int) bool {
		pi, pj := queuedJobAgedPriority(jobs[i], now), queuedJobAgedPriority(jobs[j], now)
		if pi != pj {
			return pi > pj
		}
		if !jobs[i].CreatedAt.Equal(jobs[j].CreatedAt) {
			return jobs[i].CreatedAt.Before(jobs[j].CreatedAt)
		}
		return jobs[i].ID < jobs[j].ID
	})
}

// queuedJobAfterCreationCursor reports whether j sorts strictly after the
// cursor in the immutable creation order (created_at ASC, id ASC): the
// in-memory equivalent of the SQL keyset predicate.
func queuedJobAfterCreationCursor(j model.Job, c QueuedJobTraversalCursor) bool {
	if !j.CreatedAt.Equal(c.CreatedAt) {
		return j.CreatedAt.After(c.CreatedAt)
	}
	return j.ID > c.ID
}

// sortQueuedJobsByCreation orders candidates by the immutable creation key
// (created_at ASC, id ASC) — the total order every QueuedJobTraversalStore
// returns.
func sortQueuedJobsByCreation(jobs []model.Job) {
	sort.Slice(jobs, func(i, j int) bool {
		if !jobs[i].CreatedAt.Equal(jobs[j].CreatedAt) {
			return jobs[i].CreatedAt.Before(jobs[j].CreatedAt)
		}
		return jobs[i].ID < jobs[j].ID
	})
}

// queuedJobFilterUnconstrained reports whether f carries no restriction at
// all. The entirely zero filter is the documented unconstrained value (the
// queue-reason annotation passes it and must keep seeing every queued job,
// including jobs with placement regions), so it applies no predicate. Any
// non-zero filter applies the runner-derived region rule, where an empty
// RunnerRegion means the runner has no region and only region-less jobs pass.
func queuedJobFilterUnconstrained(f QueuedJobFilter) bool {
	return f.Runtimes == nil && f.RunnerLabels == nil && f.RunnerRegion == "" &&
		f.MaxRequested == (model.ResourceCapacity{}) && !f.IgnoreServiceEnvelope
}

// queuedJobNumberSQL renders a SAFE numeric read of one request field: a
// jsonb number is cast through numeric (no float range error), while a
// missing key, a non-number JSON value or any malformed shape contributes 0.
// A malformed row can therefore never abort the page query.
func queuedJobNumberSQL(jsonbExpr, textExpr string) string {
	return `(CASE WHEN jsonb_typeof(` + jsonbExpr + `) = 'number' THEN (` + textExpr + `)::numeric ELSE 0 END)`
}

// queuedJobResourceDimension names one resource dimension: the payload paths
// of the job's own request and the service envelope request, the dimension's
// suffix in the migration index/statistics names, and the capacity renderer
// used to bind the filter's bound. The list is the SINGLE source of truth for
// both queuedJobResourcePredicateSQL and the migration-expression parity
// test: the migration 0041 index/statistics expressions are generated from
// queuedJobNumberSQL with these same paths, so a dimension can never drift
// between the query and the schema it depends on.
type queuedJobResourceDimension struct {
	jobJSON, jobText string
	envJSON, envText string
	name             string
	cap              func(model.ResourceCapacity) string
	constrained      func(model.ResourceCapacity) bool
}

var queuedJobResourceDimensions = []queuedJobResourceDimension{
	{"payload->'cpu_request'", "payload->>'cpu_request'",
		"payload->'service_envelope_request'->'cpu'", "payload->'service_envelope_request'->>'cpu'",
		"cpu",
		func(c model.ResourceCapacity) string { return strconv.FormatFloat(c.CPU, 'f', -1, 64) },
		func(c model.ResourceCapacity) bool { return c.CPU > 0 }},
	{"payload->'memory_request'", "payload->>'memory_request'",
		"payload->'service_envelope_request'->'memory'", "payload->'service_envelope_request'->>'memory'",
		"memory",
		func(c model.ResourceCapacity) string { return strconv.FormatInt(c.Memory, 10) },
		func(c model.ResourceCapacity) bool { return c.Memory > 0 }},
	{"payload->'disk_request'", "payload->>'disk_request'",
		"payload->'service_envelope_request'->'disk'", "payload->'service_envelope_request'->>'disk'",
		"disk",
		func(c model.ResourceCapacity) string { return strconv.FormatInt(c.Disk, 10) },
		func(c model.ResourceCapacity) bool { return c.Disk > 0 }},
	{"payload->'pids_request'", "payload->>'pids_request'",
		"payload->'service_envelope_request'->'pids'", "payload->'service_envelope_request'->>'pids'",
		"pids",
		func(c model.ResourceCapacity) string { return strconv.Itoa(c.PIDs) },
		func(c model.ResourceCapacity) bool { return c.PIDs > 0 }},
}

// queuedJobResourcePredicateSQL applies the per-dimension capacity predicate
// for every dimension MaxRequested constrains (zero = unconstrained), summing
// the job field and — unless IgnoreServiceEnvelope — the service envelope
// field, exactly like model.AddResourceCapacity + ResourceAdmission.
func queuedJobResourcePredicateSQL(filter QueuedJobFilter, args *[]any) string {
	addArg := func(v any) string {
		*args = append(*args, v)
		return "$" + strconv.Itoa(len(*args))
	}
	out := ""
	for _, d := range queuedJobResourceDimensions {
		if !d.constrained(filter.MaxRequested) {
			continue
		}
		expr := queuedJobNumberSQL(d.jobJSON, d.jobText)
		if !filter.IgnoreServiceEnvelope {
			expr = `(` + expr + ` + ` + queuedJobNumberSQL(d.envJSON, d.envText) + `)`
		}
		out += ` AND ` + expr + ` <= ` + addArg(d.cap(filter.MaxRequested)) + `::numeric`
	}
	return out
}

// queuedJobFilterPredicateSQL renders the coarse-eligibility SQL for f and
// appends its bound parameters to args. It returns "" for the unconstrained
// filter.
func queuedJobFilterPredicateSQL(filter QueuedJobFilter, args *[]any) string {
	if queuedJobFilterUnconstrained(filter) {
		return ""
	}
	addArg := func(v any) string {
		*args = append(*args, v)
		return "$" + strconv.Itoa(len(*args))
	}
	out := ""
	if filter.Runtimes != nil {
		out += ` AND ` + queuedJobRuntimeSQLExpr + ` = ANY(` + addArg(filter.Runtimes) + `::text[])`
	}
	if filter.RunnerLabels != nil {
		out += ` AND ` + queuedJobLabelsColumn + ` <@ ` + addArg(filter.RunnerLabels) + `::text[]`
	}
	if filter.RunnerRegion == "" {
		out += ` AND ` + queuedJobRegionsColumn + ` = '{}'::text[]`
	} else {
		// The two arms are indexable by the same array GIN index (= '{}' and
		// && $n), so the planner can form a BitmapOr and never needs a heap
		// filter for the region dimension.
		out += ` AND (` + queuedJobRegionsColumn + ` = '{}'::text[] OR ` + queuedJobRegionsColumn + ` && ` + addArg([]string{filter.RunnerRegion}) + `::text[])`
	}
	out += queuedJobResourcePredicateSQL(filter, args)
	return out
}

// queuedJobPageExecMode forces the page queries to be planned with the bound
// filter values instead of reusing a generic plan. This is load-bearing for
// boundedness: the resource/runtime predicates are expression indexes whose
// clause selectivity is only useful when PostgreSQL sees the actual value
// (its extended statistics estimate the request/capacity clause, the array
// statistics estimate the label/region clauses), while a generic plan treats
// every $n as unknown and falls back to defaults that can rate a COMMON
// value as selective — the planner then drives the scan through an index
// that actually matches the whole queue. QueryExecModeExec sends an unnamed
// statement and plans it on every execution, so a poll costs one extra
// parse/plan (bounded by query complexity, not queue size) and the plan
// always reflects the runner's real filter values.
const queuedJobPageExecMode = pgx.QueryExecModeExec

// queuedJobsPageQuery builds the page SQL and its arguments: the shared
// jobCols projection, the persisted-deadline and filter predicates, the exact
// aged ORDER BY the jobs_queued_aged_idx expression index serves, the keyset
// cursor predicate and LIMIT limit+1 (so HasMore is exact). It is used by
// ListQueuedJobsPage and by the EXPLAIN integration tests.
func queuedJobsPageQuery(filter QueuedJobFilter, after *QueuedJobCursor, limit int, now time.Time) (string, []any) {
	args := []any{now}
	where := ` WHERE status='queued' AND (queue_deadline IS NULL OR queue_deadline > $1::timestamptz)`
	where += queuedJobFilterPredicateSQL(filter, &args)
	if after != nil {
		args = append(args, after.AgedPriority, after.CreatedAt, after.ID)
		p := len(args) - 2
		where += ` AND (` + queuedJobAgedOrderSQL + ` < $` + strconv.Itoa(p) + `::int OR (` + queuedJobAgedOrderSQL +
			` = $` + strconv.Itoa(p) + `::int AND (created_at > $` + strconv.Itoa(p+1) + `::timestamptz OR (created_at = $` +
			strconv.Itoa(p+1) + `::timestamptz AND id > $` + strconv.Itoa(p+2) + `::text COLLATE "C"))))`
	}
	args = append(args, limit+1)
	query := `SELECT ` + jobCols + ` FROM jobs` + where +
		` ORDER BY ` + queuedJobAgedOrderSQL + ` DESC, created_at ASC, id ASC LIMIT $` + strconv.Itoa(len(args))
	return query, args
}

// queuedJobsTraversalQuery builds the immutable-creation-order page SQL and
// its arguments: the SAME jobCols projection, status/deadline and
// runner-coarse filter predicates as queuedJobsPageQuery, ordered by
// created_at ASC, id ASC with a (created_at, id) keyset cursor and LIMIT
// limit+1 (so HasMore is exact). jobs_queued_boost_sweep_idx
// ON (created_at, queue_boost, id) WHERE status='queued' stores created_at
// first, so the page walk can stop after limit+1 index entries instead of
// sorting the queued population.
func queuedJobsTraversalQuery(filter QueuedJobFilter, after *QueuedJobTraversalCursor, limit int, now time.Time) (string, []any) {
	args := []any{now}
	where := ` WHERE status='queued' AND (queue_deadline IS NULL OR queue_deadline > $1::timestamptz)`
	where += queuedJobFilterPredicateSQL(filter, &args)
	if after != nil {
		args = append(args, after.CreatedAt, after.ID)
		p := len(args) - 1
		where += ` AND (created_at > $` + strconv.Itoa(p) + `::timestamptz OR (created_at = $` + strconv.Itoa(p) +
			`::timestamptz AND id > $` + strconv.Itoa(p+1) + `::text COLLATE "C"))`
	}
	args = append(args, limit+1)
	query := `SELECT ` + jobCols + ` FROM jobs` + where +
		` ORDER BY created_at ASC, id ASC LIMIT $` + strconv.Itoa(len(args))
	return query, args
}

// ListQueuedJobsByCreation implements QueuedJobTraversalStore for the durable
// store: one index-backed keyset read in the immutable creation order, with
// the same filter/deadline predicates as ListQueuedJobsPage and LIMIT limit+1
// so HasMore is exact. jobCols is shared with ListQueuedJobs, so a traversal
// candidate decodes identically to an aged-page candidate.
func (s *PostgresStore) ListQueuedJobsByCreation(ctx context.Context, filter QueuedJobFilter, after *QueuedJobTraversalCursor, limit int, now time.Time) (QueuedJobTraversalPage, error) {
	limit = NormalizeQueuedJobPageLimit(limit)
	query, args := queuedJobsTraversalQuery(filter, after, limit, now)
	rows, err := s.pool.Query(ctx, query, append([]any{queuedJobPageExecMode}, args...)...)
	if err != nil {
		return QueuedJobTraversalPage{}, err
	}
	defer rows.Close()
	out := []model.Job{}
	for rows.Next() {
		js := jobScanner{}
		if err := rows.Scan(jobTargets(&js)...); err != nil {
			return QueuedJobTraversalPage{}, err
		}
		j, err := js.job()
		if err != nil {
			return QueuedJobTraversalPage{}, err
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return QueuedJobTraversalPage{}, err
	}
	page := QueuedJobTraversalPage{Jobs: out}
	if len(out) > limit {
		page.Jobs = out[:limit]
		page.HasMore = true
	}
	if len(page.Jobs) > 0 {
		last := page.Jobs[len(page.Jobs)-1]
		page.Last = QueuedJobTraversalCursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return page, nil
}

// ListQueuedJobsPage implements QueuedJobPageStore for the durable store.
// One index-backed keyset read: the aged ORDER BY with the row-value cursor
// predicate and LIMIT limit+1 so HasMore is exact. jobCols is shared with
// ListQueuedJobs, so a paged candidate decodes identically to a non-paged
// one (no second payload-decoding path).
//
// The deadline pushdown and the cursor id COLLATE "C" are documented in the
// file comment.
func (s *PostgresStore) ListQueuedJobsPage(ctx context.Context, filter QueuedJobFilter, after *QueuedJobCursor, limit int, now time.Time) (QueuedJobPage, error) {
	limit = NormalizeQueuedJobPageLimit(limit)
	query, args := queuedJobsPageQuery(filter, after, limit, now)
	rows, err := s.pool.Query(ctx, query, append([]any{queuedJobPageExecMode}, args...)...)
	if err != nil {
		return QueuedJobPage{}, err
	}
	defer rows.Close()
	out := []model.Job{}
	for rows.Next() {
		js := jobScanner{}
		if err := rows.Scan(jobTargets(&js)...); err != nil {
			return QueuedJobPage{}, err
		}
		j, err := js.job()
		if err != nil {
			return QueuedJobPage{}, err
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return QueuedJobPage{}, err
	}
	page := QueuedJobPage{Jobs: out}
	if len(out) > limit {
		page.Jobs = out[:limit]
		page.HasMore = true
	}
	if len(page.Jobs) > 0 {
		last := page.Jobs[len(page.Jobs)-1]
		page.Last = QueuedJobCursor{
			AgedPriority: queuedJobAgedPriority(last, now),
			CreatedAt:    last.CreatedAt,
			ID:           last.ID,
		}
	}
	return page, nil
}

// QueuedJobMatchesFilter is the in-memory mirror of the SQL filter predicate
// set: the same runtime/label/region/capacity decisions, including the
// unconstrained zero-filter rule, the region-less rule for an empty
// RunnerRegion and the IgnoreServiceEnvelope aggregation. It is exported so
// the scheduler's fallback path and the store fixtures share ONE definition
// of the coarse eligibility pushdown with memStore.ListQueuedJobsPage.
func QueuedJobMatchesFilter(j model.Job, filter QueuedJobFilter) bool {
	if queuedJobFilterUnconstrained(filter) {
		return true
	}
	if filter.Runtimes != nil {
		runtime := JobRuntime(j)
		if runtime == "" {
			// NULL/empty payload runtime is "native", exactly like the SQL
			// COALESCE(NULLIF(...,''),'native') expression.
			runtime = "native"
		}
		if !containsString(filter.Runtimes, runtime) {
			return false
		}
	}
	if filter.RunnerLabels != nil {
		have := make(map[string]bool, len(filter.RunnerLabels))
		for _, label := range filter.RunnerLabels {
			have[label] = true
		}
		for _, need := range j.RequiredLabels {
			if !have[need] {
				return false
			}
		}
	}
	if filter.RunnerRegion == "" {
		if len(j.PlacementRegions) != 0 {
			return false
		}
	} else if len(j.PlacementRegions) != 0 && !containsString(j.PlacementRegions, filter.RunnerRegion) {
		return false
	}
	requested := j.ResourceRequest()
	if !filter.IgnoreServiceEnvelope {
		requested = model.AddResourceCapacity(requested, j.ServiceEnvelopeRequest)
	}
	return !overCapacity(filter.MaxRequested, requested)
}

// ListQueuedJobsPage implements QueuedJobPageStore over the in-memory job
// map: the same filter pushdown the SQL page applies (QueuedJobMatchesFilter),
// the same aged order (priority + wait/10min DESC, created_at ASC, id ASC),
// the same persisted-deadline pushdown the SQL page applies (a row carrying an
// elapsed queue_deadline column is never a candidate; the scheduler still
// evaluates payload-derived deadlines in Go), and the same keyset cursor
// semantics. Every returned copy carries the computed QueueBoost with
// BoostKnown=true, so Last and the aged order agree with the SQL path's
// materialized column. The map under m.mu is a complete view, so paging is
// deterministic.
func (m *memStore) ListQueuedJobsPage(ctx context.Context, filter QueuedJobFilter, after *QueuedJobCursor, limit int, now time.Time) (QueuedJobPage, error) {
	limit = NormalizeQueuedJobPageLimit(limit)
	m.mu.Lock()
	defer m.mu.Unlock()
	eligible := make([]model.Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		if j.Status != model.StatusQueued {
			continue
		}
		if j.QueueDeadline != nil && !j.QueueDeadline.After(now) {
			continue
		}
		if !QueuedJobMatchesFilter(j, filter) {
			continue
		}
		if after != nil && !queuedJobAfterCursor(j, *after, now) {
			continue
		}
		// Materialize the wait term on the returned copy so Last, parity and
		// the ordering rule are identical to the SQL path's stored column.
		j.QueueBoost = queuedJobComputedBoost(j, now)
		j.BoostKnown = true
		eligible = append(eligible, j)
	}
	sortQueuedJobsAged(eligible, now)
	page := QueuedJobPage{Jobs: eligible}
	if len(eligible) > limit {
		page.Jobs = eligible[:limit]
		page.HasMore = true
	}
	if len(page.Jobs) > 0 {
		last := page.Jobs[len(page.Jobs)-1]
		page.Last = QueuedJobCursor{
			AgedPriority: queuedJobAgedPriority(last, now),
			CreatedAt:    last.CreatedAt,
			ID:           last.ID,
		}
	}
	return page, nil
}

// ListQueuedJobsByCreation implements QueuedJobTraversalStore over the
// in-memory job map: the same status/filter/deadline predicates and materialized
// QueueBoost the aged page applies (so both orders expose the same candidate
// set), ordered by the immutable creation key (created_at ASC, id ASC) with
// the same keyset cursor semantics. The map under m.mu is a complete view, so
// paging is deterministic.
func (m *memStore) ListQueuedJobsByCreation(ctx context.Context, filter QueuedJobFilter, after *QueuedJobTraversalCursor, limit int, now time.Time) (QueuedJobTraversalPage, error) {
	limit = NormalizeQueuedJobPageLimit(limit)
	m.mu.Lock()
	defer m.mu.Unlock()
	eligible := make([]model.Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		if j.Status != model.StatusQueued {
			continue
		}
		if j.QueueDeadline != nil && !j.QueueDeadline.After(now) {
			continue
		}
		if !QueuedJobMatchesFilter(j, filter) {
			continue
		}
		if after != nil && !queuedJobAfterCreationCursor(j, *after) {
			continue
		}
		j.QueueBoost = queuedJobComputedBoost(j, now)
		j.BoostKnown = true
		eligible = append(eligible, j)
	}
	sortQueuedJobsByCreation(eligible)
	page := QueuedJobTraversalPage{Jobs: eligible}
	if len(eligible) > limit {
		page.Jobs = eligible[:limit]
		page.HasMore = true
	}
	if len(page.Jobs) > 0 {
		last := page.Jobs[len(page.Jobs)-1]
		page.Last = QueuedJobTraversalCursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return page, nil
}

// PromoteQueuedJobBoosts implements QueuedBoostPromoter: it recomputes the
// materialized aged-wait term queue_boost for the queued rows whose stored
// value is stale, in bounded ctid batches, and returns how many rows it
// promoted. The recomputation is ABSOLUTE (from created_at and the caller's
// now, never from the current stored value), so it is idempotent: a second
// call over the same rows promotes nothing, and any replica may run it. Each
// iteration updates at most `want` = batchLimit - promoted rows inside a
// schema-fenced transaction using the jobs_queued_boost_sweep_idx order
// (created_at, queue_boost, id), then stops early once a batch is not filled.
func (s *PostgresStore) PromoteQueuedJobBoosts(ctx context.Context, now time.Time, batchLimit int) (int64, error) {
	if batchLimit <= 0 {
		return 0, nil
	}
	const promoteSQL = `
		UPDATE jobs
		SET queue_boost = GREATEST(0, FLOOR(EXTRACT(EPOCH FROM ($1::timestamptz - created_at)) / 600))::int
		WHERE ctid IN (
			SELECT ctid FROM jobs
			WHERE status='queued'
			  AND queue_boost <> GREATEST(0, FLOOR(EXTRACT(EPOCH FROM ($1::timestamptz - created_at)) / 600))::int
			ORDER BY created_at ASC, queue_boost ASC, id ASC
			LIMIT $2
		)`
	var total int64
	for total < int64(batchLimit) {
		want := int64(batchLimit) - total
		var promoted int64
		err := s.withSchemaCompatibleTx(ctx, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, promoteSQL, now, want)
			if err != nil {
				return err
			}
			promoted = tag.RowsAffected()
			return nil
		})
		if err != nil {
			return total, err
		}
		total += promoted
		if promoted < want {
			break
		}
	}
	return total, nil
}

var _ QueuedJobPageStore = (*PostgresStore)(nil)
var _ QueuedJobPageStore = (*memStore)(nil)
var _ QueuedJobTraversalStore = (*PostgresStore)(nil)
var _ QueuedJobTraversalStore = (*memStore)(nil)
var _ QueuedBoostPromoter = (*PostgresStore)(nil)
