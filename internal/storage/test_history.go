package storage

// Incremental, repository-scoped test-history storage (migration 0026).
//
// The pre-0026 path rebuilt the whole test history from every report on every
// upload and served test-intelligence by materializing every report and
// resolving its run in Go. This file implements the replacement contract
// documented on TestHistoryAggregateStore:
//
//   - InsertTestReportWithHistory is ONE transaction: report rows + case rows
//     + the per-(repo, suite, class, name) aggregate upserts for exactly the
//     report's cases + the repository version bump.
//   - LoadRepoTestHistory / TestReportTotals / FlakyTestNames read only the
//     requested canonical repository (through the canonical run-identity
//     index added by 0027, which matches these queries' policy-first
//     canonical expression exactly).
//   - RebuildRepoTestHistory is the explicit bounded repair operation.
//
// The aggregate rows serialize to the SAME JSON shape the legacy
// test_history cache and the fs history file use, so existing readers
// (historyFromStats / testintel.LoadHistory) need no change.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

var _ TestHistoryAggregateStore = (*PostgresStore)(nil)

// testHistoryAggregateKey is the deterministic in-memory key for one
// aggregate row while rebuilding. It uses the same structured encoding as the
// persisted stats (see testintel.EncodeHistoryKey) with an empty repository,
// so the rebuild map can never merge two distinct test identities whose
// fields contain the old in-band separator.
func testHistoryAggregateKey(suite, class, name string) string {
	return testintel.EncodeHistoryKey("", suite, class, name)
}

// EncodeTestHistoryStats renders aggregate rows as the stats JSON: a map
// keyed by the canonical v2 history key (testintel.EncodeHistoryKey, the
// unambiguous structured form) whose values carry the same JSON tags as
// testintel.TestStat. It is the single encoder shared by the SQL load path
// and the in-memory stores, so every reader sees one shape and a part
// containing "|" can never be mis-split. Legacy keys are still READ
// (testintel.LoadHistory decodes both forms); new writes are v2 only.
func EncodeTestHistoryStats(rows []TestHistoryAggregate) ([]byte, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	stats := make(map[string]testintel.TestStat, len(rows))
	for _, r := range rows {
		stats[testintel.EncodeHistoryKey(r.RepoID, r.Suite, r.Class, r.Name)] = testintel.TestStat{
			Runs:        int(r.Runs),
			Passes:      int(r.Passes),
			Fails:       int(r.Fails),
			EWMA:        r.EWMA,
			LastFailure: r.LastFailure,
			Outcomes:    append([]bool(nil), r.Outcomes...),
			FlakeProb:   r.FlakeProb,
		}
	}
	return json.Marshal(stats)
}

// insertTestReportRowsTx inserts the report row and its case rows inside the
// caller's transaction. It is the single report-insert implementation shared
// by InsertTestReport and InsertTestReportWithHistory.
func insertTestReportRowsTx(ctx context.Context, tx pgx.Tx, rep model.TestReport) error {
	payload, err := jsonMarshal(rep)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO test_results (id, run_id, job_id, job_key, path, tests, failures, duration, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		rep.ID, rep.RunID, nullText(rep.JobID), nullText(rep.JobKey), nullText(rep.Path), rep.Tests, rep.Failures, rep.Duration, rep.CreatedAt, payload); err != nil {
		return err
	}
	for _, c := range rep.Cases {
		caseID, err := newID()
		if err != nil {
			return err
		}
		cp, err := jsonMarshal(c)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO test_cases (id, report_id, name, class, duration, passed, message, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			caseID, rep.ID, c.Name, nullText(c.Class), c.Duration, c.Passed, nullText(c.Message), cp); err != nil {
			return err
		}
	}
	return nil
}

// foldTestHistoryTx upserts ONE test outcome into the repository's aggregate
// row inside the caller's transaction. The row is created if absent and
// locked (FOR UPDATE) before the read-modify-write, so concurrent uploads of
// the same test name serialize on the row instead of losing an update. All
// work is proportional to the single key; total history size never matters.
func foldTestHistoryTx(ctx context.Context, tx pgx.Tx, repoID string, e TestHistoryEntry) error {
	if _, err := tx.Exec(ctx, `INSERT INTO test_history_aggregates (repo_id, suite, test_class, test_name) VALUES ($1, $2, $3, $4) ON CONFLICT (repo_id, suite, test_class, test_name) DO NOTHING`,
		repoID, e.Suite, e.Class, e.Name); err != nil {
		return err
	}
	var (
		row       = TestHistoryAggregate{RepoID: repoID, Suite: e.Suite, Class: e.Class, Name: e.Name}
		outcomes  []byte
		lastFail  *time.Time
		flakeprob float64
	)
	if err := tx.QueryRow(ctx, `SELECT runs, passes, fails, ewma, last_failure, outcomes, flake_prob FROM test_history_aggregates WHERE repo_id=$1 AND suite=$2 AND test_class=$3 AND test_name=$4 FOR UPDATE`,
		repoID, e.Suite, e.Class, e.Name).Scan(&row.Runs, &row.Passes, &row.Fails, &row.EWMA, &lastFail, &outcomes, &flakeprob); err != nil {
		return err
	}
	row.LastFailure = lastFail
	row.FlakeProb = flakeprob
	if len(outcomes) > 0 {
		if err := json.Unmarshal(outcomes, &row.Outcomes); err != nil {
			return err
		}
	}
	row = FoldTestHistoryAggregate(row, e)
	encoded, err := json.Marshal(row.Outcomes)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE test_history_aggregates SET runs=$5, passes=$6, fails=$7, ewma=$8, last_failure=$9, outcomes=$10::jsonb, flake_prob=$11, updated_at=now() WHERE repo_id=$1 AND suite=$2 AND test_class=$3 AND test_name=$4`,
		repoID, e.Suite, e.Class, e.Name, row.Runs, row.Passes, row.Fails, row.EWMA, row.LastFailure, string(encoded), row.FlakeProb)
	return err
}

// bumpTestHistoryVersionTx advances the repository's history version and
// returns the new value. The version is per repository, so a replica reloads
// only the repository whose history moved.
func bumpTestHistoryVersionTx(ctx context.Context, tx pgx.Tx, repoID string) (int64, error) {
	var version int64
	err := tx.QueryRow(ctx, `INSERT INTO test_history_repos (repo_id, version, updated_at) VALUES ($1, 1, now()) ON CONFLICT (repo_id) DO UPDATE SET version = test_history_repos.version + 1, updated_at = now() RETURNING version`, repoID).Scan(&version)
	return version, err
}

// lockTestHistoryRepoTx creates the repository's version row when absent and
// locks it (FOR UPDATE), returning the current version. The inserted row is
// the per-repository serialization point for aggregate writes: a concurrent
// first upload for the same repository blocks on the unique index until the
// winner commits, then observes the committed version. version == 0 means the
// repository predates migration 0026 (or its aggregates were never built), so
// the caller must seed the existing durable reports before folding the new
// one — otherwise the first post-upgrade upload would permanently drop the
// pre-upgrade history for that repository.
func lockTestHistoryRepoTx(ctx context.Context, tx pgx.Tx, repoID string) (int64, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO test_history_repos (repo_id, version) VALUES ($1, 0) ON CONFLICT (repo_id) DO NOTHING`, repoID); err != nil {
		return 0, err
	}
	var version int64
	if err := tx.QueryRow(ctx, `SELECT version FROM test_history_repos WHERE repo_id=$1 FOR UPDATE`, repoID).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

// InsertTestReportWithHistory inserts the durable report and folds its cases
// into the repository's aggregates in ONE transaction (see
// TestHistoryAggregateStore). The returned version is the repository's new
// history version. It is the legacy delivery path (no durable delivery
// receipt); callers that can supply a stable delivery identity use
// InsertTestReportWithHistoryDelivery, which additionally makes the upload
// idempotent across retries.
func (s *PostgresStore) InsertTestReportWithHistory(ctx context.Context, rep model.TestReport, repoID string) (int64, error) {
	outcome, err := s.InsertTestReportWithHistoryDelivery(ctx, rep, repoID, TestReportDelivery{})
	if err != nil {
		return 0, err
	}
	return outcome.Version, nil
}

// LoadRepoTestHistory returns one repository's history version and its
// aggregates serialized in the legacy stats JSON shape. A repository whose
// version row does not exist yet reports version 0 with nil stats; the caller
// (server lazy repair) then rebuilds it once from the durable reports.
func (s *PostgresStore) LoadRepoTestHistory(ctx context.Context, repoID string) (int64, []byte, error) {
	if strings.TrimSpace(repoID) == "" {
		return 0, nil, nil
	}
	var version int64
	err := s.pool.QueryRow(ctx, `SELECT version FROM test_history_repos WHERE repo_id=$1`, repoID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT repo_id, suite, test_class, test_name, runs, passes, fails, ewma, last_failure, outcomes, flake_prob FROM test_history_aggregates WHERE repo_id=$1 ORDER BY suite, test_class, test_name`, repoID)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	out := []TestHistoryAggregate{}
	for rows.Next() {
		row, err := scanTestHistoryAggregate(rows)
		if err != nil {
			return 0, nil, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	stats, err := EncodeTestHistoryStats(out)
	if err != nil {
		return 0, nil, err
	}
	return version, stats, nil
}

// scanTestHistoryAggregate decodes one aggregate row (from a pgx.Rows scan).
func scanTestHistoryAggregate(rows pgx.Rows) (TestHistoryAggregate, error) {
	var (
		row      TestHistoryAggregate
		outcomes []byte
	)
	if err := rows.Scan(&row.RepoID, &row.Suite, &row.Class, &row.Name, &row.Runs, &row.Passes, &row.Fails, &row.EWMA, &row.LastFailure, &outcomes, &row.FlakeProb); err != nil {
		return TestHistoryAggregate{}, err
	}
	if len(outcomes) > 0 {
		if err := json.Unmarshal(outcomes, &row.Outcomes); err != nil {
			return TestHistoryAggregate{}, err
		}
	}
	return row, nil
}

// ErrRepoQueryAmbiguous reports that a BARE (host-less) repository query
// addresses more distinct canonical repositories than the supported ambiguity
// limit. A bare owner/name is not a repository identity — several forges can
// present the same name — so a query that exceeds the limit is REFUSED
// explicitly instead of being answered with an arbitrary first `limit`
// candidates: a silently truncated candidate list would make an authorized
// repository sorting after the cap invisible to its own owner. The caller
// re-addresses the repository with its forge-scoped canonical ID
// (host/owner/name), which resolves by exact identity with no ambiguity.
var ErrRepoQueryAmbiguous = errors.New("storage: repository query addresses more canonical repositories than the ambiguity limit")

// repoQueryAmbiguousError carries the diagnosable context of an over-limit
// bare-name resolution. It matches ErrRepoQueryAmbiguous through errors.Is;
// the HTTP layer deliberately maps it to an OPAQUE response that never leaks
// the candidate identities or their count.
type repoQueryAmbiguousError struct {
	query string
	found int
	limit int
}

func (e *repoQueryAmbiguousError) Error() string {
	return fmt.Sprintf("%v: query %q addresses at least %d canonical repositories (limit %d); use the forge-scoped canonical repository ID", ErrRepoQueryAmbiguous, e.query, e.found, e.limit)
}

// Is makes errors.Is(err, ErrRepoQueryAmbiguous) succeed.
func (e *repoQueryAmbiguousError) Is(target error) bool { return target == ErrRepoQueryAmbiguous }

// TestHistoryRepoResolutionStore is the authorization-aware form of
// ResolveTestHistoryRepoIDs: the caller passes the canonical repository
// identities the request's principal is explicitly permitted to read, and the
// implementation intersects candidate discovery with that set BEFORE applying
// the ambiguity limit. Intersecting first is what makes an authorized
// repository that sorts after the bare-name cap reachable; the limit+1
// ambiguity check then applies to what remains. permitted == nil means "no
// identity restriction" (no principal, or a global/bare-alias grant that
// authorizes every forge presenting the name); a non-nil slice — possibly
// empty — is the exact permitted identity set, and an empty one resolves to
// no candidates without touching the database.
type TestHistoryRepoResolutionStore interface {
	ResolveTestHistoryRepoIDsScoped(ctx context.Context, query string, permitted []string, limit int) ([]string, error)
}

var _ TestHistoryRepoResolutionStore = (*PostgresStore)(nil)

// testHistoryResolveLimit normalizes the supported ambiguity limit of one
// bare-name resolution. Non-positive or oversized values select the
// documented default.
func testHistoryResolveLimit(limit int) int {
	if limit <= 0 || limit > 256 {
		return 64
	}
	return limit
}

// repoQueryHasForgeHost reports whether a query already carries a forge host
// (host/owner/name) and is therefore an exact canonical repository identity
// rather than a bare owner/name candidate hint. It mirrors the host-like rule
// of auth.CanonicalRepoID (the remainder must itself contain a slash), so a
// GitLab group whose name contains a dot is never mistaken for a host.
func repoQueryHasForgeHost(query string) bool {
	_, _, ok := splitHostLike(query)
	return ok
}

// filterTestHistoryPermitted normalizes the permitted canonical identity set.
// The second result reports whether the restriction is active (permitted was
// non-nil); an active restriction with no usable identity resolves to zero
// candidates.
func filterTestHistoryPermitted(permitted []string) ([]string, bool) {
	if permitted == nil {
		return nil, false
	}
	seen := make(map[string]bool, len(permitted))
	out := make([]string, 0, len(permitted))
	for _, id := range permitted {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, true
}

// ResolveTestHistoryRepoIDs maps a test-intelligence query to the CANDIDATE
// canonical repository IDs it addresses: resolution is candidate discovery,
// NOT an authorization decision. It is ResolveTestHistoryRepoIDsScoped with
// no identity restriction.
func (s *PostgresStore) ResolveTestHistoryRepoIDs(ctx context.Context, query string, limit int) ([]string, error) {
	return s.ResolveTestHistoryRepoIDsScoped(ctx, query, nil, limit)
}

// ResolveTestHistoryRepoIDsScoped resolves one test-intelligence query with
// the repository resolution policy:
//
//   - a Canonical repository ID query (host/owner/name) is an EXACT identity
//     lookup: it addresses at most one canonical repository, so it is never
//     capped and can never be reported ambiguous;
//   - a bare owner/name query is candidate discovery across every forge that
//     presents the name. At most limit+1 distinct canonical identities are
//     fetched: more than limit means ErrRepoQueryAmbiguous, never a silently
//     truncated list;
//   - when permitted is non-nil, candidate discovery is INTERSECTED with the
//     principal's permitted canonical identities FIRST (for the canonical
//     form too: the exact identity is offered only inside the permitted set),
//     and the limit+1 ambiguity check applies to the intersection. An
//     authorized repository that would sort after a bare-name cap is
//     therefore still resolved.
//
// The query forms mirror runMatchesRepoQuery (full name, canonical identity,
// legacy host-less canonical form); resolution is a single set-based run
// query backed by the 0027 canonical-identity expression index — it never
// materializes reports or resolves runs one by one. The caller must still
// authorize every returned canonical ID individually before reading
// aggregates.
func (s *PostgresStore) ResolveTestHistoryRepoIDsScoped(ctx context.Context, query string, permitted []string, limit int) ([]string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	allowed, restricted := filterTestHistoryPermitted(permitted)
	if restricted && len(allowed) == 0 {
		return []string{}, nil
	}
	limit = testHistoryResolveLimit(limit)
	canonicalQuery := repoQueryHasForgeHost(query)
	args := []any{query}
	predicate := canonicalPolicyRepoIDSQLExpr("repo") + ` = $1`
	if !canonicalQuery {
		predicate = `(payload->>'repo_full_name' = $1 OR ` + canonicalPolicyRepoIDSQLExpr("repo") + ` = $1)`
	}
	if restricted {
		args = append(args, allowed)
		predicate += ` AND ` + canonicalPolicyRepoIDSQLExpr("repo") + fmt.Sprintf(` = ANY($%d::text[])`, len(args))
	}
	inner := `SELECT DISTINCT ` + canonicalPolicyRepoIDSQLExpr("repo") + ` AS id FROM runs WHERE ` + predicate
	q := `SELECT id FROM (` + inner + `) AS candidates WHERE id <> '' ORDER BY id`
	if !canonicalQuery {
		args = append(args, limit+1)
		q += fmt.Sprintf(` LIMIT $%d`, len(args))
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !canonicalQuery && len(out) > limit {
		return nil, &repoQueryAmbiguousError{query: query, found: len(out), limit: limit}
	}
	sort.Strings(out)
	return out, nil
}

// TestReportTotals returns the report count and the report-declared test and
// failure totals for EXACTLY the supplied canonical repository IDs. The query
// joins test_results to runs and filters on the CANONICAL run identity
// (policy-first, legacy rows derived from clone URL + full name), so
// unrelated reports are never read — not even their payloads — and a
// pre-RepoID run is never excluded from its repository's totals.
//
// There is deliberately NO bare-name predicate: a bare full name is not a
// repository identity (several forges can present it), and re-injecting the
// query form here would fan one query's totals across every forge that
// presents the name — including repositories the caller is not authorized to
// read. The caller resolves candidates (ResolveTestHistoryRepoIDs, which
// keeps the full-name fallback) and authorizes every candidate individually
// before calling this method; the repoQuery argument is retained for
// interface compatibility and is IGNORED. An empty set returns zero totals
// without touching the database.
func (s *PostgresStore) TestReportTotals(ctx context.Context, repoIDs []string, repoQuery string) (int, int, int, error) {
	ids := make([]string, 0, len(repoIDs))
	for _, id := range repoIDs {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			ids = append(ids, trimmed)
		}
	}
	if len(ids) == 0 {
		return 0, 0, 0, nil
	}
	var reports, tests, failures int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*), COALESCE(SUM(tr.tests), 0)::int, COALESCE(SUM(tr.failures), 0)::int
		FROM test_results tr JOIN runs r ON r.id = tr.run_id
		WHERE `+canonicalPolicyRepoIDSQLExprOn("r.payload", "repo")+` = ANY($1::text[])`, ids).Scan(&reports, &tests, &failures)
	if err != nil {
		return 0, 0, 0, err
	}
	return reports, tests, failures, nil
}

// FlakyTestNames returns the sorted, deduplicated class-qualified test names
// that are flaky inside their 16-outcome window among the resolved
// repositories, bounded by limit. The predicate is the window-derived
// flake_prob > 0 — the SAME rule as testintel.History.Flaky — not the
// lifetime passes/fails counters, so a test that failed long ago and passed
// its whole window drops out. Deduplication happens in SQL on the RENDERED
// identity (DISTINCT), BEFORE the limit is applied: the same class.name in
// two suites renders to one output name, and duplicate rows can no longer
// crowd out later unique names from the bounded list.
func (s *PostgresStore) FlakyTestNames(ctx context.Context, repoIDs []string, limit int) ([]string, error) {
	if len(repoIDs) == 0 {
		return []string{}, nil
	}
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT (CASE WHEN test_class = '' THEN test_name ELSE test_class || '.' || test_name END) AS display
		FROM test_history_aggregates
		WHERE repo_id = ANY($1::text[]) AND flake_prob > 0
		ORDER BY display
		LIMIT $2`, repoIDs, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var display string
		if err := rows.Scan(&display); err != nil {
			return nil, err
		}
		out = append(out, display)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// testHistoryRebuildPage bounds one keyset page of the repair scan.
const testHistoryRebuildPage = 500

// RebuildRepoTestHistory is the explicit bounded repair operation: it
// recomputes ONE repository's aggregates from its durable reports in one
// transaction (delete + re-insert + version bump) using the exact
// created_at/id ordering the legacy full rebuild used, so an incremental
// history and a rebuilt history are byte-identical. It is never called per
// upload; the server uses it as lazy repair when a repository predates the
// aggregates migration.
func (s *PostgresStore) RebuildRepoTestHistory(ctx context.Context, repoID string) (int64, error) {
	repoID = strings.TrimSpace(repoID)
	if repoID == "" {
		return 0, fmt.Errorf("storage: test history repository identity is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := lockTestHistoryRepoTx(ctx, tx, repoID); err != nil {
		return 0, err
	}
	if err := rebuildRepoTestHistoryTx(ctx, tx, repoID); err != nil {
		return 0, err
	}
	version, err := bumpTestHistoryVersionTx(ctx, tx, repoID)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return version, nil
}

// rebuildRepoTestHistoryTx replaces one repository's aggregate rows with a
// fresh fold of its durable reports (created_at/id order) inside the caller's
// transaction. It does NOT touch the version counter: callers bump it once.
// The report scan selects the repository through the SAME canonical
// policy-first identity expression every scoped read uses
// (canonicalPolicyRepoIDSQLExprOn), so a repository's pre-RepoID runs — whose
// payload carries only the clone URL and full name — are folded into the
// repository's aggregates instead of being silently dropped.
func rebuildRepoTestHistoryTx(ctx context.Context, tx pgx.Tx, repoID string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM test_history_aggregates WHERE repo_id=$1`, repoID); err != nil {
		return err
	}
	// The aggregate is accumulated in memory per repository: the repair work
	// is bounded by the repository's reports and distinct test names, never by
	// the whole database.
	aggregates := map[string]TestHistoryAggregate{}
	afterCreated := time.Time{}
	afterID := ""
	for {
		rows, err := tx.Query(ctx, `SELECT tr.created_at, tr.id, tr.payload
			FROM test_results tr JOIN runs r ON r.id = tr.run_id
			WHERE `+canonicalPolicyRepoIDSQLExprOn("r.payload", "repo")+` = $1
			  AND (tr.created_at, tr.id) > ($2, $3)
			ORDER BY tr.created_at ASC, tr.id ASC
			LIMIT $4`, repoID, afterCreated, afterID, testHistoryRebuildPage)
		if err != nil {
			return err
		}
		type pageRow struct {
			created time.Time
			id      string
			rep     model.TestReport
		}
		page := []pageRow{}
		for rows.Next() {
			var (
				created time.Time
				id      string
				payload []byte
				rep     model.TestReport
			)
			if err := rows.Scan(&created, &id, &payload); err != nil {
				rows.Close()
				return err
			}
			if err := json.Unmarshal(payload, &rep); err != nil {
				rows.Close()
				return err
			}
			page = append(page, pageRow{created: created, id: id, rep: rep})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		for _, p := range page {
			for _, c := range p.rep.Cases {
				// Skip policy: skipped cases are excluded from the fold here
				// exactly as they are on the incremental path, so a rebuilt
				// history is byte-identical to one built by uploads and a
				// skip can never surface as a failure or as flakiness.
				if c.Skipped {
					continue
				}
				key := testHistoryAggregateKey(p.rep.JobKey, c.Class, c.Name)
				row := aggregates[key]
				row.RepoID = repoID
				row.Suite = p.rep.JobKey
				row.Class = c.Class
				row.Name = c.Name
				aggregates[key] = FoldTestHistoryAggregate(row, TestHistoryEntry{
					Suite: p.rep.JobKey, Class: c.Class, Name: c.Name, Duration: c.Duration, Passed: c.Passed, When: p.rep.CreatedAt,
				})
			}
			afterCreated, afterID = p.created, p.id
		}
		if len(page) < testHistoryRebuildPage {
			break
		}
	}
	for _, row := range aggregates {
		encoded, err := json.Marshal(row.Outcomes)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO test_history_aggregates (repo_id, suite, test_class, test_name, runs, passes, fails, ewma, last_failure, outcomes, flake_prob, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, now())`,
			repoID, row.Suite, row.Class, row.Name, row.Runs, row.Passes, row.Fails, row.EWMA, row.LastFailure, string(encoded), row.FlakeProb); err != nil {
			return err
		}
	}
	return nil
}

// TestHistoryRepoPageSize is the default keyset page size of the repository
// enumeration (ListTestHistoryRepoIDs). A page bounds ONE query; it is not a
// cap on the enumeration: the method keeps requesting pages with a strict
// keyset cursor until a short page proves the end, so a maintenance rebuild
// repairs every repository that has durable reports.
const TestHistoryRepoPageSize = 500

// ListTestHistoryRepoIDs returns EVERY canonical repository ID that has
// durable reports, in ascending id order. limit is the keyset page size (a
// non-positive value selects TestHistoryRepoPageSize): each query is
// `WHERE <canonical repo> > $after ORDER BY 1 LIMIT $page` and the loop
// continues until a page shorter than the bound, so no repository is ever
// left out by a magic enumeration cap. Legacy runs (no
// repo_id/policy_repo_id) resolve through the same canonical policy-first
// expression the scoped reads and the rebuild use, so their repositories are
// listed too (a purely stored-identity enumeration would omit every
// pre-RepoID repository and never repair it).
func (s *PostgresStore) ListTestHistoryRepoIDs(ctx context.Context, limit int) ([]string, error) {
	page := limit
	if page <= 0 {
		page = TestHistoryRepoPageSize
	}
	repoExpr := canonicalPolicyRepoIDSQLExprOn("r.payload", "repo")
	out := []string{}
	after := ""
	for {
		rows, err := s.pool.Query(ctx, `SELECT DISTINCT `+repoExpr+`
			FROM test_results tr JOIN runs r ON r.id = tr.run_id
			WHERE `+repoExpr+` <> '' AND `+repoExpr+` > $1
			ORDER BY 1 LIMIT $2`, after, page)
		if err != nil {
			return nil, err
		}
		n := 0
		last := ""
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, id)
			last = id
			n++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if n < page {
			return out, nil
		}
		// Strict keyset advance: the next page starts after the last id of
		// this page, so pages can never overlap or skip ids.
		after = last
	}
}
