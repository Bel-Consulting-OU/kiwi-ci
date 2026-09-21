package storage

// Real-PostgreSQL integration tests for the incremental, repository-scoped
// test history (migration 0026) and the atomic runner-disable transaction.
// Gated on KIWI_TEST_POSTGRES_URL (skipped when unset and in -short mode).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

// pgITHistoryRun enqueues one run + job whose payload carries the canonical
// repository identity, so the 0026 expression indexes and every scoped read
// see the same identity the server resolves.
func pgITHistoryRun(t *testing.T, st *PostgresStore, runID, jobID, repoID, fullName string, created time.Time) {
	t.Helper()
	if err := st.InsertCompiledRun(context.Background(), InsertCompiledRunRequest{
		Run: model.Run{ID: runID, RepoID: repoID, PolicyRepoID: repoID, Repo: "https://" + repoID + ".git", RepoFullName: fullName, Status: model.StatusQueued, CreatedAt: created},
		Jobs: map[string]model.Job{jobID: {
			ID: jobID, RunID: runID, Key: "build", RepoID: repoID, PolicyRepoID: repoID,
			RepoURL: "https://" + repoID + ".git", RepoFullName: fullName, Status: model.StatusQueued, CreatedAt: created,
		}},
	}); err != nil {
		t.Fatalf("enqueue history run %s: %v", runID, err)
	}
}

func pgITHistoryReport(runID, id string, created time.Time, cases ...model.TestResult) model.TestReport {
	tests, failures := 0, 0
	for _, c := range cases {
		tests++
		if !c.Passed && !c.Skipped {
			failures++
		}
	}
	return model.TestReport{ID: id, RunID: runID, JobKey: "build", Tests: tests, Failures: failures, Cases: cases, CreatedAt: created}
}

func pgITHistoryVersion(t *testing.T, st *PostgresStore, repoID string) int64 {
	t.Helper()
	var version int64
	if err := st.pool.QueryRow(context.Background(), `SELECT version FROM test_history_repos WHERE repo_id=$1`, repoID).Scan(&version); err != nil {
		t.Fatalf("read history version %s: %v", repoID, err)
	}
	return version
}

func pgITHistoryStats(t *testing.T, st *PostgresStore, repoID string) map[string]testintel.TestStat {
	t.Helper()
	_, stats, err := st.LoadRepoTestHistory(context.Background(), repoID)
	if err != nil {
		t.Fatalf("load repo history %s: %v", repoID, err)
	}
	out := map[string]testintel.TestStat{}
	if len(stats) == 0 {
		return out
	}
	if err := json.Unmarshal(stats, &out); err != nil {
		t.Fatalf("decode repo history %s: %v", repoID, err)
	}
	return out
}

// pgITHistoryStatsJSON renders a testintel history through its own Save so
// the comparison is against the legacy persisted shape, not a hand-built map.
func pgITHistoryStatsJSON(t *testing.T, h *testintel.History) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history.json")
	if err := h.Save(path); err != nil {
		t.Fatalf("save expected history: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pgITHealBoom(t *testing.T, st *PostgresStore, table string) {
	t.Helper()
	fn := "kiwi_boom_" + table
	for _, ev := range []string{"insert", "update", "delete"} {
		if _, err := st.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+fn+`_`+ev+` ON `+table); err != nil {
			t.Fatalf("heal trigger on %s: %v", table, err)
		}
	}
}

func pgITHistoryReportCount(t *testing.T, st *PostgresStore, reportID string) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM test_results WHERE id=$1`, reportID).Scan(&n); err != nil {
		t.Fatalf("count report %s: %v", reportID, err)
	}
	return n
}

// TestPostgresIntegrationTestHistoryIncrementalEquivalenceBounded is tests
// (a) and (b): sequential uploads produce exactly the history a full rebuild
// derives from the same reports (duplicate names, multiple repositories,
// re-runs, >16 outcomes), and one upload touches ONLY the aggregate rows for
// the keys in its report — unrelated repositories' rows are byte-identical
// afterwards (no full-history rewrite).
func TestPostgresIntegrationTestHistoryIncrementalEquivalenceBounded(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repoA, fullA := "github.com/kiwi-it/repo-a", "kiwi-it/repo-a"
	repoB, fullB := "gitlab.example.com/kiwi-it/repo-b", "kiwi-it/repo-b"
	base := time.Now().UTC().Truncate(time.Second)

	runA1, jobA1 := pgITNewID(t), pgITNewID(t)
	runA2, jobA2 := pgITNewID(t), pgITNewID(t)
	runB1, jobB1 := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runA1, jobA1, repoA, fullA, base)
	pgITHistoryRun(t, st, runA2, jobA2, repoA, fullA, base.Add(time.Second))
	pgITHistoryRun(t, st, runB1, jobB1, repoB, fullB, base.Add(2*time.Second))

	repA1 := pgITHistoryReport(runA1, pgITNewID(t), base,
		model.TestResult{Name: "t1", Duration: 1, Passed: true},
		model.TestResult{Name: "t2", Class: "C", Duration: 2, Passed: false},
		model.TestResult{Name: "t1", Duration: 3, Passed: true},
	)
	repA2 := pgITHistoryReport(runA2, pgITNewID(t), base.Add(time.Second),
		model.TestResult{Name: "t1", Duration: 4},
		model.TestResult{Name: "t2", Class: "C", Passed: true},
	)
	casesB := []model.TestResult{}
	for i := 0; i < 20; i++ {
		casesB = append(casesB, model.TestResult{Name: "t9", Duration: float64(i), Passed: i%2 == 0})
	}
	repB := pgITHistoryReport(runB1, pgITNewID(t), base.Add(2*time.Second), casesB...)

	for _, item := range []struct {
		rep  model.TestReport
		repo string
	}{{repA1, repoA}, {repA2, repoA}, {repB, repoB}} {
		if _, err := st.InsertTestReportWithHistory(ctx, item.rep, item.repo); err != nil {
			t.Fatalf("insert report %s: %v", item.rep.ID, err)
		}
	}

	// (a) Equivalence with an independent testintel fold over the reports in
	// created_at/id order — the ordering the legacy full rebuild used.
	want := map[string]testintel.TestStat{}
	h := testintel.NewHistory()
	for _, rep := range []model.TestReport{repA1, repA2} {
		for _, c := range rep.Cases {
			h.Record(repoA, rep.JobKey, c.Class, c.Name, c.Duration, c.Passed, rep.CreatedAt)
		}
	}
	if err := json.Unmarshal(pgITHistoryStatsJSON(t, h), &want); err != nil {
		t.Fatal(err)
	}
	if got := pgITHistoryStats(t, st, repoA); !reflect.DeepEqual(want, got) {
		t.Fatalf("incremental history diverged from testintel fold:\nwant %+v\ngot  %+v", want, got)
	}

	// (a2) The explicit repair rebuild is equivalent to the incremental
	// uploads (same JSON bytes) and advances the version.
	_, before, err := st.LoadRepoTestHistory(ctx, repoA)
	if err != nil {
		t.Fatal(err)
	}
	versionBefore := pgITHistoryVersion(t, st, repoA)
	if _, err := st.RebuildRepoTestHistory(ctx, repoA); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	_, after, err := st.LoadRepoTestHistory(ctx, repoA)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("incremental vs rebuilt history diverged:\nbefore %s\nafter  %s", before, after)
	}
	if v := pgITHistoryVersion(t, st, repoA); v <= versionBefore {
		t.Fatalf("rebuild version = %d, want > %d", v, versionBefore)
	}

	// (b) Bounded: snapshot every aggregate row of both repositories, upload
	// one report with a single new key for A, and assert no unrelated row
	// changed (B byte-identical; every other A row keeps updated_at and
	// counters) and exactly one new row exists.
	type rowKey struct{ repo, suite, class, name string }
	snapshot := func() map[rowKey][]string {
		rows, err := st.pool.Query(ctx, `SELECT repo_id, suite, test_class, test_name, runs, passes, fails, updated_at::text FROM test_history_aggregates ORDER BY repo_id, suite, test_class, test_name`)
		if err != nil {
			t.Fatalf("snapshot aggregates: %v", err)
		}
		defer rows.Close()
		out := map[rowKey][]string{}
		for rows.Next() {
			var k rowKey
			var runs, passes, fails int64
			var updated string
			if err := rows.Scan(&k.repo, &k.suite, &k.class, &k.name, &runs, &passes, &fails, &updated); err != nil {
				t.Fatal(err)
			}
			out[k] = []string{updated, itoa64(runs), itoa64(passes), itoa64(fails)}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	prior := snapshot()
	repA3 := pgITHistoryReport(runA2, pgITNewID(t), base.Add(2*time.Second), model.TestResult{Name: "brand-new", Passed: true})
	if _, err := st.InsertTestReportWithHistory(ctx, repA3, repoA); err != nil {
		t.Fatalf("insert bounded report: %v", err)
	}
	post := snapshot()
	if len(post) != len(prior)+1 {
		t.Fatalf("aggregate rows = %d, want %d (exactly one new key)", len(post), len(prior)+1)
	}
	newKey := rowKey{repoA, "build", "", "brand-new"}
	for k, v := range prior {
		if k == newKey {
			t.Fatalf("the new key already existed before the upload: %+v", k)
		}
		if !reflect.DeepEqual(post[k], v) {
			t.Fatalf("unrelated aggregate row %+v changed: %v -> %v", k, v, post[k])
		}
	}
	if _, ok := post[newKey]; !ok {
		t.Fatal("the uploaded key's aggregate row is missing")
	}

	// Scoped totals: only repo A's three reports count.
	reports, tests, failures, err := st.TestReportTotals(ctx, []string{repoA}, fullA)
	if err != nil || reports != 3 || tests != 6 || failures != 2 {
		t.Fatalf("repo A totals = %d/%d/%d, %v; want 3/6/2", reports, tests, failures, err)
	}
	flaky, err := st.FlakyTestNames(ctx, []string{repoA}, 100)
	if err != nil || !reflect.DeepEqual(flaky, []string{"C.t2", "t1"}) {
		t.Fatalf("repo A flaky = %v, %v; want [C.t2 t1]", flaky, err)
	}
	flakyB, err := st.FlakyTestNames(ctx, []string{repoB}, 100)
	if err != nil || !reflect.DeepEqual(flakyB, []string{"t9"}) {
		t.Fatalf("repo B flaky = %v, %v; want [t9]", flakyB, err)
	}

	// Identity resolution accepts the human full name and the canonical ID
	// and never leaks the other repository.
	for _, query := range []string{fullA, repoA} {
		ids, err := st.ResolveTestHistoryRepoIDs(ctx, query, 10)
		if err != nil || !reflect.DeepEqual(ids, []string{repoA}) {
			t.Fatalf("resolve %q = %v, %v; want [%s]", query, ids, err, repoA)
		}
	}
}

// TestPostgresIntegrationTestHistoryScopedReadsIgnoreUnrelatedCorruption is
// test (c): a report whose payload cannot decode as a model.TestReport (the
// old full-table path fails on it) plants no obstacle for the scoped reads,
// because they never materialize or decode unrelated reports/runs.
func TestPostgresIntegrationTestHistoryScopedReadsIgnoreUnrelatedCorruption(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repoGood, fullGood := "github.com/kiwi-it/good", "kiwi-it/good"
	repoBad := "github.com/kiwi-it/bad"
	base := time.Now().UTC().Truncate(time.Second)
	runGood, jobGood := pgITNewID(t), pgITNewID(t)
	runBad, jobBad := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runGood, jobGood, repoGood, fullGood, base)
	pgITHistoryRun(t, st, runBad, jobBad, repoBad, "kiwi-it/bad", base.Add(time.Second))

	if _, err := st.InsertTestReportWithHistory(ctx, pgITHistoryReport(runGood, pgITNewID(t), base,
		model.TestResult{Name: "ok", Passed: false}), repoGood); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertTestReportWithHistory(ctx, pgITHistoryReport(runGood, pgITNewID(t), base.Add(time.Second),
		model.TestResult{Name: "ok", Passed: true}), repoGood); err != nil {
		t.Fatal(err)
	}
	// Valid JSONB, invalid model.TestReport: the legacy
	// ListTestReportsAll -> json.Unmarshal path cannot survive it.
	corruptID := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO test_results (id, run_id, job_key, created_at, payload) VALUES ($1, $2, 'build', $3, '{"cases":"boom"}'::jsonb)`,
		corruptID, runBad, base.Add(2*time.Second)); err != nil {
		t.Fatalf("plant corrupt report: %v", err)
	}
	if _, err := st.ListTestReportsAll(ctx); err == nil {
		t.Fatal("the legacy full-table path unexpectedly tolerated the corrupt report (test premise broken)")
	}
	// The scoped read path is unaffected.
	ids, err := st.ResolveTestHistoryRepoIDs(ctx, fullGood, 10)
	if err != nil || !reflect.DeepEqual(ids, []string{repoGood}) {
		t.Fatalf("resolve = %v, %v; want [%s]", ids, err, repoGood)
	}
	reports, tests, failures, err := st.TestReportTotals(ctx, ids, fullGood)
	if err != nil || reports != 2 || tests != 2 || failures != 1 {
		t.Fatalf("totals = %d/%d/%d, %v; want 2/2/1", reports, tests, failures, err)
	}
	flaky, err := st.FlakyTestNames(ctx, ids, 100)
	if err != nil || !reflect.DeepEqual(flaky, []string{"ok"}) {
		t.Fatalf("flaky = %v, %v; want [ok]", flaky, err)
	}
	if _, _, err := st.LoadRepoTestHistory(ctx, repoGood); err != nil {
		t.Fatalf("scoped history load: %v", err)
	}
}

// TestPostgresIntegrationTestHistoryCanceledContextAndAtomicRollback is test
// (d): a canceled request context commits nothing, and a failure inside the
// aggregate write rolls the report insert back with it (one transaction).
func TestPostgresIntegrationTestHistoryCanceledContextAndAtomicRollback(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := "github.com/kiwi-it/ctx-repo"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repo, "kiwi-it/ctx-repo", base)

	// Canceled context: the transaction never begins.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	repCanceled := pgITHistoryReport(runID, pgITNewID(t), base, model.TestResult{Name: "t", Passed: true})
	if _, err := st.InsertTestReportWithHistory(canceled, repCanceled, repo); err == nil {
		t.Fatal("canceled context must fail the upload")
	}
	if n := pgITHistoryReportCount(t, st, repCanceled.ID); n != 0 {
		t.Fatalf("canceled upload persisted %d report(s)", n)
	}
	if v, stats, err := st.LoadRepoTestHistory(ctx, repo); err != nil || v != 0 || stats != nil {
		t.Fatalf("canceled upload left history version %d stats %v err %v", v, stats, err)
	}

	// Injected aggregate-write failure: the report insert is part of the same
	// transaction and must roll back with it.
	pgITBoom(t, st, "test_history_aggregates")
	repBoom := pgITHistoryReport(runID, pgITNewID(t), base.Add(time.Second), model.TestResult{Name: "atomic", Passed: true})
	if _, err := st.InsertTestReportWithHistory(ctx, repBoom, repo); err == nil {
		t.Fatal("injected aggregate failure must fail the upload")
	}
	if n := pgITHistoryReportCount(t, st, repBoom.ID); n != 0 {
		t.Fatalf("aggregate failure left %d report row(s) behind", n)
	}
	pgITHealBoom(t, st, "test_history_aggregates")

	// Heal and retry: exactly one report and one history.
	if _, err := st.InsertTestReportWithHistory(ctx, repBoom, repo); err != nil {
		t.Fatalf("healed retry: %v", err)
	}
	if n := pgITHistoryReportCount(t, st, repBoom.ID); n != 1 {
		t.Fatalf("healed retry stored %d reports, want 1", n)
	}
	if got := pgITHistoryStats(t, st, repo); len(got) != 1 {
		t.Fatalf("healed retry history = %v, want exactly one key", got)
	}
}

// TestPostgresIntegrationDisableRunnerCertAtomic is the S6-B real-PostgreSQL
// proof: disable + lease revocation + certificate revocation + audit commit
// together; an injected revocation-write failure leaves NOTHING behind; the
// healed retry succeeds exactly once; and a concurrent two-replica disable is
// state-idempotent.
func TestPostgresIntegrationDisableRunnerCertAtomic(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, runnerID, jobID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	serial := "serial-atomic-" + pgITRandomHex(t, 8)

	job := pgITJob(runID, jobID, pgITRepo)
	job.MaxInfraRetries = 2
	pgITRecSeedRun(t, st, runID, model.StatusRunning, map[string]model.Job{jobID: job})
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, CertSerial: serial, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	pgITRecLease(t, st, jobID, runnerID, 1, time.Now().UTC().Add(time.Hour))

	// Fail-before: the revocation write explodes, so the whole transaction
	// rolls back — no disable, no lease move, no revocation, no audit.
	pgITBoom(t, st, "cert_revocations")
	if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, serial, "admin"); err == nil {
		t.Fatal("injected certificate revocation failure must fail the disable")
	}
	if ri, err := st.GetRunner(ctx, runnerID); err != nil || ri.Disabled || ri.RevokedAt != nil {
		t.Fatalf("failed disable mutated the runner: %+v err=%v", ri, err)
	}
	if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID {
		t.Fatalf("failed disable mutated the lease: %+v err=%v", j, err)
	}
	if revoked, err := st.CertRevoked(ctx, serial); err != nil || revoked {
		t.Fatalf("failed disable recorded a revocation: %v err=%v", revoked, err)
	}
	audit, err := st.ReadAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range audit {
		if e.Action == "runner.disable" || e.Action == "runner.cert_revoked" {
			t.Fatalf("failed disable left audit evidence: %+v", e)
		}
	}
	pgITHealBoom(t, st, "cert_revocations")

	// Healed: everything commits together.
	revoked, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, serial, "admin")
	if err != nil || revoked != 1 {
		t.Fatalf("healed disable = %d, %v; want 1/nil", revoked, err)
	}
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil || !ri.Disabled || ri.RevokedAt == nil {
		t.Fatalf("healed disable runner = %+v err=%v", ri, err)
	}
	if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
		t.Fatalf("healed disable job = %+v err=%v, want requeued with cleared lease", j, err)
	}
	if revoked, err := st.CertRevoked(ctx, serial); err != nil || !revoked {
		t.Fatalf("healed disable revocation = %v err=%v, want true", revoked, err)
	}
	audit, err = st.ReadAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range audit {
		seen[e.Action] = true
	}
	if !seen["runner.disable"] || !seen["runner.cert_revoked"] {
		t.Fatalf("healed disable audit actions = %v, want runner.disable + runner.cert_revoked", seen)
	}
	failedAfterFirst := ri.Failed

	// Idempotent replay: no lease moves, no counter moves, still revoked.
	revoked, err = st.DisableRunnerAndRevokeCert(ctx, runnerID, serial, "admin")
	if err != nil || revoked != 0 {
		t.Fatalf("replayed disable = %d, %v; want 0/nil", revoked, err)
	}
	if ri, err := st.GetRunner(ctx, runnerID); err != nil || ri.Failed != failedAfterFirst {
		t.Fatalf("replayed disable moved counters: %+v err=%v", ri, err)
	}
	if revoked, err := st.CertRevoked(ctx, serial); err != nil || !revoked {
		t.Fatalf("replayed disable lost the revocation: %v err=%v", revoked, err)
	}
}

// TestPostgresIntegrationDisableRunnerCertTwoReplicas runs the atomic disable
// concurrently over two pools on the same schema: exactly one replica moves
// the lease, both succeed, and the durable state is the same as a single
// disable.
func TestPostgresIntegrationDisableRunnerCertTwoReplicas(t *testing.T) {
	env := pgITSetup(t)
	stA := env.open(t)
	env.migrate(t, stA)
	pgITArmFence(t, stA)
	stB := env.open(t)
	env.migrate(t, stB)
	pgITArmFence(t, stB)
	ctx := context.Background()

	runID, runnerID, jobID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	serial := "serial-race-" + pgITRandomHex(t, 8)
	job := pgITJob(runID, jobID, pgITRepo)
	job.MaxInfraRetries = 2
	pgITRecSeedRun(t, stA, runID, model.StatusRunning, map[string]model.Job{jobID: job})
	if err := stA.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, CertSerial: serial, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	pgITRecLease(t, stA, jobID, runnerID, 1, time.Now().UTC().Add(time.Hour))

	type result struct {
		revoked int
		err     error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, st := range []*PostgresStore{stA, stB} {
		wg.Add(1)
		go func(st *PostgresStore) {
			defer wg.Done()
			revoked, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, serial, "admin")
			results <- result{revoked: revoked, err: err}
		}(st)
	}
	wg.Wait()
	close(results)

	total := 0
	for res := range results {
		if res.err != nil {
			t.Fatalf("concurrent disable failed: %v", res.err)
		}
		total += res.revoked
	}
	if total != 1 {
		t.Fatalf("concurrent disable revoked %d leases, want exactly 1", total)
	}
	ri, err := stA.GetRunner(ctx, runnerID)
	if err != nil || !ri.Disabled || ri.Failed != 1 {
		t.Fatalf("runner after concurrent disable = %+v err=%v (want disabled, failed=1)", ri, err)
	}
	if revoked, err := stA.CertRevoked(ctx, serial); err != nil || !revoked {
		t.Fatalf("certificate after concurrent disable = %v err=%v, want revoked", revoked, err)
	}
	if j, err := stA.GetJob(ctx, jobID); err != nil || j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
		t.Fatalf("job after concurrent disable = %+v err=%v", j, err)
	}
}

// TestPostgresIntegrationTestHistoryUpgradeBridge pins the migration-0026
// upgrade bridge: a repository whose reports predate the aggregates table
// keeps its full history when the FIRST post-upgrade upload folds its own
// cases, because that upload seeds the repository's existing reports once
// (bounded by the repository) in the same transaction.
func TestPostgresIntegrationTestHistoryUpgradeBridge(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	ctx := context.Background()
	// The schema is at 0025: test_history_aggregates does not exist yet.
	pgITApplyThrough(t, st, 25)
	repo, full := "github.com/kiwi-it/legacy", "kiwi-it/legacy"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repo, full, base)
	oldRep := pgITHistoryReport(runID, pgITNewID(t), base, model.TestResult{Name: "old", Duration: 1, Passed: false})
	if err := st.InsertTestReport(ctx, oldRep); err != nil {
		t.Fatalf("pre-upgrade report insert: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate to 0026: %v", err)
	}
	newRep := pgITHistoryReport(runID, pgITNewID(t), base.Add(time.Second),
		model.TestResult{Name: "old", Duration: 2, Passed: true},
		model.TestResult{Name: "new", Passed: true},
	)
	if _, err := st.InsertTestReportWithHistory(ctx, newRep, repo); err != nil {
		t.Fatalf("first post-upgrade upload: %v", err)
	}
	h := testintel.NewHistory()
	for _, rep := range []model.TestReport{oldRep, newRep} {
		for _, c := range rep.Cases {
			h.Record(repo, rep.JobKey, c.Class, c.Name, c.Duration, c.Passed, rep.CreatedAt)
		}
	}
	want := map[string]testintel.TestStat{}
	if err := json.Unmarshal(pgITHistoryStatsJSON(t, h), &want); err != nil {
		t.Fatal(err)
	}
	if got := pgITHistoryStats(t, st, repo); !reflect.DeepEqual(want, got) {
		t.Fatalf("post-upgrade history dropped pre-upgrade data:\nwant %+v\ngot  %+v", want, got)
	}
	// The explicit rebuild still agrees byte-for-byte.
	_, before, err := st.LoadRepoTestHistory(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RebuildRepoTestHistory(ctx, repo); err != nil {
		t.Fatal(err)
	}
	_, after, err := st.LoadRepoTestHistory(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("post-upgrade seed diverged from rebuild:\nbefore %s\nafter  %s", before, after)
	}
}

// TestPostgresIntegrationTestHistoryLegacyIdentityCanonical is the T4-A
// upgrade regression: pre-RepoID runs carry ONLY the clone URL and full name
// (no repo_id/policy_repo_id), so their canonical identity exists only through
// the canonicalPolicyRepoIDSQLExpr derivation. The test seeds such runs plus
// pre-0026 reports, upgrades the schema, uploads one new report, and asserts
// the aggregates and totals equal old+new (not only new), that scoped reads by
// the canonical ID find the legacy data, and that the migration indexes match
// the query expressions (planner verification with enable_seqscan=off).
func TestPostgresIntegrationTestHistoryLegacyIdentityCanonical(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	ctx := context.Background()
	// Schema before 0026: no aggregates tables and no canonical index yet.
	pgITApplyThrough(t, st, 25)
	canonical, full := "github.com/acme/widget", "acme/widget"
	base := time.Now().UTC().Truncate(time.Second)

	// Legacy run rows: no repo_id and no policy_repo_id, only the clone URL
	// (HTTPS and scp-like SSH spellings) plus the full name.
	legacyRun := func(id, url string, created time.Time) {
		t.Helper()
		payload := json.RawMessage(`{"id":"` + id + `","repo":"` + url + `","repo_full_name":"` + full + `","status":"success","created_at":"` + created.Format(time.RFC3339) + `"}`)
		if _, err := st.pool.Exec(ctx, `INSERT INTO runs (id, status, created_at, payload) VALUES ($1, 'success', $2, $3::jsonb)`, id, created, payload); err != nil {
			t.Fatalf("insert legacy run %s: %v", id, err)
		}
	}
	runA, runB, runC := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	legacyRun(runA, "https://github.com/acme/widget.git", base)
	legacyRun(runB, "git@github.com:acme/widget.git", base.Add(time.Second))

	oldA := pgITHistoryReport(runA, pgITNewID(t), base,
		model.TestResult{Name: "t1", Duration: 1, Passed: true},
		model.TestResult{Name: "t2", Duration: 2, Passed: false},
	)
	oldB := pgITHistoryReport(runB, pgITNewID(t), base.Add(time.Second),
		model.TestResult{Name: "t1", Duration: 3, Passed: true},
	)
	for _, rep := range []model.TestReport{oldA, oldB} {
		if err := st.InsertTestReport(ctx, rep); err != nil {
			t.Fatalf("pre-0026 report insert %s: %v", rep.ID, err)
		}
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	if v, err := st.SchemaVersion(ctx); err != nil || v != pgITLatestVersion(t) {
		t.Fatalf("schema version = %d/%v, want %d", v, err, pgITLatestVersion(t))
	}

	// The final index definitions live on the canonical expressions: the
	// 0026 identity index would have omitted the clone-URL derivation.
	var identityDef, fullNameDef string
	if err := st.pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='runs_repo_identity_idx'`).Scan(&identityDef); err != nil {
		t.Fatalf("read identity indexdef: %v", err)
	}
	if !strings.Contains(identityDef, `policy_repo_id`) || !strings.Contains(identityDef, `kiwi_canonical_repo_id`) {
		t.Fatalf("runs_repo_identity_idx is not the canonical policy-first expression: %s", identityDef)
	}
	if err := st.pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='runs_repo_full_name_idx'`).Scan(&fullNameDef); err != nil {
		t.Fatalf("read full-name indexdef: %v", err)
	}
	if !strings.Contains(fullNameDef, `repo_full_name`) {
		t.Fatalf("runs_repo_full_name_idx = %s, want the full-name expression", fullNameDef)
	}
	// Planner proof: the query expression built by the SAME helper the reads
	// use must resolve to the index (textual pg_indexes comparison would be
	// normalization-sensitive; expression-tree equivalence is what matters).
	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	planRows, err := tx.Query(ctx, `EXPLAIN SELECT id FROM runs WHERE `+canonicalPolicyRepoIDSQLExpr("repo")+` = $1`, canonical)
	if err != nil {
		t.Fatalf("explain canonical query: %v", err)
	}
	var plan strings.Builder
	for planRows.Next() {
		var line string
		if err := planRows.Scan(&line); err != nil {
			planRows.Close()
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteString("\n")
	}
	planRows.Close()
	if err := planRows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "runs_repo_identity_idx") {
		t.Fatalf("canonical identity query does not use runs_repo_identity_idx:\n%s", plan.String())
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// Both scoped read forms find the legacy repository.
	for _, query := range []string{canonical, full} {
		ids, err := st.ResolveTestHistoryRepoIDs(ctx, query, 10)
		if err != nil || !reflect.DeepEqual(ids, []string{canonical}) {
			t.Fatalf("resolve %q = %v, %v; want [%s]", query, ids, err, canonical)
		}
	}
	listed, err := st.ListTestHistoryRepoIDs(ctx, 100)
	if err != nil || !reflect.DeepEqual(listed, []string{canonical}) {
		t.Fatalf("ListTestHistoryRepoIDs = %v, %v; want [%s]", listed, err, canonical)
	}

	// First post-upgrade upload: its run is legacy-shaped too, and the upload
	// seeds the legacy reports through the canonical rebuild filter BEFORE
	// folding the new report.
	legacyRun(runC, "https://github.com/acme/widget.git", base.Add(2*time.Second))
	newRep := pgITHistoryReport(runC, pgITNewID(t), base.Add(2*time.Second),
		model.TestResult{Name: "t1", Duration: 4, Passed: true},
		model.TestResult{Name: "t3", Duration: 5, Passed: false},
	)
	if _, err := st.InsertTestReportWithHistory(ctx, newRep, canonical); err != nil {
		t.Fatalf("first post-upgrade upload: %v", err)
	}

	// Aggregates equal the fold over old+new (the upgrade must not drop the
	// pre-RepoID history).
	h := testintel.NewHistory()
	for _, rep := range []model.TestReport{oldA, oldB, newRep} {
		for _, c := range rep.Cases {
			h.Record(canonical, rep.JobKey, c.Class, c.Name, c.Duration, c.Passed, rep.CreatedAt)
		}
	}
	want := map[string]testintel.TestStat{}
	if err := json.Unmarshal(pgITHistoryStatsJSON(t, h), &want); err != nil {
		t.Fatal(err)
	}
	if got := pgITHistoryStats(t, st, canonical); !reflect.DeepEqual(want, got) {
		t.Fatalf("history dropped legacy data:\nwant %+v\ngot  %+v", want, got)
	}
	// The explicit repair rebuild agrees byte-for-byte (same canonical
	// filter).
	_, before, err := st.LoadRepoTestHistory(ctx, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RebuildRepoTestHistory(ctx, canonical); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	_, after, err := st.LoadRepoTestHistory(ctx, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("post-upgrade history diverged from rebuild:\nbefore %s\nafter  %s", before, after)
	}

	// Scoped totals include old+new, both by canonical ID and by full name.
	for _, query := range []string{canonical, full} {
		reports, tests, failures, err := st.TestReportTotals(ctx, []string{canonical}, query)
		if err != nil || reports != 3 || tests != 5 || failures != 2 {
			t.Fatalf("totals(%q) = %d/%d/%d, %v; want 3/5/2", query, reports, tests, failures, err)
		}
	}
}

// TestPostgresIntegrationTestHistoryCanonicalIndexUpgradeFrom0026 pins the
// 0026 -> 0027 upgrade path: a database that already applied 0026 (the
// incomplete identity index, no canonical function) converges on the
// canonical policy-first index and function when 0027 applies.
func TestPostgresIntegrationTestHistoryCanonicalIndexUpgradeFrom0026(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	ctx := context.Background()
	pgITApplyThrough(t, st, 26)

	var oldDef string
	if err := st.pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='runs_repo_identity_idx'`).Scan(&oldDef); err != nil {
		t.Fatalf("read 0026 indexdef: %v", err)
	}
	if strings.Contains(oldDef, "kiwi_canonical_repo_id") {
		t.Fatalf("0026 index already canonical (test premise broken): %s", oldDef)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate 0026 -> 0027: %v", err)
	}
	if v, err := st.SchemaVersion(ctx); err != nil || v != pgITLatestVersion(t) {
		t.Fatalf("schema version = %d/%v, want %d", v, err, pgITLatestVersion(t))
	}
	var functions int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM pg_proc WHERE proname='kiwi_canonical_repo_id' AND pronamespace=current_schema()::regnamespace`).Scan(&functions); err != nil {
		t.Fatalf("count canonical function: %v", err)
	}
	if functions != 1 {
		t.Fatalf("kiwi_canonical_repo_id functions = %d, want 1", functions)
	}
	var newDef string
	if err := st.pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='runs_repo_identity_idx'`).Scan(&newDef); err != nil {
		t.Fatalf("read upgraded indexdef: %v", err)
	}
	if !strings.Contains(newDef, "kiwi_canonical_repo_id") || !strings.Contains(newDef, "policy_repo_id") {
		t.Fatalf("upgraded runs_repo_identity_idx is not canonical: %s", newDef)
	}
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// pgITSeedHistoryRepoPage plants n repositories with one durable report each
// by bulk SQL, so repository-enumeration pagination can be exercised at a
// scale where per-insert APIs would dominate the test runtime. Each run
// payload carries the canonical repo_id every scoped read resolves.
func pgITSeedHistoryRepoPage(t *testing.T, st *PostgresStore, n int) []string {
	t.Helper()
	ctx := context.Background()
	if _, err := st.pool.Exec(ctx, `INSERT INTO runs (id, status, created_at, payload)
		SELECT 'run-' || lpad(i::text, 28, '0'), 'success', now(),
			jsonb_build_object('id', 'run-' || lpad(i::text, 28, '0'),
				'repo_id', 'github.com/kiwi-it/page-' || lpad(i::text, 4, '0'),
				'repo_full_name', 'kiwi-it/page-' || lpad(i::text, 4, '0'),
				'repo', 'https://github.com/kiwi-it/page-' || lpad(i::text, 4, '0') || '.git')
		FROM generate_series(1, $1) AS i`, n); err != nil {
		t.Fatalf("seed pagination runs: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO test_results (id, run_id, job_key, tests, failures, created_at, payload)
		SELECT 'rep-' || lpad(i::text, 28, '0'), 'run-' || lpad(i::text, 28, '0'), 'build', 1, 0, now(), '{}'::jsonb
		FROM generate_series(1, $1) AS i`, n); err != nil {
		t.Fatalf("seed pagination reports: %v", err)
	}
	ids := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		ids = append(ids, "github.com/kiwi-it/page-"+fmt.Sprintf("%04d", i))
	}
	return ids
}

// TestPostgresIntegrationTestHistoryRepairRepoPagination is defect 4's
// real-PostgreSQL proof: more than the old 1000-repository enumeration cap is
// returned COMPLETE (every repository present, ascending, unique) by the
// keyset loop, with the default page size and with a deliberately small page
// size that forces many pages.
func TestPostgresIntegrationTestHistoryRepairRepoPagination(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const repos = 1005
	want := pgITSeedHistoryRepoPage(t, st, repos)

	full, err := st.ListTestHistoryRepoIDs(ctx, 0)
	if err != nil {
		t.Fatalf("default enumeration: %v", err)
	}
	if len(full) != repos {
		t.Fatalf("default enumeration = %d repositories, want %d (the pre-fix cap returned 1000)", len(full), repos)
	}
	if !reflect.DeepEqual(full, want) {
		t.Fatalf("default enumeration is not the complete ascending set:\ngot  %d ids\nwant %d ids", len(full), len(want))
	}
	// Small page size: the loop must fetch the identical complete set across
	// many keyset pages.
	small, err := st.ListTestHistoryRepoIDs(ctx, 7)
	if err != nil {
		t.Fatalf("small-page enumeration: %v", err)
	}
	if !reflect.DeepEqual(small, full) {
		t.Fatalf("small-page enumeration diverged: %d ids vs %d", len(small), len(full))
	}
	// A page bound larger than the set terminates after one short page.
	one, err := st.ListTestHistoryRepoIDs(ctx, repos+10)
	if err != nil || !reflect.DeepEqual(one, full) {
		t.Fatalf("single-page enumeration diverged: %d ids err=%v", len(one), err)
	}
}

// TestPostgresIntegrationTestHistoryFlakyWindowDropsOut is defect 2's
// real-PostgreSQL proof: FlakyTestNames filters on the window-derived
// flake_prob (NOT the lifetime passes/fails counters), so a test that failed
// once and then passed its whole 16-outcome window drops out while its
// lifetime counters still show the failure.
func TestPostgresIntegrationTestHistoryFlakyWindowDropsOut(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo, full := "github.com/kiwi-it/window", "kiwi-it/window"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repo, full, base)

	upload := func(at time.Time, passed bool) {
		t.Helper()
		rep := pgITHistoryReport(runID, pgITNewID(t), at, model.TestResult{Name: "t", Duration: 1, Passed: passed})
		if _, err := st.InsertTestReportWithHistory(ctx, rep, repo); err != nil {
			t.Fatalf("upload: %v", err)
		}
	}
	upload(base, false)
	for i := 0; i < 16; i++ {
		upload(base.Add(time.Duration(i+1)*time.Second), true)
	}
	flaky, err := st.FlakyTestNames(ctx, []string{repo}, 100)
	if err != nil || len(flaky) != 0 {
		t.Fatalf("flaky after a clean 16-outcome window = %v, %v; want none", flaky, err)
	}
	// The lifetime counters still carry the old failure: the predicate must be
	// flake_prob, not passes > 0 AND fails > 0.
	var passes, fails int64
	var flakeProb float64
	if err := st.pool.QueryRow(ctx, `SELECT passes, fails, flake_prob FROM test_history_aggregates
		WHERE repo_id=$1 AND suite='build' AND test_class='' AND test_name='t'`, repo).Scan(&passes, &fails, &flakeProb); err != nil {
		t.Fatalf("read aggregate: %v", err)
	}
	if passes != 16 || fails != 1 || flakeProb != 0 {
		t.Fatalf("aggregate = passes %d fails %d flake_prob %v; want 16/1/0", passes, fails, flakeProb)
	}
	// A fresh failure inside the window restores the flaky classification.
	upload(base.Add(time.Minute), false)
	flaky, err = st.FlakyTestNames(ctx, []string{repo}, 100)
	if err != nil || !reflect.DeepEqual(flaky, []string{"t"}) {
		t.Fatalf("flaky after a fresh failure = %v, %v; want [t]", flaky, err)
	}
}

// TestPostgresIntegrationTestHistoryTotalsCanonicalSetOnly is the real-PG
// proof of the authorized-set totals contract: resolution still finds BOTH
// forges that present the same bare name, but TestReportTotals answers ONLY
// the canonical IDs it is given — the bare-name predicate is gone, so a
// one-repository authorized set can never include the other forge and an
// empty set can never fan the query across every forge.
func TestPostgresIntegrationTestHistoryTotalsCanonicalSetOnly(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)
	repoGH, repoGL := "github.com/acme/service", "gitlab.example/acme/service"
	runGH, jobGH, runGL, jobGL := pgITNewID(t), pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runGH, jobGH, repoGH, "acme/service", base)
	pgITHistoryRun(t, st, runGL, jobGL, repoGL, "acme/service", base.Add(time.Second))
	repGH := pgITHistoryReport(runGH, pgITNewID(t), base, model.TestResult{Name: "gh", Passed: true})
	repGL := pgITHistoryReport(runGL, pgITNewID(t), base.Add(time.Second),
		model.TestResult{Name: "gl1", Passed: true},
		model.TestResult{Name: "gl2", Passed: false},
		model.TestResult{Name: "gl3", Passed: true})
	for _, item := range []struct {
		rep  model.TestReport
		repo string
	}{{repGH, repoGH}, {repGL, repoGL}} {
		if _, err := st.InsertTestReportWithHistory(ctx, item.rep, item.repo); err != nil {
			t.Fatalf("insert %s: %v", item.rep.ID, err)
		}
	}
	// Candidate discovery keeps the bare-name fallback.
	ids, err := st.ResolveTestHistoryRepoIDs(ctx, "acme/service", 10)
	if err != nil || !reflect.DeepEqual(ids, []string{repoGH, repoGL}) {
		t.Fatalf("resolve = %v, %v; want both forges", ids, err)
	}
	// The authorized canonical set is the ONLY totals predicate.
	reports, tests, failures, err := st.TestReportTotals(ctx, []string{repoGH}, "acme/service")
	if err != nil || reports != 1 || tests != 1 || failures != 0 {
		t.Fatalf("canonical-set totals = %d/%d/%d, %v; want 1/1/0 (pre-fix the bare query added the GitLab forge)", reports, tests, failures, err)
	}
	// An empty set returns zero without touching the bare name.
	reports, tests, failures, err = st.TestReportTotals(ctx, nil, "acme/service")
	if err != nil || reports != 0 || tests != 0 || failures != 0 {
		t.Fatalf("empty-set totals = %d/%d/%d, %v; want 0/0/0", reports, tests, failures, err)
	}
}
