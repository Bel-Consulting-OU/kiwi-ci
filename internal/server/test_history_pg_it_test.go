package server

// Real-PostgreSQL integration tests for the S6-A scoped test-history reads
// over the HTTP handlers and the S6-B atomic runner disable. Gated on
// KIWI_TEST_POSTGRES_URL via the shared pgITServer* helpers.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITServerExec runs one statement on the test schema through a raw
// connection (used to plant data the store API would never write).
func pgITServerExec(t *testing.T, env *pgITServerEnv, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.base)
	if err != nil {
		t.Fatalf("raw connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "SET search_path TO "+pgx.Identifier{env.schema}.Sanitize()); err != nil {
		t.Fatalf("raw search_path: %v", err)
	}
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("raw exec: %v", err)
	}
}

// pgITUploadTestReport uploads one report for a leased task.
func pgITUploadTestReport(t *testing.T, s *Server, runnerID string, task Task, cases ...model.TestResult) *httptest.ResponseRecorder {
	t.Helper()
	failures := 0
	for _, c := range cases {
		if !c.Passed && !c.Skipped {
			failures++
		}
	}
	rep := model.TestReport{RunID: task.Job.RunID, JobID: task.Job.ID, JobKey: task.Job.Key, Tests: len(cases), Failures: failures, Cases: cases}
	raw, err := json.Marshal(map[string]any{
		"runner_id": runnerID, "lease_token": task.LeaseToken, "lease_generation": task.LeaseGeneration, "report": rep,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", string(raw), nil)
}

// TestPostgresIntegrationServerTestIntelScopedHistory drives the scoped read
// path end to end against real PostgreSQL: two uploads make a test flaky,
// test-intelligence reports it for the requested canonical repository only,
// test-shards converges from the same per-repository aggregates, and an
// unrelated corrupt report cannot break either read.
func TestPostgresIntegrationServerTestIntelScopedHistory(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)
	run := pgITSubmit(t, s, pgITServerPipeline)
	task := pgITNext(t, s, runnerID)
	if w := pgITUploadTestReport(t, s, runnerID, task, model.TestResult{Class: "C", Name: "flaky", Passed: false}); w.Code != http.StatusCreated {
		t.Fatalf("upload 1 = %d: %s", w.Code, w.Body.String())
	}
	if w := pgITUploadTestReport(t, s, runnerID, task, model.TestResult{Class: "C", Name: "flaky", Passed: true}); w.Code != http.StatusCreated {
		t.Fatalf("upload 2 = %d: %s", w.Code, w.Body.String())
	}

	canonical := storage.RepoIDForRun(run)
	if canonical == "" {
		t.Fatal("submitted run has no canonical repository identity")
	}
	w := pgITDo(t, s, http.MethodGet, "/api/v1/test-intelligence?repo="+canonical, "token", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("intelligence = %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Reports    int      `json:"reports"`
		TotalTests int      `json:"total_tests"`
		Failures   int      `json:"failures"`
		Flaky      []string `json:"flaky_tests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Reports != 2 || out.TotalTests != 2 || out.Failures != 1 || len(out.Flaky) != 1 || out.Flaky[0] != "C.flaky" {
		t.Fatalf("scoped intelligence = %+v, want 2 reports / 2 tests / 1 failure / [C.flaky]", out)
	}
	// The durable per-repository aggregates back the read.
	version, stats, err := st.LoadRepoTestHistory(context.Background(), canonical)
	if err != nil || version != 2 || len(stats) == 0 {
		t.Fatalf("durable aggregates = version %d stats %d err %v, want version 2", version, len(stats), err)
	}

	// test-shards converges from the same aggregates (and never rebuilds).
	shards := pgITDo(t, s, http.MethodGet, "/api/v1/jobs/"+task.Job.ID+"/test-shards?shards=2", "token", "", pgITLeaseHeaders(task, runnerID))
	if shards.Code != http.StatusOK {
		t.Fatalf("test-shards = %d: %s", shards.Code, shards.Body.String())
	}
}

// TestPostgresIntegrationServerTestHistoryKeyedPerRepo is the live-PostgreSQL
// half of the keyed-cache regression: two repositories in one schema with
// disjoint histories, and every shard response (sequential and concurrent)
// must answer exactly its OWN repository's generation — never the other
// repository's history and never a mix.
func TestPostgresIntegrationServerTestHistoryKeyedPerRepo(t *testing.T) {
	env := pgITServerSetup(t)
	s, _ := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)

	submitRepo := func(fullName string) Task {
		t.Helper()
		body, err := json.Marshal(SubmitRun{
			RepoURL: "https://github.com/" + fullName + ".git", RepoFullName: fullName,
			Ref: "refs/heads/main", SHA: "abc123", Event: "push", Pipeline: pgITServerPipeline,
		})
		if err != nil {
			t.Fatal(err)
		}
		w := pgITDo(t, s, http.MethodPost, "/api/v1/runs", "token", string(body), nil)
		if w.Code != http.StatusAccepted {
			t.Fatalf("submit %s: %d %s", fullName, w.Code, w.Body.String())
		}
		return pgITNext(t, s, runnerID)
	}

	// Repo A: two tests, one of them flaky. Repo B: a different test.
	taskA := submitRepo("o/pg-a")
	if w := pgITUploadTestReport(t, s, runnerID, taskA, model.TestResult{Name: "pg-a-1", Passed: false}); w.Code != http.StatusCreated {
		t.Fatalf("A upload 1 = %d: %s", w.Code, w.Body.String())
	}
	if w := pgITUploadTestReport(t, s, runnerID, taskA, model.TestResult{Name: "pg-a-1", Passed: true}); w.Code != http.StatusCreated {
		t.Fatalf("A upload 2 = %d: %s", w.Code, w.Body.String())
	}
	if w := pgITUploadTestReport(t, s, runnerID, taskA, model.TestResult{Name: "pg-a-2", Passed: true}); w.Code != http.StatusCreated {
		t.Fatalf("A upload 3 = %d: %s", w.Code, w.Body.String())
	}
	taskB := submitRepo("o/pg-b")
	if w := pgITUploadTestReport(t, s, runnerID, taskB, model.TestResult{Name: "pg-b-1", Passed: true}); w.Code != http.StatusCreated {
		t.Fatalf("B upload = %d: %s", w.Code, w.Body.String())
	}

	type shardBody struct {
		Repo       string     `json:"repo"`
		Manifest   []string   `json:"manifest"`
		Assignment [][]string `json:"assignment"`
		Flaky      []string   `json:"flaky_tests"`
	}
	var mu sync.Mutex
	var problems []string
	report := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if len(problems) < 10 {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}
	check := func(task Task, wantRepo string, wantManifest, wantFlaky []string) {
		w := pgITDo(t, s, http.MethodGet, "/api/v1/jobs/"+task.Job.ID+"/test-shards?shards=2", "token", "", pgITLeaseHeaders(task, runnerID))
		if w.Code != http.StatusOK {
			report("repo %s: test-shards = %d: %s", wantRepo, w.Code, w.Body.String())
			return
		}
		var out shardBody
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			report("repo %s: decode: %v", wantRepo, err)
			return
		}
		seen := map[string]int{}
		for _, shard := range out.Assignment {
			for _, name := range shard {
				seen[name]++
			}
		}
		for _, name := range wantManifest {
			if seen[name] != 1 {
				report("repo %s: test %s appears %d times across shards", wantRepo, name, seen[name])
			}
		}
		if len(seen) != len(wantManifest) {
			report("repo %s: assignment covers %d tests, want %d", wantRepo, len(seen), len(wantManifest))
		}
		if out.Repo != wantRepo || !reflect.DeepEqual(out.Manifest, wantManifest) || !reflect.DeepEqual(out.Flaky, wantFlaky) {
			report("repo %s: response repo=%q manifest=%v flaky=%v; want %v/%v", wantRepo, out.Repo, out.Manifest, out.Flaky, wantManifest, wantFlaky)
		}
	}
	manifestA, flakyA := []string{"pg-a-1", "pg-a-2"}, []string{"pg-a-1"}
	manifestB, flakyB := []string{"pg-b-1"}, []string{}

	// Sequential: the pre-fix single slot swapped A's generation for B's as
	// soon as B was loaded.
	check(taskA, "github.com/o/pg-a", manifestA, flakyA)
	check(taskB, "github.com/o/pg-b", manifestB, flakyB)
	check(taskA, "github.com/o/pg-a", manifestA, flakyA)

	// Concurrent: many simultaneous requests for both repositories.
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			order := []Task{taskA, taskB}
			manifests := [][]string{manifestA, manifestB}
			flakies := [][]string{flakyA, flakyB}
			repos := []string{"github.com/o/pg-a", "github.com/o/pg-b"}
			if seed%2 == 1 {
				order = []Task{taskB, taskA}
				manifests = [][]string{manifestB, manifestA}
				flakies = [][]string{flakyB, flakyA}
				repos = []string{"github.com/o/pg-b", "github.com/o/pg-a"}
			}
			for i := 0; i < 4; i++ {
				for j := range order {
					check(order[j], repos[j], manifests[j], flakies[j])
				}
			}
		}(w)
	}
	wg.Wait()
	if len(problems) > 0 {
		t.Fatalf("keyed snapshot verification failed:\n%s", strings.Join(problems, "\n"))
	}
}

// TestPostgresIntegrationServerTestIntelScopedReadsStayUpOnUnrelatedCorruption
// is the real-PostgreSQL half of test (c): a report whose payload cannot
// decode as a model.TestReport (the legacy full-table read fails on it)
// belongs to an unrelated repository, and both scoped reads must keep
// serving the requested repository.
func TestPostgresIntegrationServerTestIntelScopedReadsStayUpOnUnrelatedCorruption(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)
	run := pgITSubmit(t, s, pgITServerPipeline)
	task := pgITNext(t, s, runnerID)
	if w := pgITUploadTestReport(t, s, runnerID, task, model.TestResult{Name: "ok", Passed: false}); w.Code != http.StatusCreated {
		t.Fatalf("upload 1 = %d: %s", w.Code, w.Body.String())
	}
	if w := pgITUploadTestReport(t, s, runnerID, task, model.TestResult{Name: "ok", Passed: true}); w.Code != http.StatusCreated {
		t.Fatalf("upload 2 = %d: %s", w.Code, w.Body.String())
	}
	canonical := storage.RepoIDForRun(run)

	// An unrelated repository's report is UNDECODABLE: create a run for it,
	// then plant a valid-JSON/wrong-shape report payload. The old full-table
	// path fails on it; the scoped path must not even look at it.
	otherRun, otherJob := pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32)
	if err := st.InsertCompiledRun(context.Background(), storage.InsertCompiledRunRequest{
		Run: model.Run{ID: otherRun, RepoID: "github.com/kiwi-it/other", PolicyRepoID: "github.com/kiwi-it/other",
			Repo: "https://github.com/kiwi-it/other.git", RepoFullName: "kiwi-it/other", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{otherJob: {ID: otherJob, RunID: otherRun, Key: "build",
			RepoID: "github.com/kiwi-it/other", RepoURL: "https://github.com/kiwi-it/other.git", RepoFullName: "kiwi-it/other",
			Status: model.StatusQueued, CreatedAt: time.Now().UTC()}},
	}); err != nil {
		t.Fatalf("seed unrelated run: %v", err)
	}
	pgITServerExec(t, env, `INSERT INTO test_results (id, run_id, job_key, created_at, payload) VALUES ($1, $2, 'build', now(), '{"cases":"boom"}'::jsonb)`, pgITServerRandomHex(t, 32), otherRun)
	if _, err := st.ListTestReportsAll(context.Background()); err == nil {
		t.Fatal("legacy full-table path unexpectedly tolerated the corrupt report")
	}
	w := pgITDo(t, s, http.MethodGet, "/api/v1/test-intelligence?repo="+canonical, "token", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("scoped intelligence after unrelated corruption = %d: %s", w.Code, w.Body.String())
	}
	shards := pgITDo(t, s, http.MethodGet, "/api/v1/jobs/"+task.Job.ID+"/test-shards?shards=2", "token", "", pgITLeaseHeaders(task, runnerID))
	if shards.Code != http.StatusOK {
		t.Fatalf("scoped test-shards after unrelated corruption = %d: %s", shards.Code, shards.Body.String())
	}
}

// TestPostgresIntegrationServerDisableRunnerAtomicCert proves the admin
// disable commits the flag, the lease revocation and the permanent
// certificate revocation together against real PostgreSQL: the response is
// 200 only because the durable revocation row exists, and a replay stays
// idempotent.
func TestPostgresIntegrationServerDisableRunnerAtomicCert(t *testing.T) {
	s, st := pgITServer(t, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)
	pgITSubmit(t, s, pgITServerPipeline)
	task := pgITNext(t, s, runnerID)

	serial := "it-disable-" + pgITServerRandomHex(t, 10)
	ri, err := st.GetRunner(context.Background(), runnerID)
	if err != nil {
		t.Fatal(err)
	}
	ri.CertSerial = serial
	if err := st.UpsertRunner(context.Background(), ri); err != nil {
		t.Fatal(err)
	}

	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", "", nil); w.Code != http.StatusOK {
		t.Fatalf("disable = %d: %s", w.Code, w.Body.String())
	}
	ri, err = st.GetRunner(context.Background(), runnerID)
	if err != nil || !ri.Disabled || ri.RevokedAt == nil {
		t.Fatalf("durable runner after disable = %+v err=%v", ri, err)
	}
	if revoked, err := st.CertRevoked(context.Background(), serial); err != nil || !revoked {
		t.Fatalf("durable certificate revocation = %v err=%v, want true", revoked, err)
	}
	job, err := st.GetJob(context.Background(), task.Job.ID)
	if err != nil || job.Status == model.StatusRunning || job.LeaseRunnerID != "" {
		t.Fatalf("durable job after disable = %+v err=%v, want lease revoked", job, err)
	}
	audit, err := st.ReadAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range audit {
		seen[e.Action] = true
	}
	if !seen["runner.disable"] || !seen["runner.cert_revoked"] {
		t.Fatalf("audit actions = %v, want runner.disable + runner.cert_revoked", seen)
	}

	// Replay: the endpoint stays successful and state-idempotent.
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", "", nil); w.Code != http.StatusOK {
		t.Fatalf("replayed disable = %d: %s", w.Code, w.Body.String())
	}
	if revoked, err := st.CertRevoked(context.Background(), serial); err != nil || !revoked {
		t.Fatalf("certificate revocation after replay = %v err=%v", revoked, err)
	}
}

// pgITServerCount runs one scalar count query through a raw connection bound
// to the test schema.
func pgITServerCount(t *testing.T, env *pgITServerEnv, sql string, args ...any) int {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.base)
	if err != nil {
		t.Fatalf("raw connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "SET search_path TO "+pgx.Identifier{env.schema}.Sanitize()); err != nil {
		t.Fatalf("raw search_path: %v", err)
	}
	var n int
	if err := conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		t.Fatalf("raw count: %v", err)
	}
	return n
}

// pgITServerSeedHistoryRepoPage plants n repositories with one durable report
// each by bulk SQL, so the repository-enumeration pagination can be exercised
// past the old 1000-repository cap without 1000+ API round trips.
func pgITServerSeedHistoryRepoPage(t *testing.T, env *pgITServerEnv, n int) {
	t.Helper()
	pgITServerExec(t, env, `INSERT INTO runs (id, status, created_at, payload)
		SELECT 'run-' || lpad(i::text, 28, '0'), 'success', now(),
			jsonb_build_object('id', 'run-' || lpad(i::text, 28, '0'),
				'repo_id', 'github.com/kiwi-it/page-' || lpad(i::text, 4, '0'),
				'repo_full_name', 'kiwi-it/page-' || lpad(i::text, 4, '0'),
				'repo', 'https://github.com/kiwi-it/page-' || lpad(i::text, 4, '0') || '.git')
		FROM generate_series(1, $1) AS i`, n)
	pgITServerExec(t, env, `INSERT INTO test_results (id, run_id, job_key, tests, failures, created_at, payload)
		SELECT 'rep-' || lpad(i::text, 28, '0'), 'run-' || lpad(i::text, 28, '0'), 'build', 1, 0, now(), '{}'::jsonb
		FROM generate_series(1, $1) AS i`, n)
}

// repairCountingStore wraps the live PostgreSQL store: it forces a small
// keyset page size and counts the per-repository repairs the server's
// maintenance enumeration drives, so the test proves EVERY repository
// participates across many pages (not only the first 1000).
type repairCountingStore struct {
	*storage.PostgresStore
	page    int
	mu      sync.Mutex
	rebuilt map[string]int
}

func (c *repairCountingStore) ListTestHistoryRepoIDs(ctx context.Context, limit int) ([]string, error) {
	if c.page > 0 {
		limit = c.page
	}
	return c.PostgresStore.ListTestHistoryRepoIDs(ctx, limit)
}

func (c *repairCountingStore) RebuildRepoTestHistory(ctx context.Context, repoID string) (int64, error) {
	c.mu.Lock()
	c.rebuilt[repoID]++
	c.mu.Unlock()
	return c.PostgresStore.RebuildRepoTestHistory(ctx, repoID)
}

// TestPostgresIntegrationServerTestHistoryRepairAllReposAcrossPages is defect
// 4's end-to-end real-PostgreSQL proof: the maintenance repair enumerates
// MORE than 1000 repositories through keyset pages (the wrapper forces pages
// of 97) and rebuilds every one of them. Pre-fix the enumeration stopped at
// the 1000-repository cap and the remaining repositories were never repaired.
func TestPostgresIntegrationServerTestHistoryRepairAllReposAcrossPages(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	// One past the old 1000-repository cap: the smallest set that still
	// crosses the boundary the pre-fix enumeration truncated at.
	const repos = 1001
	pgITServerSeedHistoryRepoPage(t, env, repos)

	counting := &repairCountingStore{PostgresStore: st, page: 97, rebuilt: map[string]int{}}
	s.DB = counting
	s.rebuildTestHistoryDB(context.Background())

	counting.mu.Lock()
	rebuilt := len(counting.rebuilt)
	counting.mu.Unlock()
	if rebuilt != repos {
		t.Fatalf("maintenance repair rebuilt %d repositories, want all %d across keyset pages", rebuilt, repos)
	}
	// The durable effect: every repository got its version row.
	if n := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_history_repos`); n != repos {
		t.Fatalf("test_history_repos rows = %d, want %d", n, repos)
	}
	// Spot check through the store API: a repaired repository loads.
	if v, _, err := st.LoadRepoTestHistory(context.Background(), "github.com/kiwi-it/page-1001"); err != nil || v == 0 {
		t.Fatalf("spot-check repaired history = version %d err %v, want a repaired version", v, err)
	}
}
