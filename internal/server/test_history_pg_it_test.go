package server

// Real-PostgreSQL integration tests for the S6-A scoped test-history reads
// over the HTTP handlers and the S6-B atomic runner disable. Gated on
// KIWI_TEST_POSTGRES_URL via the shared pgITServer* helpers.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
