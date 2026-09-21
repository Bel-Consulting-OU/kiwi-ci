package server

// Real-PostgreSQL integration tests for the durable test-report delivery
// identity over the HTTP /tests endpoint: replay idempotence, explicit
// digest conflicts and concurrent duplicate deliveries. Gated on
// KIWI_TEST_POSTGRES_URL via the shared pgITServer* helpers.

import (
	"net/http"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestPostgresIntegrationTestReportDeliveryReplayAndConflict proves the
// dropped-response contract end to end against real PostgreSQL: the first
// upload commits, the identical replay is answered 200 and changes NOTHING,
// and a reused delivery ID with different content is a 409 with the report
// count, the folded history and the version untouched.
func TestPostgresIntegrationTestReportDeliveryReplayAndConflict(t *testing.T) {
	env := pgITServerSetup(t)
	s, _ := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)
	run := pgITSubmit(t, s, pgITServerPipeline)
	task := pgITNext(t, s, runnerID)
	canonical := storage.RepoIDForRun(run)
	if canonical == "" {
		t.Fatal("submitted run has no canonical repository identity")
	}
	reportCount := func() int {
		return pgITServerCount(t, env, `SELECT COUNT(*) FROM test_results WHERE run_id=$1`, run.ID)
	}
	foldCount := func() int {
		return pgITServerCount(t, env, `SELECT COALESCE(SUM(runs),0)::int FROM test_history_aggregates WHERE repo_id=$1`, canonical)
	}
	version := func() int {
		return pgITServerCount(t, env, `SELECT COALESCE(MAX(version),0)::int FROM test_history_repos WHERE repo_id=$1`, canonical)
	}

	body := deliveryReportBody(task.Job.ID, runnerID, task.LeaseToken, task.LeaseGeneration, "delivery-it-1",
		model.TestResult{Name: "it", Class: "C", Duration: 1, Passed: true})
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", body, nil); w.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
	}
	// The dropped response retry.
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", body, nil); w.Code != http.StatusOK {
		t.Fatalf("replay = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := reportCount(); got != 1 {
		t.Fatalf("reports after replay = %d, want 1 (the retry double-inserted)", got)
	}
	if got := foldCount(); got != 1 {
		t.Fatalf("folded outcomes after replay = %d, want 1", got)
	}
	if got := version(); got != 1 {
		t.Fatalf("history version after replay = %d, want 1", got)
	}
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_report_deliveries WHERE job_id=$1 AND lease_generation=$2 AND delivery_id=$3`, task.Job.ID, task.LeaseGeneration, "delivery-it-1"); got != 1 {
		t.Fatalf("delivery receipts = %d, want 1", got)
	}

	// Same delivery identity, different payload: explicit 409, state intact.
	conflict := deliveryReportBody(task.Job.ID, runnerID, task.LeaseToken, task.LeaseGeneration, "delivery-it-1",
		model.TestResult{Name: "it", Class: "C", Duration: 2, Passed: false})
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", conflict, nil); w.Code != http.StatusConflict {
		t.Fatalf("conflict = %d, want 409: %s", w.Code, w.Body.String())
	}
	if got := reportCount(); got != 1 {
		t.Fatalf("reports after conflict = %d, want 1", got)
	}
	if got := foldCount(); got != 1 {
		t.Fatalf("folded outcomes after conflict = %d, want 1", got)
	}
	if got := version(); got != 1 {
		t.Fatalf("history version after conflict = %d, want 1", got)
	}
}

// TestPostgresIntegrationTestReportDeliveryConcurrentDuplicates races the
// identical delivery through the HTTP endpoint against real PostgreSQL: the
// unique delivery key serializes the claims, exactly one request inserts, the
// others replay, and one report/history/version exists.
func TestPostgresIntegrationTestReportDeliveryConcurrentDuplicates(t *testing.T) {
	env := pgITServerSetup(t)
	s, _ := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)
	run := pgITSubmit(t, s, pgITServerPipeline)
	task := pgITNext(t, s, runnerID)
	canonical := storage.RepoIDForRun(run)
	if canonical == "" {
		t.Fatal("submitted run has no canonical repository identity")
	}
	body := deliveryReportBody(task.Job.ID, runnerID, task.LeaseToken, task.LeaseGeneration, "delivery-race",
		model.TestResult{Name: "racy", Passed: false},
		model.TestResult{Name: "racy", Passed: true})

	const workers = 8
	codes := make([]int, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", body, nil)
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()
	created, replayed := 0, 0
	for i, code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusOK:
			replayed++
		default:
			t.Fatalf("worker %d: status %d", i, code)
		}
	}
	if created != 1 || replayed != workers-1 {
		t.Fatalf("concurrent duplicates: %d created / %d replayed, want exactly one created", created, replayed)
	}
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_results WHERE run_id=$1`, run.ID); got != 1 {
		t.Fatalf("reports after concurrent duplicates = %d, want 1", got)
	}
	if got := pgITServerCount(t, env, `SELECT COALESCE(SUM(runs),0)::int FROM test_history_aggregates WHERE repo_id=$1`, canonical); got != 2 {
		t.Fatalf("folded outcomes after concurrent duplicates = %d, want one report's two cases", got)
	}
	if got := pgITServerCount(t, env, `SELECT COALESCE(MAX(version),0)::int FROM test_history_repos WHERE repo_id=$1`, canonical); got != 1 {
		t.Fatalf("history version after concurrent duplicates = %d, want 1", got)
	}
}
