package server

// L5-B real-PostgreSQL proof: a legacy client that sends NO delivery_id gets
// a server-synthesized deterministic delivery identity after the lease is
// verified, so a dropped response followed by a resend yields exactly ONE
// report row, ONE folded history outcome, ONE metrics observation, ONE audit
// event and ONE delivery receipt. Conflicting content presented under that
// same synthesized identity is refused with 409 and changes nothing.
//
// Gated on KIWI_TEST_POSTGRES_URL via the shared pgITServer* helpers.

import (
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

func TestPostgresIntegrationServerTestReportLegacyResendConvergesOnce(t *testing.T) {
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
	path := "/api/v1/jobs/" + task.Job.ID + "/tests"
	body, payload := legacyReportBody(task.Job.ID, runnerID, task.LeaseToken, task.LeaseGeneration,
		model.TestResult{Name: "it", Class: "C", Duration: 1, Passed: true})
	synth := synthesizedReportDeliveryID(task.Job.ID, task.LeaseGeneration, testintel.ReportContentDigest(payload))

	if w := pgITDo(t, s, http.MethodPost, path, "token", body, nil); w.Code != http.StatusCreated {
		t.Fatalf("first legacy upload = %d: %s", w.Code, w.Body.String())
	}
	// The classic dropped-response retry: identical bytes, no delivery_id.
	if w := pgITDo(t, s, http.MethodPost, path, "token", body, nil); w.Code != http.StatusOK {
		t.Fatalf("legacy resend = %d, want idempotent 200 (pre-fix: 201 + duplicate report)", w.Code)
	}
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_results WHERE run_id=$1`, run.ID); got != 1 {
		t.Fatalf("reports after legacy resend = %d, want 1", got)
	}
	if got := pgITServerCount(t, env, `SELECT COALESCE(SUM(runs),0)::int FROM test_history_aggregates WHERE repo_id=$1`, canonical); got != 1 {
		t.Fatalf("folded outcomes after legacy resend = %d, want 1", got)
	}
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM audit_events WHERE action='tests.uploaded'`); got != 1 {
		t.Fatalf("tests.uploaded audits after legacy resend = %d, want 1", got)
	}
	if got := testDurationObservations(t, s); got != 1 {
		t.Fatalf("metrics observations after legacy resend = %d, want 1", got)
	}
	// The receipt is keyed by the SYNTHESIZED identity, not by an empty ID.
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_report_deliveries WHERE job_id=$1 AND lease_generation=$2 AND delivery_id=$3`,
		task.Job.ID, task.LeaseGeneration, synth); got != 1 {
		t.Fatalf("delivery receipts for the synthesized identity = %d, want 1", got)
	}

	// Conflicting content under the SAME synthesized identity: 409, and the
	// committed report/history/version stay untouched.
	conflict, _ := explicitDeliveryBody(task.Job.ID, runnerID, task.LeaseToken, task.LeaseGeneration, synth,
		model.TestResult{Name: "it", Class: "C", Duration: 2, Passed: false})
	if w := pgITDo(t, s, http.MethodPost, path, "token", conflict, nil); w.Code != http.StatusConflict {
		t.Fatalf("conflicting content under the synthesized identity = %d, want 409", w.Code)
	}
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_results WHERE run_id=$1`, run.ID); got != 1 {
		t.Fatalf("reports after synthesized-identity conflict = %d, want 1", got)
	}
	if got := pgITServerCount(t, env, `SELECT COALESCE(SUM(fails),0)::int FROM test_history_aggregates WHERE repo_id=$1`, canonical); got != 0 {
		t.Fatalf("folded failures after synthesized-identity conflict = %d, want 0", got)
	}
	if got := pgITServerCount(t, env, `SELECT COALESCE(MAX(version),0)::int FROM test_history_repos WHERE repo_id=$1`, canonical); got != 1 {
		t.Fatalf("history version after synthesized-identity conflict = %d, want 1", got)
	}
}
