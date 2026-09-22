package server

// Real-PostgreSQL integration test for the leader-promotion resource
// reconciliation on the server surface (E4-B). Gated on
// KIWI_TEST_POSTGRES_URL like every *_it_test.go here.
//
// The scenario is the rolling-upgrade over-admission window: an OLD-version
// leader created a running lease after migration 0030 (the ledger is empty,
// because only the new-version claim knows about it). When a new-version
// replica becomes leader, its FIRST lease attempt must reconcile the durable
// ledger from the live leases BEFORE it can issue a lease; otherwise it would
// sum an empty ledger and admit work the runner cannot hold.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITRunFirstJobID returns the first job ID of one run through the jobs API.
func pgITRunFirstJobID(t *testing.T, s *Server, runID string) string {
	t.Helper()
	w := pgITDo(t, s, http.MethodGet, "/api/v1/runs/"+runID+"/jobs", "token", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list jobs = %d %s", w.Code, w.Body.String())
	}
	var jobs []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &jobs); err != nil {
		t.Fatalf("decode jobs: %v", err)
	}
	if len(jobs) == 0 {
		t.Fatalf("run %s has no jobs", runID)
	}
	return jobs[0].ID
}

// pgITWriteOldLeaderRunningJob marks a queued job running under a lease with
// the given generation, exactly as an old-version leader would have — no
// reservation row — and appends it to the runner's active set.
func pgITWriteOldLeaderRunningJob(t *testing.T, env *pgITServerEnv, runnerID, jobID string, generation int64) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.base)
	if err != nil {
		t.Fatalf("connect for old-leader simulation: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `SET search_path TO `+pgx.Identifier{env.schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE jobs SET status='running', attempts = attempts + 1, started_at = COALESCE(started_at, now()), lease_runner_id=$2, lease_token_hash='x'::bytea, lease_generation=$3, lease_expires_at=now() + interval '1 hour' WHERE id=$1`,
		jobID, runnerID, generation); err != nil {
		t.Fatalf("old-leader job update: %v", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE runners SET active_jobs = COALESCE(active_jobs, '[]'::jsonb) || to_jsonb($2::text) WHERE id=$1`, runnerID, jobID); err != nil {
		t.Fatalf("old-leader runner update: %v", err)
	}
}

// pgITReservationRows counts the ledger rows (schema-scoped).
func pgITReservationRows(t *testing.T, env *pgITServerEnv) int {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.base)
	if err != nil {
		t.Fatalf("connect for ledger count: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `SET search_path TO `+pgx.Identifier{env.schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM job_resource_reservations`).Scan(&rows); err != nil {
		t.Fatalf("count reservations: %v", err)
	}
	return rows
}

func TestIntegrationResourceReconcilePromotionServerPostgres(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	s.UntrustedMemoryCeiling = 16 << 30
	serial := "res-promo-" + pgITServerRandomHex(t, 8)
	profileID := "res-promo-prof-" + pgITServerRandomHex(t, 6)
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runner-profiles", "token",
		`{"id":"`+profileID+`","labels":["container"],"capabilities":["container"],"max_capacity":8,"max_memory":8589934592}`, nil); w.Code != http.StatusCreated {
		t.Fatalf("create profile = %d %s", w.Code, w.Body.String())
	}
	if w := pgITDo(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/cert/"+serial, "token", "{}", nil); w.Code != http.StatusOK {
		t.Fatalf("bind profile = %d %s", w.Code, w.Body.String())
	}
	w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"res-promo-runner","cert_serial":"`+serial+`","protocol_min":3,"protocol_max":3,"capacity":8}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register = %d %s", w.Code, w.Body.String())
	}
	var runner model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &runner); err != nil {
		t.Fatal(err)
	}

	// The previous (old-version) leader left one RUNNING 5 GiB lease behind
	// with no reservation row: migration 0030's ledger is empty.
	oldRun := pgITSubmit(t, s, pgITResourcePipeline)
	oldJobID := pgITRunFirstJobID(t, s, oldRun.ID)
	pgITWriteOldLeaderRunningJob(t, env, runner.ID, oldJobID, 1)
	if rows := pgITReservationRows(t, env); rows != 0 {
		t.Fatalf("precondition: ledger rows = %d, want the old leader's empty ledger", rows)
	}

	// A new 5 GiB job arrives. The promoted replica's first lease attempt
	// reconciles the ledger (5 GiB already running on the 8 GiB runner)
	// BEFORE issuing the lease, so the job waits instead of oversubscribing.
	newRun := pgITSubmit(t, s, pgITResourcePipeline)
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runner.ID+"/next", "token", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("over-admitted next = %d, want 204: %s", w.Code, w.Body.String())
	}
	if rows := pgITReservationRows(t, env); rows != 1 {
		t.Fatalf("ledger rows after promotion = %d, want the reconciled pre-existing lease", rows)
	}
	reserved, err := st.RunnerReservedResources(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 5<<30 {
		t.Fatalf("reserved memory = %d, want the old leader's 5GiB", reserved.Memory)
	}
	if reason := pgITJobQueueReason(t, s, newRun.ID); reason != "RUNNER_CAPACITY" {
		t.Fatalf("waiter reason = %q, want RUNNER_CAPACITY", reason)
	}

	// The pre-existing lease ending releases its reservation; the waiter then
	// leases normally.
	if err := st.CompleteJob(context.Background(), oldJobID, 1, runner.ID, model.StatusSuccess, "", nil,
		model.CompletionReceipt{JobID: oldJobID, Generation: 1, RunnerID: runner.ID}); err != nil {
		t.Fatalf("complete pre-existing lease: %v", err)
	}
	if rows := pgITReservationRows(t, env); rows != 0 {
		t.Fatalf("ledger rows after completion = %d, want 0", rows)
	}
	task := pgITNext(t, s, runner.ID)
	if task.Job.RunID != newRun.ID {
		t.Fatalf("leased run = %s, want %s", task.Job.RunID, newRun.ID)
	}
	reserved, err = st.RunnerReservedResources(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 5<<30 {
		t.Fatalf("reserved memory after re-lease = %d, want 5GiB", reserved.Memory)
	}
}
