package storage

// Cross-feature composition: request-context cancellation at the durable
// ledger boundaries (lease claim with its quota install, and the
// leader-promotion reservation reconciliation).
//
// Both operations run in ONE transaction guarded by the leader fence and the
// reservation primary key. The composed contract is: a canceled call may
// commit nothing — the job stays queued, the reservation ledger stays empty
// and the repository quota counters do not move — while the next call with a
// live context succeeds and leaves exactly the state the transaction
// describes. A cancellation that lands MID-transaction must leave the
// ledger in one of the two whole states (rebuilt or untouched), never a
// partial mix.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// composeStoreExec runs one statement inside the test's schema.
func composeStoreExec(t *testing.T, env *pgITEnv, sql string, args ...any) {
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
		t.Fatalf("raw exec %q: %v", sql, err)
	}
}

// composeStoreLedgerCount returns the number of reservation rows for a job.
func composeStoreLedgerCount(t *testing.T, env *pgITEnv, jobID string) int {
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
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM job_resource_reservations WHERE job_id=$1`, jobID).Scan(&n); err != nil {
		t.Fatalf("count ledger rows: %v", err)
	}
	return n
}

// TestIntegrationComposeCanceledClaimLeavesNoClaimOrQuotaPostgres cancels the
// atomic lease claim before it starts and mid-flight, and asserts the world
// never observes a partial claim: the job stays queued, no reservation row
// exists, the runner's reserved sum is zero and the repository quota
// counters are untouched — after which the same claim succeeds.
func TestIntegrationComposeCanceledClaimLeavesNoClaimOrQuotaPostgres(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	pgITArmFence(t, st)

	runnerID := pgITNewID(t)
	profileID := pgITNewID(t)
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	repo := "https://example.com/compose/claim-cancel.git"
	request := model.ResourceCapacity{CPU: 1.5, Memory: 2 << 30, Disk: 1 << 30, PIDs: 32}
	pgITResourceProfileRunner(t, st, runnerID, profileID, 4, model.ResourceCapacity{})
	pgITResourceEnqueue(t, st, runID, jobID, repo, request)

	repoKey := RepoIDForJob(pgITResourceJob(runID, jobID, repo, request))
	runBefore, queuedBefore, err := st.QuotaCounts(context.Background(), repoKey, "")
	if err != nil {
		t.Fatalf("quota counts: %v", err)
	}
	if runBefore != 0 {
		t.Fatalf("running quota before the claim = %d, want 0", runBefore)
	}

	claim := pgITResourceClaim(jobID, runnerID, request)
	claim.RepoConcurrency = 1

	// A claim whose context is already canceled commits nothing.
	dead, cancelDead := context.WithCancel(context.Background())
	cancelDead()
	if _, err := st.AcquireLeaseAtomic(dead, claim); err == nil {
		t.Fatal("claim with a canceled context succeeded")
	}

	// The canceled-before-call claim left the world exactly as it was.
	job, err := st.GetJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	reserved, err := st.RunnerReservedResources(context.Background(), runnerID)
	if err != nil {
		t.Fatalf("reserved: %v", err)
	}
	rows, err := st.ListResourceReservations(context.Background(), runnerID)
	if err != nil {
		t.Fatalf("list reservations: %v", err)
	}
	runAfter, queuedAfter, err := st.QuotaCounts(context.Background(), repoKey, "")
	if err != nil {
		t.Fatalf("quota counts: %v", err)
	}
	if job.Status != model.StatusQueued {
		t.Fatalf("canceled claim left the job %s, want queued", job.Status)
	}
	if reserved != (model.ResourceCapacity{}) || len(rows) != 0 || composeStoreLedgerCount(t, env, jobID) != 0 {
		t.Fatalf("canceled claim leaked reservations: reserved=%+v rows=%d", reserved, len(rows))
	}
	if runAfter != runBefore || queuedAfter != queuedBefore {
		t.Fatalf("canceled claim moved quota counters: running %d->%d queued %d->%d", runBefore, runAfter, queuedBefore, queuedAfter)
	}

	// The next claim with a live context succeeds and installs exactly one
	// reservation row plus the quota transition.
	leased, err := st.AcquireLeaseAtomic(context.Background(), claim)
	if err != nil {
		t.Fatalf("claim after cancellation: %v", err)
	}
	if leased.ID != jobID || leased.Status != model.StatusRunning {
		t.Fatalf("claimed job = %s/%s, want %s/running", leased.ID, leased.Status, jobID)
	}
	reserved, err = st.RunnerReservedResources(context.Background(), runnerID)
	if err != nil {
		t.Fatalf("reserved after claim: %v", err)
	}
	if reserved != request {
		t.Fatalf("reserved after the successful claim = %+v, want %+v", reserved, request)
	}
	if got := composeStoreLedgerCount(t, env, jobID); got != 1 {
		t.Fatalf("ledger rows after the successful claim = %d, want 1", got)
	}
	runAfter, queuedAfter, err = st.QuotaCounts(context.Background(), repoKey, "")
	if err != nil {
		t.Fatalf("quota counts after claim: %v", err)
	}
	// The claim flips one queued job to running; the queued counter is
	// floored at zero, exactly as claimQuotaTx documents.
	wantQueued := queuedBefore - 1
	if wantQueued < 0 {
		wantQueued = 0
	}
	if runAfter != runBefore+1 || queuedAfter != wantQueued {
		t.Fatalf("quota counters after the claim: running %d->%d queued %d->%d (want running+1 and max(queued-1,0))", runBefore, runAfter, queuedBefore, queuedAfter)
	}
}

// TestIntegrationComposeCanceledReconcileLeavesLedgerConsistentPostgres
// cancels the leader-promotion reconciliation. A canceled pass must either
// rebuild the whole ledger or change nothing (it is ONE transaction), and the
// next pass must converge on the same ledger the uncanceled pass would leave.
func TestIntegrationComposeCanceledReconcileLeavesLedgerConsistentPostgres(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	pgITArmFence(t, st)

	runnerID := pgITNewID(t)
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	repo := "https://example.com/compose/reconcile-cancel.git"
	request := model.ResourceCapacity{Memory: 3 << 30, PIDs: 64}
	pgITResourceEnqueue(t, st, runID, jobID, repo, request)
	// The old-version lease shape: running with a live lease but no ledger
	// row (only an old leader could have written this).
	composeStoreExec(t, env, `UPDATE jobs SET status='running', lease_runner_id=$2, lease_token_hash='x'::bytea, lease_generation=3, lease_expires_at=now() + interval '1 hour' WHERE id=$1`, jobID, runnerID)
	if got := composeStoreLedgerCount(t, env, jobID); got != 0 {
		t.Fatalf("precondition: ledger rows = %d, want the legacy world's zero", got)
	}

	// A canceled pass changes nothing.
	dead, cancelDead := context.WithCancel(context.Background())
	cancelDead()
	if _, err := st.ReconcileResourceReservations(dead); err == nil {
		t.Fatal("reconcile with a canceled context succeeded")
	}
	if got := composeStoreLedgerCount(t, env, jobID); got != 0 {
		t.Fatalf("canceled reconcile left %d partial ledger row(s)", got)
	}
	if reserved, err := st.RunnerReservedResources(context.Background(), runnerID); err != nil || reserved != (model.ResourceCapacity{}) {
		t.Fatalf("canceled reconcile left reserved=%+v err=%v", reserved, err)
	}

	// A mid-flight cancellation must leave one of the two whole states.
	mid, cancelMid := context.WithTimeout(context.Background(), time.Millisecond)
	res, midErr := st.ReconcileResourceReservations(mid)
	cancelMid()
	if midErr != nil {
		if got := composeStoreLedgerCount(t, env, jobID); got != 0 {
			t.Fatalf("mid-flight canceled reconcile left %d partial row(s)", got)
		}
	} else {
		if res.Running != 1 || composeStoreLedgerCount(t, env, jobID) != 1 {
			t.Fatalf("raced reconcile result %+v with %d ledger rows, want a whole rebuild", res, composeStoreLedgerCount(t, env, jobID))
		}
	}

	// The next pass converges on the authoritative ledger.
	final, err := st.ReconcileResourceReservations(context.Background())
	if err != nil {
		t.Fatalf("reconcile after cancellation: %v", err)
	}
	if final.Running != 1 || final.Upserted != 1 || final.Deleted != 0 {
		t.Fatalf("converging reconcile = %+v, want Running/Upserted 1 and Deleted 0", final)
	}
	reserved, err := st.RunnerReservedResources(context.Background(), runnerID)
	if err != nil {
		t.Fatalf("reserved after reconcile: %v", err)
	}
	if reserved != request {
		t.Fatalf("reserved after the converging reconcile = %+v, want %+v", reserved, request)
	}
	// Idempotent: one more pass deletes nothing and rewrites the same row.
	again, err := st.ReconcileResourceReservations(context.Background())
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if again.Running != 1 || again.Upserted != 1 || again.Deleted != 0 {
		t.Fatalf("second reconcile = %+v, want the same whole ledger", again)
	}
}

// TestIntegrationComposeMidFlightCanceledClaimIsWholePostgres is the
// raced-commit half of the claim boundary: the claim is given a context that
// may expire while the transaction is in flight, and the store must leave
// either the pre-claim world or the complete post-claim world — never a
// queued job with a reservation row, nor a running job without one.
func TestIntegrationComposeMidFlightCanceledClaimIsWholePostgres(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	pgITArmFence(t, st)

	runnerID := pgITNewID(t)
	profileID := pgITNewID(t)
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	repo := "https://example.com/compose/claim-race.git"
	request := model.ResourceCapacity{CPU: 0.5, Memory: 1 << 30, PIDs: 8}
	pgITResourceProfileRunner(t, st, runnerID, profileID, 4, model.ResourceCapacity{})
	pgITResourceEnqueue(t, st, runID, jobID, repo, request)
	claim := pgITResourceClaim(jobID, runnerID, request)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	_, err := st.AcquireLeaseAtomic(ctx, claim)
	cancel()

	job, gerr := st.GetJob(context.Background(), jobID)
	if gerr != nil {
		t.Fatalf("get job: %v", gerr)
	}
	reserved, rerr := st.RunnerReservedResources(context.Background(), runnerID)
	if rerr != nil {
		t.Fatalf("reserved: %v", rerr)
	}
	if err != nil {
		if job.Status != model.StatusQueued || reserved != (model.ResourceCapacity{}) {
			t.Fatalf("canceled claim left job=%s reserved=%+v, want the whole pre-claim world", job.Status, reserved)
		}
		return
	}
	if job.Status != model.StatusRunning || reserved != request {
		t.Fatalf("committed claim left job=%s reserved=%+v, want the whole post-claim world", job.Status, reserved)
	}
}
