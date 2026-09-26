package storage

// X2-C real-PostgreSQL regression: the repository-identity repair and
// CompleteJob must not deadlock, whichever way their transactions interleave.
//
// CompleteJob takes the job row first and the run row last (job -> run,
// through recomputeRunTx). The repair therefore locks a run's non-terminal
// child jobs BEFORE the run row and cancels exactly those locked child rows; it
// never waits for a job lock while holding a run lock. The test forces the
// deadlock-prone interleaving with deterministic database barriers only (no
// sleeps):
//
//  1. a barrier transaction locks the completing job's quota row, parking
//     CompleteJob AFTER it has locked the job row and BEFORE it can reach the
//     run row;
//  2. the repair is started and observed (pg_stat_activity, wait_event_type =
//     Lock) parked on the child job row CompleteJob holds;
//  3. the barrier releases, letting CompleteJob race to the run row.
//
// Pre-fix (run lock before the child locks) step 3 closes the cycle and
// PostgreSQL aborts one side with SQLSTATE 40P01; post-fix the repair waits at
// the child row before ever locking the run, both transactions commit, and the
// final state is consistent. The interleaving is repeated N times.

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const (
	pgITRepairLockOrderIterations = 5
	pgITRepairLockOrderOldRepo    = "github.com/acme/lockorder-old"
	pgITRepairLockOrderNewRepo    = "github.com/acme/lockorder-new"
	pgITRepairLockOrderRepoURL    = "https://github.com/acme/lockorder-new.git"
	pgITRepairLockOrderFullName   = "acme/lockorder-new"
)

// pgITWaitForLockBlockedQuery waits until some other backend in THIS database
// is active and blocked on a lock while running a statement matching the
// pattern. It is a state barrier (observed lock wait), never a sleep.
func pgITWaitForLockBlockedQuery(t *testing.T, st *PostgresStore, ctx context.Context, queryPattern string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		var blocked int
		if err := st.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM pg_stat_activity
			WHERE datname = current_database()
			  AND state = 'active'
			  AND wait_event_type = 'Lock'
			  AND query ILIKE $1
			  AND pid <> pg_backend_pid()`, queryPattern).Scan(&blocked); err != nil {
			t.Fatalf("observe a lock-blocked query matching %q: %v", queryPattern, err)
		}
		if blocked > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a query blocked on a lock matching %q", queryPattern)
		}
		runtime.Gosched()
	}
}

// pgITAwaitResult receives one concurrent transaction's result (or fails the
// test on a hung transaction).
func pgITAwaitResult(t *testing.T, ch <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(60 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return nil
	}
}

// TestPostgresIntegrationRepoIdentityRepairCompleteJobLockOrder is the X2-C
// regression. See the file comment for the barrier design.
func TestPostgresIntegrationRepoIdentityRepairCompleteJobLockOrder(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	for i := 0; i < pgITRepairLockOrderIterations; i++ {
		runID := pgITNewID(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)

		// The run and its child job carry the OLD identity; the clone URL
		// proves the NEW canonical one, so a --cancel-active repair would
		// drain and rewrite both.
		pgITInsertRunIdentityStatus(t, st, runID, "running",
			pgITRepairLockOrderOldRepo, pgITRepairLockOrderOldRepo, pgITRepairLockOrderRepoURL, pgITRepairLockOrderFullName)
		pgITInsertJobIdentityStatus(t, st, runID, jobID, "queued",
			pgITRepairLockOrderOldRepo, pgITRepairLockOrderOldRepo, pgITRepairLockOrderRepoURL, pgITRepairLockOrderFullName)
		pgITSeedRunner(t, st, runnerID, 2, 0, 0)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{
			JobID: jobID, RunnerID: runnerID, TokenHash: []byte("token"), Generation: 1,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}); err != nil {
			t.Fatalf("iteration %d: lease the child job: %v", i, err)
		}

		// Barrier: lock the quota rows CompleteJob adjusts right after the
		// job-row lock and before recomputeRunTx, so it parks holding the job
		// row (the exact job -> run prefix the repair must not invert).
		conn, err := st.pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("iteration %d: acquire the barrier connection: %v", i, err)
		}
		barrier, err := conn.Begin(ctx)
		if err != nil {
			conn.Release()
			t.Fatalf("iteration %d: begin the barrier transaction: %v", i, err)
		}
		for _, key := range QuotaKeys(pgITRepairLockOrderOldRepo) {
			if _, err := barrier.Exec(ctx, `SELECT 1 FROM quota_reservations WHERE key=$1 FOR UPDATE`, key); err != nil {
				_ = barrier.Rollback(ctx)
				conn.Release()
				t.Fatalf("iteration %d: lock quota row %q: %v", i, key, err)
			}
		}

		completeErr := make(chan error, 1)
		go func() {
			completeErr <- st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil,
				model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "lock-order-result"})
		}()
		pgITWaitForLockBlockedQuery(t, st, ctx, "%UPDATE quota_reservations%")

		repairErr := make(chan error, 1)
		go func() {
			_, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairApply, RepoIdentityRepairOptions{CancelActive: true})
			repairErr <- err
		}()
		pgITWaitForLockBlockedQuery(t, st, ctx, "%FROM jobs WHERE run_id=$1%")

		// Release: CompleteJob resumes toward the run row while the repair is
		// parked on the child job row. Pre-fix this is the cycle; post-fix the
		// repair cannot have taken the run lock yet.
		if err := barrier.Rollback(ctx); err != nil {
			t.Fatalf("iteration %d: release the barrier: %v", i, err)
		}
		conn.Release()

		errC := pgITAwaitResult(t, completeErr, "CompleteJob")
		errR := pgITAwaitResult(t, repairErr, "the repair")

		// No SQLSTATE 40P01, ever: it means PostgreSQL aborted one side of a
		// lock cycle, i.e. the lock order was violated. Any other error is
		// also unexpected.
		for _, res := range []struct {
			name string
			err  error
		}{{"CompleteJob", errC}, {"repair", errR}} {
			if res.err == nil {
				continue
			}
			var pgErr *pgconn.PgError
			if errors.As(res.err, &pgErr) && pgErr.Code == "40P01" {
				t.Fatalf("iteration %d: %s deadlocked (SQLSTATE 40P01) against the other transaction: %v", i, res.name, res.err)
			}
			t.Fatalf("iteration %d: %s failed: %v", i, res.name, res.err)
		}

		// Consistent final state, whichever side won:
		//   - the identity is the URL-proven NEW one for both rows (a
		//     terminal row is rewritten in place by the repair);
		//   - the job is terminal: CompleteJob's success with its receipt, or
		//     the repair's cancellation, never a lost/resurrected state;
		//   - the run is terminal.
		job, err := st.GetJob(ctx, jobID)
		if err != nil {
			t.Fatalf("iteration %d: get job: %v", i, err)
		}
		run, err := st.GetRun(ctx, runID)
		if err != nil {
			t.Fatalf("iteration %d: get run: %v", i, err)
		}
		if got := RepoIDForJob(job); got != pgITRepairLockOrderNewRepo {
			t.Fatalf("iteration %d: job identity = %q, want %q", i, got, pgITRepairLockOrderNewRepo)
		}
		if got := RepoIDForRun(run); got != pgITRepairLockOrderNewRepo {
			t.Fatalf("iteration %d: run identity = %q, want %q", i, got, pgITRepairLockOrderNewRepo)
		}
		if !run.Status.Terminal() {
			t.Fatalf("iteration %d: run status = %q, want terminal", i, run.Status)
		}
		if job.FinishedAt == nil {
			t.Fatalf("iteration %d: job has no finished_at", i)
		}
		switch job.Status {
		case model.StatusSuccess:
			// CompleteJob won the interleaving: its durable receipt proves the
			// repair never overwrote the terminal completion.
			var receipts int
			if err := st.pool.QueryRow(ctx,
				`SELECT count(*) FROM completion_receipts WHERE job_id=$1 AND generation=1 AND runner_id=$2`,
				jobID, runnerID).Scan(&receipts); err != nil {
				t.Fatalf("iteration %d: read completion receipt: %v", i, err)
			}
			if receipts != 1 {
				t.Fatalf("iteration %d: job is success but its completion receipt is missing", i)
			}
		case model.StatusCancelled:
			// The repair drained the job first: the terminal state is the
			// cancellation, and CompleteJob must not have been acked.
			if errC == nil {
				t.Fatalf("iteration %d: job was cancelled after CompleteJob reported success (lost terminal state)", i)
			}
		default:
			t.Fatalf("iteration %d: job status = %q, want success or cancelled", i, job.Status)
		}
	}
}
