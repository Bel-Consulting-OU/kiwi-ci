package storage

// Third coverage round, part 2: runner-lease revocation, expired-lease
// recovery, queue-timeout expiry, migration apply arms and the leadership
// session cache. Same throwaway-database + seam-helper approach as
// postgres_gap3_it_test.go.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// gapITLeaseRunning seeds one queued run/job, claims it for runnerID and
// returns the leased job.
func gapITLeaseRunning(t *testing.T, st *PostgresStore, runnerID string) (string, string, model.Job) {
	t.Helper()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	leased := gapITLeaseObject(t, st, jobID, runnerID)
	return runID, jobID, leased
}

// gapITSeedRunnerSlot seeds a runner row whose active_jobs already contains
// jobID, so slot-release statements have a matching row to update.
func gapITSeedRunnerSlot(t *testing.T, st *PostgresStore, runnerID, jobID string) {
	t.Helper()
	pgITSeedRunner(t, st, runnerID, 4, 0, 0)
	if _, err := st.pool.Exec(context.Background(), `UPDATE runners SET active_jobs=jsonb_build_array($2::text), busy=TRUE WHERE id=$1`, runnerID, jobID); err != nil {
		t.Fatal(err)
	}
}

// gapITBoomOnFailedCounter fails only runner updates that move the failure
// counter, so releaseRunnerSlotTx (active_jobs only) still succeeds.
func gapITBoomOnFailedCounter(t *testing.T, st *PostgresStore) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION kiwi_boom_failed_counter() RETURNS trigger AS $$ BEGIN IF NEW.failed <> OLD.failed THEN RAISE EXCEPTION 'injected failed-counter failure'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `CREATE TRIGGER kiwi_boom_failed_counter_t BEFORE UPDATE ON runners FOR EACH ROW EXECUTE FUNCTION kiwi_boom_failed_counter()`); err != nil {
		t.Fatal(err)
	}
}

func gapITDropQuotaTable(t *testing.T, st *PostgresStore) {
	t.Helper()
	if _, err := st.pool.Exec(context.Background(), `DROP TABLE quota_reservations`); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresIntegrationRevokeRunnerLeasesArms(t *testing.T) {
	ctx := context.Background()

	t.Run("invalidRunnerID", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.RevokeRunnerLeases(ctx, "short", "gap"); err == nil {
			t.Fatal("invalid runner id was accepted")
		}
	})

	t.Run("jobScanFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, _, _ = gapITLeaseRunning(t, st, runnerID)
		pgITBreakColumnToArray(t, st, "jobs", "key")
		if _, err := st.RevokeRunnerLeases(ctx, runnerID, "gap scan"); err == nil {
			t.Fatal("revocation over a mistyped job key succeeded")
		}
	})

	t.Run("jobDecodeFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.RevokeRunnerLeases(ctx, runnerID, "gap decode"); err == nil {
			t.Fatal("revocation over an undecodable payload succeeded")
		}
	})

	t.Run("marshalFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, _, _ = gapITLeaseRunning(t, st, runnerID)
		defer seamPGFailAll(t)()
		if _, err := st.RevokeRunnerLeases(ctx, runnerID, "gap marshal"); err == nil {
			t.Fatal("revocation with a failing encoder succeeded")
		}
	})

	t.Run("jobUpdateFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		pgITBoomOp(t, st, "jobs", "UPDATE")
		if _, err := st.RevokeRunnerLeases(ctx, runnerID, "gap update"); err == nil {
			t.Fatal("revocation with a failing job update succeeded")
		}
		if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusRunning {
			t.Fatalf("job after failed revocation = %+v, %v; want still running", j, err)
		}
	})

	t.Run("resourceReleaseFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		if _, err := st.pool.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id) VALUES ($1,$2)`, jobID, runnerID); err != nil {
			t.Fatal(err)
		}
		pgITBoomOp(t, st, "job_resource_reservations", "DELETE")
		if _, err := st.RevokeRunnerLeases(ctx, runnerID, "gap resources"); err == nil {
			t.Fatal("revocation with a failing resource release succeeded")
		}
	})

	t.Run("quotaFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, _, _ = gapITLeaseRunning(t, st, runnerID)
		gapITDropQuotaTable(t, st)
		if _, err := st.RevokeRunnerLeases(ctx, runnerID, "gap quota"); err == nil {
			t.Fatal("revocation with a missing quota table succeeded")
		}
	})

	t.Run("auditFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, _, _ = gapITLeaseRunning(t, st, runnerID)
		pgITBoomOp(t, st, "audit_events", "INSERT")
		if _, err := st.RevokeRunnerLeases(ctx, runnerID, "gap audit"); err == nil {
			t.Fatal("revocation with a failing audit insert succeeded")
		}
	})

	t.Run("runnerSlotFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		gapITSeedRunnerSlot(t, st, runnerID, jobID)
		pgITBoomOp(t, st, "runners", "UPDATE")
		if _, err := st.RevokeRunnerLeases(ctx, runnerID, "gap slot"); err == nil {
			t.Fatal("revocation with a failing runner slot update succeeded")
		}
	})

	t.Run("failedCounterFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		gapITSeedRunnerSlot(t, st, runnerID, jobID)
		gapITBoomOnFailedCounter(t, st)
		if _, err := st.RevokeRunnerLeases(ctx, runnerID, "gap counter"); err == nil {
			t.Fatal("revocation with a failing runner counter update succeeded")
		}
	})

	t.Run("cancelBranch", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET attempts=99 WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		revoked, err := st.RevokeRunnerLeases(ctx, runnerID, "gap exhausted")
		if err != nil {
			t.Fatalf("exhausted-budget revocation = %v", err)
		}
		if len(revoked) != 1 || revoked[0] != jobID {
			t.Fatalf("revoked = %v, want [%s]", revoked, jobID)
		}
		j, err := st.GetJob(ctx, jobID)
		if err != nil || j.Status != model.StatusCancelled || j.FinishedAt == nil {
			t.Fatalf("exhausted job = %+v, %v; want terminal cancellation", j, err)
		}
	})

	t.Run("requeueBranch", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET attempts=0 WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		revoked, err := st.RevokeRunnerLeases(ctx, runnerID, "gap requeue")
		if err != nil {
			t.Fatalf("requeue revocation = %v", err)
		}
		if len(revoked) != 1 || revoked[0] != jobID {
			t.Fatalf("revoked = %v, want [%s]", revoked, jobID)
		}
		j, err := st.GetJob(ctx, jobID)
		if err != nil || j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
			t.Fatalf("requeued job = %+v, %v; want queued with cleared lease", j, err)
		}
	})

	t.Run("dependentsFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		pgITDropFKsOn(t, st, "job_dependencies")
		if _, err := st.pool.Exec(ctx, `INSERT INTO job_dependencies (job_id, depends_on) VALUES ($1,$2)`, pgITNewID(t), jobID); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToBytea(t, st, "job_dependencies", "job_id")
		if _, err := st.RevokeRunnerLeases(ctx, runnerID, "gap deps"); err == nil {
			t.Fatal("revocation with a mistyped dependency column succeeded")
		}
	})
}

func TestPostgresIntegrationRecoverExpiredLeaseArms(t *testing.T) {
	ctx := context.Background()

	expire := func(t *testing.T, st *PostgresStore, jobID string) {
		t.Helper()
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = now() - interval '1 hour' WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("notFound", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.RecoverExpiredLease(ctx, pgITNewID(t), 1, time.Now()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing job recovery = %v, want ErrNotFound", err)
		}
	})

	t.Run("scanFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		pgITBreakColumnToArray(t, st, "jobs", "key")
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("recovery over a mistyped key succeeded")
		}
	})

	t.Run("marshalFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		defer seamPGFailAll(t)()
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("recovery with a failing encoder succeeded")
		}
	})

	t.Run("jobUpdateFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		pgITBoomOp(t, st, "jobs", "UPDATE")
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("recovery with a failing job update succeeded")
		}
	})

	t.Run("resourceReleaseFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		if _, err := st.pool.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id) VALUES ($1,$2)`, jobID, runnerID); err != nil {
			t.Fatal(err)
		}
		pgITBoomOp(t, st, "job_resource_reservations", "DELETE")
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("recovery with a failing resource release succeeded")
		}
	})

	t.Run("quotaFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		gapITDropQuotaTable(t, st)
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("recovery with a missing quota table succeeded")
		}
	})

	t.Run("runnerSlotFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		gapITSeedRunnerSlot(t, st, runnerID, jobID)
		pgITBoomOp(t, st, "runners", "UPDATE")
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("recovery with a failing runner slot update succeeded")
		}
	})

	t.Run("failedCounterFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		gapITSeedRunnerSlot(t, st, runnerID, jobID)
		gapITBoomOnFailedCounter(t, st)
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("recovery with a failing runner counter update succeeded")
		}
	})

	t.Run("auditFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		pgITBoomOp(t, st, "audit_events", "INSERT")
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("recovery with a failing audit insert succeeded")
		}
	})

	t.Run("dependentsFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		pgITDropFKsOn(t, st, "job_dependencies")
		if _, err := st.pool.Exec(ctx, `INSERT INTO job_dependencies (job_id, depends_on) VALUES ($1,$2)`, pgITNewID(t), jobID); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToBytea(t, st, "job_dependencies", "job_id")
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("recovery with a mistyped dependency column succeeded")
		}
	})

	t.Run("runAggregationFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		pgITBoomOp(t, st, "runs", "UPDATE")
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("recovery with a failing run aggregation succeeded")
		}
	})

	t.Run("requeue", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET attempts=0 WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err != nil {
			t.Fatalf("expired lease recovery = %v", err)
		}
		j, err := st.GetJob(ctx, jobID)
		if err != nil || j.Status != model.StatusQueued {
			t.Fatalf("recovered job = %+v, %v; want queued", j, err)
		}
	})

	t.Run("corruptPayload", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb, lease_expires_at = now() - interval '1 hour' WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err != nil {
			t.Fatalf("corrupt lease recovery = %v", err)
		}
		// The corrupt payload is left untouched as evidence; the relational
		// columns carry the terminal state.
		var status, leaseRunner string
		if err := st.pool.QueryRow(ctx, `SELECT status, COALESCE(lease_runner_id,'') FROM jobs WHERE id=$1`, jobID).Scan(&status, &leaseRunner); err != nil {
			t.Fatal(err)
		}
		if status != string(model.StatusFailure) || leaseRunner != "" {
			t.Fatalf("corrupt lease columns = status %q runner %q; want terminal failure with cleared lease", status, leaseRunner)
		}
	})

	t.Run("corruptRepoLookupFail", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb, lease_expires_at = now() - interval '1 hour' WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "runs", "payload")
		if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now()); err == nil {
			t.Fatal("corrupt recovery with an unreadable run identity succeeded")
		}
	})

	t.Run("staleGenerationNoop", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		_, jobID, _ := gapITLeaseRunning(t, st, runnerID)
		expire(t, st, jobID)
		if err := st.RecoverExpiredLease(ctx, jobID, 7, time.Now()); err != nil {
			t.Fatalf("stale-generation recovery = %v", err)
		}
		j, err := st.GetJob(ctx, jobID)
		if err != nil || j.Status != model.StatusRunning {
			t.Fatalf("stale-generation job = %+v, %v; want untouched running", j, err)
		}
	})
}

func TestPostgresIntegrationExpireQueuedJobArms(t *testing.T) {
	ctx := context.Background()

	seed := func(t *testing.T, st *PostgresStore) (string, time.Time) {
		t.Helper()
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		deadline := time.Now().UTC().Add(-time.Hour)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET queue_deadline=$2::timestamptz WHERE id=$1`, jobID, deadline); err != nil {
			t.Fatal(err)
		}
		return jobID, deadline
	}

	t.Run("notFound", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.ExpireQueuedJob(ctx, pgITNewID(t), time.Now().Add(-time.Hour)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing queued job expiry = %v, want ErrNotFound", err)
		}
	})

	t.Run("scanFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		pgITBreakColumnToBytea(t, st, "jobs", "queue_deadline")
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
			t.Fatal("expiry over a mistyped deadline column succeeded")
		}
	})

	t.Run("jobUpdateFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		pgITBoomOp(t, st, "jobs", "UPDATE")
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
			t.Fatal("expiry with a failing job update succeeded")
		}
	})

	t.Run("corruptUpdateFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		pgITBoomOp(t, st, "jobs", "UPDATE")
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
			t.Fatal("corrupt expiry with a failing column-only update succeeded")
		}
	})

	t.Run("marshalFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		defer seamPGFailAll(t)()
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
			t.Fatal("expiry with a failing encoder succeeded")
		}
	})

	t.Run("resourceReleaseFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		if _, err := st.pool.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id) VALUES ($1,'gap')`, jobID); err != nil {
			t.Fatal(err)
		}
		pgITBoomOp(t, st, "job_resource_reservations", "DELETE")
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
			t.Fatal("expiry with a failing resource release succeeded")
		}
	})

	t.Run("quotaFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		gapITDropQuotaTable(t, st)
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
			t.Fatal("expiry with a missing quota table succeeded")
		}
	})

	t.Run("auditFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		pgITBoomOp(t, st, "audit_events", "INSERT")
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
			t.Fatal("expiry with a failing audit insert succeeded")
		}
	})

	t.Run("dependentsFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		pgITDropFKsOn(t, st, "job_dependencies")
		if _, err := st.pool.Exec(ctx, `INSERT INTO job_dependencies (job_id, depends_on) VALUES ($1,$2)`, pgITNewID(t), jobID); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToBytea(t, st, "job_dependencies", "job_id")
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
			t.Fatal("expiry with a mistyped dependency column succeeded")
		}
	})

	t.Run("runAggregationFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		pgITBoomOp(t, st, "runs", "UPDATE")
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
			t.Fatal("expiry with a failing run aggregation succeeded")
		}
	})

	t.Run("corruptRepoLookupFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "runs", "payload")
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
			t.Fatal("corrupt expiry with an unreadable run identity succeeded")
		}
	})

	t.Run("cancelsAndReleases", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err != nil {
			t.Fatalf("queue timeout expiry = %v", err)
		}
		j, err := st.GetJob(ctx, jobID)
		if err != nil || j.Status != model.StatusCancelled || j.FinishedAt == nil {
			t.Fatalf("expired job = %+v, %v; want terminal cancellation", j, err)
		}
	})

	t.Run("corruptPayloadColumnDeadline", func(t *testing.T) {
		st := pgITStore(t)
		jobID, deadline := seed(t, st)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		if err := st.ExpireQueuedJob(ctx, jobID, deadline); err != nil {
			t.Fatalf("corrupt queue expiry = %v", err)
		}
		var status string
		if err := st.pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, jobID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != string(model.StatusCancelled) {
			t.Fatalf("corrupt expired job status = %q, want cancelled", status)
		}
	})
}

func TestPostgresIntegrationApplyMigrationArms(t *testing.T) {
	ctx := context.Background()

	t.Run("beginFailClosedPool", func(t *testing.T) {
		st := pgITStore(t)
		st.Close()
		all, err := migrations.All()
		if err != nil {
			t.Fatal(err)
		}
		if err := st.applyMigration(ctx, all[0]); err == nil {
			t.Fatal("applyMigration over a closed pool succeeded")
		}
	})

	t.Run("identityDDLOnView", func(t *testing.T) {
		env := pgITSetupFresh(t)
		st := env.open(t)
		if _, err := st.pool.Exec(ctx, `CREATE VIEW schema_migrations AS SELECT 1::bigint AS version`); err != nil {
			t.Fatal(err)
		}
		if err := st.Migrate(ctx); err == nil {
			t.Fatal("Migrate over a schema_migrations view succeeded")
		}
	})

	t.Run("appliedProbeTypeMismatch", func(t *testing.T) {
		env := pgITSetupFresh(t)
		st := env.open(t)
		if _, err := st.pool.Exec(ctx, `CREATE TABLE schema_migrations (version BIGINT PRIMARY KEY, name TEXT, sha256 INTEGER, compatible_from INTEGER)`); err != nil {
			t.Fatal(err)
		}
		if err := st.Migrate(ctx); err == nil {
			t.Fatal("Migrate over a mistyped schema_migrations succeeded")
		}
	})

	t.Run("nameDivergence", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET name='tampered-name' WHERE version=(SELECT MIN(version) FROM schema_migrations)`); err != nil {
			t.Fatal(err)
		}
		if err := st.Migrate(ctx); err == nil {
			t.Fatal("Migrate over a tampered migration name succeeded")
		}
	})

	t.Run("preIdentityUpdateFail", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET name='', sha256='' WHERE version=(SELECT MIN(version) FROM schema_migrations)`); err != nil {
			t.Fatal(err)
		}
		pgITBoomOp(t, st, "schema_migrations", "UPDATE")
		if err := st.Migrate(ctx); err == nil {
			t.Fatal("Migrate with a failing identity backfill succeeded")
		}
	})

	t.Run("preflightFail", func(t *testing.T) {
		env := pgITSetupAtVersion(t, 42)
		st := env.open(t)
		if _, err := st.pool.Exec(ctx, `CREATE VIEW generated_fragments_conflicts AS SELECT 1 AS dummy`); err != nil {
			t.Fatal(err)
		}
		if err := st.Migrate(ctx); err == nil {
			t.Fatal("Migrate with a failing preflight succeeded")
		}
	})
}

func TestPostgresIntegrationAcquireLeaderSessionArms(t *testing.T) {
	ctx := context.Background()

	t.Run("noPool", func(t *testing.T) {
		st := &PostgresStore{}
		got, done, err := st.acquireLeaderSession(ctx, "gap-key", time.Minute, time.Second)
		if err == nil || got || !done {
			t.Fatalf("no-pool acquire = got %v done %v err %v; want error, done", got, done, err)
		}
	})

	t.Run("cachedFreshAndStale", func(t *testing.T) {
		st := pgITStore(t)
		conn, err := pgx.ConnectConfig(ctx, st.pool.Config().ConnConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(ctx) }()
		st.leaderMu.Lock()
		st.leaderConn = conn
		st.leaderKey = "gap-cached"
		st.leaderHeldUntil = time.Now().Add(time.Minute)
		st.leaderProbedAt = time.Now()
		st.leaderEpoch.Store(1)
		st.leaderMu.Unlock()
		t.Cleanup(func() {
			st.leaderMu.Lock()
			st.leaderConn = nil
			st.leaderKey = ""
			st.leaderEpoch.Store(0)
			st.leaderMu.Unlock()
		})

		got, done, err := st.acquireLeaderSession(ctx, "gap-cached", time.Minute, time.Hour)
		if err != nil || !got || !done {
			t.Fatalf("fresh cached acquire = got %v done %v err %v; want true,true,nil", got, done, err)
		}
		got, done, err = st.acquireLeaderSession(ctx, "gap-cached", time.Minute, 0)
		if err != nil || got || done {
			t.Fatalf("stale cached acquire = got %v done %v err %v; want false,false,nil", got, done, err)
		}
	})
}
