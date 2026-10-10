package storage

// Third coverage round, part 3: approval writes, heartbeat TTL write arms and
// the schedule-occurrence claim. Same throwaway-database + seam-helper
// approach as the other gap files.

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPostgresIntegrationApproveJobArms(t *testing.T) {
	ctx := context.Background()

	seedApprovalRequired := func(t *testing.T, st *PostgresStore, jobID string) {
		t.Helper()
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{approval_required}', 'true') WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("notRequired", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		if _, err := st.ApproveJob(ctx, jobID, "alice"); !errors.Is(err, ErrApprovalNotRequired) {
			t.Fatalf("plain job approval = %v, want ErrApprovalNotRequired", err)
		}
	})

	t.Run("jobDecodeFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ApproveJob(ctx, jobID, "alice"); err == nil {
			t.Fatal("approval over an undecodable payload succeeded")
		}
	})

	t.Run("marshalFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		seedApprovalRequired(t, st, jobID)
		defer seamPGFailAll(t)()
		if _, err := st.ApproveJob(ctx, jobID, "alice"); err == nil {
			t.Fatal("approval with a failing encoder succeeded")
		}
	})

	t.Run("updateFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		seedApprovalRequired(t, st, jobID)
		pgITBoomOp(t, st, "jobs", "UPDATE")
		if _, err := st.ApproveJob(ctx, jobID, "alice"); err == nil {
			t.Fatal("approval with a failing job update succeeded")
		}
	})

	t.Run("eventAppendFail", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		seedApprovalRequired(t, st, jobID)
		pgITBoomOp(t, st, "execution_events", "INSERT")
		if _, err := st.ApproveJob(ctx, jobID, "alice"); err == nil {
			t.Fatal("approval with a failing semantic event append succeeded")
		}
		if j, err := st.GetJob(ctx, jobID); err != nil || j.ApprovedBy != "" {
			t.Fatalf("rolled-back approval persisted approver %q, %v", j.ApprovedBy, err)
		}
	})

	t.Run("approvesWaitingJob", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		seedApprovalRequired(t, st, jobID)
		j, err := st.ApproveJob(ctx, jobID, "alice")
		if err != nil || j.ApprovedBy != "alice" {
			t.Fatalf("approval = %+v, %v", j, err)
		}
	})
}

func TestPostgresIntegrationHeartbeatLeaseWithTTLArms(t *testing.T) {
	ctx := context.Background()

	t.Run("badTTL", func(t *testing.T) {
		if _, err := (&PostgresStore{}).HeartbeatLeaseWithTTL(ctx, pgITNewID(t), "r", 1, 0); err == nil {
			t.Fatal("non-positive heartbeat TTL was accepted")
		}
	})

	t.Run("closedPool", func(t *testing.T) {
		st := pgITStore(t)
		st.Close()
		if _, err := st.HeartbeatLeaseWithTTL(ctx, pgITNewID(t), "r", 1, time.Minute); err == nil {
			t.Fatal("heartbeat over a closed pool succeeded")
		}
	})

	t.Run("updateFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		pgITBoomOp(t, st, "jobs", "UPDATE")
		if _, err := st.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, 1, time.Minute); err == nil {
			t.Fatal("heartbeat with a failing lease update succeeded")
		}
	})

	t.Run("renewsLiveLease", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		expires, err := st.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, 1, 2*time.Hour)
		if err != nil {
			t.Fatalf("live heartbeat = %v", err)
		}
		if time.Until(expires) < time.Hour {
			t.Fatalf("heartbeat expiry %s was not extended by the TTL", expires)
		}
	})

	t.Run("expiredLeaseMiss", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = now() - interval '1 hour' WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, 1, time.Minute); err == nil {
			t.Fatal("heartbeat renewed an expired lease")
		}
	})

	t.Run("wrongRunnerMiss", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		if _, err := st.HeartbeatLeaseWithTTL(ctx, jobID, pgITNewID(t), 1, time.Minute); err == nil {
			t.Fatal("heartbeat from a foreign runner succeeded")
		}
	})

	t.Run("jobNotFound", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.HeartbeatLeaseWithTTL(ctx, pgITNewID(t), "runner-x", 1, time.Minute); !errors.Is(err, ErrNotFound) {
			t.Fatalf("heartbeat for a missing job = %v, want ErrNotFound", err)
		}
	})
}

func TestPostgresIntegrationClaimScheduleOccurrenceArms(t *testing.T) {
	ctx := context.Background()
	nominal := time.Now().UTC().Truncate(time.Minute)

	t.Run("validation", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.ClaimScheduleOccurrence(ctx, "", nominal, pgITNewID(t)); err == nil {
			t.Fatal("empty schedule id was accepted")
		}
		if _, err := st.ClaimScheduleOccurrence(ctx, "sched-1", nominal, ""); err == nil {
			t.Fatal("empty run id was accepted")
		}
	})

	t.Run("insertFail", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoomOp(t, st, "schedule_occurrences", "INSERT")
		if _, err := st.ClaimScheduleOccurrence(ctx, "sched-1", nominal, pgITNewID(t)); err == nil {
			t.Fatal("occurrence claim with a failing insert succeeded")
		}
	})

	t.Run("unobservedClaimLoses", func(t *testing.T) {
		st := pgITStore(t)
		pgITSkipWrites(t, st, "schedule_occurrences", "INSERT")
		won, err := st.ClaimScheduleOccurrence(ctx, "sched-1", nominal, pgITNewID(t))
		if err != nil || won {
			t.Fatalf("claim with no durable row = %v, %v; want false,nil", won, err)
		}
	})

	t.Run("firstWinsSecondLoses", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(ctx, `INSERT INTO schedules (id, repository, repo_id, repo_url, forge, trusted, spec, enabled, created_at) VALUES ('sched-1','repo','github.com/o/r','https://github.com/o/r.git','github',true,'version: 1',true,now())`); err != nil {
			t.Fatal(err)
		}
		first, second := pgITNewID(t), pgITNewID(t)
		won, err := st.ClaimScheduleOccurrence(ctx, "sched-1", nominal, first)
		if err != nil || !won {
			t.Fatalf("first claim = %v, %v; want true,nil", won, err)
		}
		won, err = st.ClaimScheduleOccurrence(ctx, "sched-1", nominal, second)
		if err != nil || won {
			t.Fatalf("second claim = %v, %v; want false,nil", won, err)
		}
		won, err = st.ClaimScheduleOccurrence(ctx, "sched-1", nominal, first)
		if err != nil || !won {
			t.Fatalf("idempotent re-claim = %v, %v; want true,nil", won, err)
		}
	})
}
