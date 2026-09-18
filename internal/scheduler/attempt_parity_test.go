package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// leasedParityJob returns a store whose single leader-scheduler job holds a
// REAL lease (attempts incremented once by the claim), then expires the
// lease so both recovery paths see the identical expired-lease state. The
// atomicFakeStore's embedded fakeStore implements the transactional
// RecoveryStore the kill switch and lease recovery now consume.
func leasedParityJob(t *testing.T, maxInfraRetries int) (*atomicFakeStore, *DBScheduler) {
	t.Helper()
	st := newAtomicFakeStore()
	st.setLeader(true, nil)
	now := time.Now().UTC()
	st.putRun(model.Run{ID: "run", Repo: "https://github.com/o/r.git", RepoFullName: "o/r", Status: model.StatusRunning, CreatedAt: now})
	st.putJob(model.Job{ID: "job", RunID: "run", Key: "build", RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r", Status: model.StatusQueued, MaxInfraRetries: maxInfraRetries, CreatedAt: now})
	st.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 1})
	s := NewDB(st, time.Minute, nil, nil)
	leased, _, _, err := s.Lease(context.Background(), "runner", time.Now().UTC())
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if leased.Attempts != 1 {
		t.Fatalf("lease attempts = %d, want the one lease-time increment", leased.Attempts)
	}
	expired := time.Now().UTC().Add(-time.Minute)
	leased.LeaseExpiresAt = &expired
	if err := st.UpdateJob(context.Background(), *leased); err != nil {
		t.Fatal(err)
	}
	return st, s
}

// releaseAttemptParityRunnerSlot clears the atomic fake's active set after a
// recovery pass, mirroring what the real store's release does, so the job can
// be re-leased by the parity assertion. The embedded fakeStore recovery
// updates the runner row; the atomic fake's separate capacity map is cleared
// here, exactly as before.
func releaseAttemptParityRunnerSlot(st *atomicFakeStore) {
	st.mu.Lock()
	delete(st.active, "runner")
	st.mu.Unlock()
}

// TestRecoveryAttemptParityLeaseExpiryAndRunnerDisable: lease-expiry recovery
// (RecoverExpired) and runner-disable recovery (CancelJobsByRunner) apply the
// SAME requeue/exhaustion decision to identical jobs and consume the SAME
// attempts count. Attempts are charged by the lease only: a recovery pass
// never increments them a second time, so N leases/executions means exactly
// N attempts on both paths.
func TestRecoveryAttemptParityLeaseExpiryAndRunnerDisable(t *testing.T) {
	ctx := context.Background()

	t.Run("requeue within budget", func(t *testing.T) {
		expiredStore, expiredSched := leasedParityJob(t, 2)
		disableStore, disableSched := leasedParityJob(t, 2)

		if err := expiredSched.RecoverExpired(ctx, time.Now().UTC()); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}
		if _, err := disableSched.CancelJobsByRunner(ctx, "runner", "runner disabled"); err != nil {
			t.Fatalf("CancelJobsByRunner: %v", err)
		}

		expiredJob, _ := expiredStore.job("job")
		disableJob, _ := disableStore.job("job")
		for name, j := range map[string]model.Job{"lease expiry": expiredJob, "runner disable": disableJob} {
			if j.Status != model.StatusQueued {
				t.Fatalf("%s status = %s, want queued (requeue branch)", name, j.Status)
			}
			if j.Attempts != 1 {
				t.Fatalf("%s attempts = %d, want 1 (the lease-time increment only)", name, j.Attempts)
			}
			if j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
				t.Fatalf("%s lease not cleared: %+v", name, j)
			}
		}
		if expiredJob.Attempts != disableJob.Attempts {
			t.Fatalf("attempt parity broken: lease expiry=%d runner disable=%d", expiredJob.Attempts, disableJob.Attempts)
		}

		// The budget decision is identical: both requeued jobs are leasable
		// again and the next lease consumes exactly one further attempt.
		releaseAttemptParityRunnerSlot(expiredStore)
		releaseAttemptParityRunnerSlot(disableStore)
		expiredRe, _, _, err := expiredSched.Lease(ctx, "runner", time.Now().UTC())
		if err != nil {
			t.Fatalf("re-lease after lease-expiry recovery: %v", err)
		}
		disableRe, _, _, err := disableSched.Lease(ctx, "runner", time.Now().UTC())
		if err != nil {
			t.Fatalf("re-lease after runner-disable recovery: %v", err)
		}
		if expiredRe.Attempts != 2 || disableRe.Attempts != 2 || expiredRe.Attempts != disableRe.Attempts {
			t.Fatalf("attempts after re-lease = lease expiry %d, runner disable %d; want 2/2", expiredRe.Attempts, disableRe.Attempts)
		}
	})

	t.Run("budget exhausted", func(t *testing.T) {
		expiredStore, expiredSched := leasedParityJob(t, 0)
		disableStore, disableSched := leasedParityJob(t, 0)

		if err := expiredSched.RecoverExpired(ctx, time.Now().UTC()); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}
		if _, err := disableSched.CancelJobsByRunner(ctx, "runner", "runner disabled"); err != nil {
			t.Fatalf("CancelJobsByRunner: %v", err)
		}

		expiredJob, _ := expiredStore.job("job")
		disableJob, _ := disableStore.job("job")
		if expiredJob.Attempts != 1 || disableJob.Attempts != 1 {
			t.Fatalf("attempts = lease expiry %d, runner disable %d; want 1/1 (no recovery increment)", expiredJob.Attempts, disableJob.Attempts)
		}
		// Same branch decision: both are terminal (no requeue), with the
		// terminal status each recovery path owns.
		if expiredJob.Status != model.StatusFailure {
			t.Fatalf("lease-expiry terminal status = %s, want failure", expiredJob.Status)
		}
		if disableJob.Status != model.StatusCancelled {
			t.Fatalf("runner-disable terminal status = %s, want cancelled", disableJob.Status)
		}
		if expiredJob.FinishedAt == nil || disableJob.FinishedAt == nil {
			t.Fatalf("terminal jobs missing finished_at: %+v / %+v", expiredJob, disableJob)
		}
	})
}
