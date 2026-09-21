package scheduler

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// injectedStore wraps the shared fakeStore with settable failures so every
// scheduler error branch can be driven deterministically.
type injectedStore struct {
	*fakeStore
	getRunnerErr     error
	listQueuedErr    error
	listByEnvErr     error
	listByRunErr     error
	updateJobErr     error
	upsertRunnerErr  error
	heartbeatErr     error
	heartbeatHook    func()
	cancelRunErr     error
	listRunsErr      error
	listExpiredErr   error
	listQueueTOErr   error
	profileErr       error
	acquireLeaseHook func(jobID string) error
	recoverHook      func(jobID string) error
	expireHook       func(jobID string) error
	clearStartedAt   bool

	// Discovery call counters prove the sweep pages (and how often).
	listExpiredCalls int
	listQueueTOCalls int
}

func newInjectedStore() *injectedStore {
	return &injectedStore{fakeStore: newFakeStore()}
}

func (s *injectedStore) GetRunner(ctx context.Context, id string) (model.Runner, error) {
	if s.getRunnerErr != nil {
		return model.Runner{}, s.getRunnerErr
	}
	return s.fakeStore.GetRunner(ctx, id)
}

func (s *injectedStore) ListQueuedJobs(ctx context.Context) ([]model.Job, error) {
	if s.listQueuedErr != nil {
		return nil, s.listQueuedErr
	}
	return s.fakeStore.ListQueuedJobs(ctx)
}

func (s *injectedStore) ListJobsByEnvironment(ctx context.Context, repoID, environment string) ([]model.Job, error) {
	if s.listByEnvErr != nil {
		return nil, s.listByEnvErr
	}
	return s.fakeStore.ListJobsByEnvironment(ctx, repoID, environment)
}

func (s *injectedStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	if s.listByRunErr != nil {
		return nil, s.listByRunErr
	}
	return s.fakeStore.ListJobsByRun(ctx, runID)
}

func (s *injectedStore) UpdateJob(ctx context.Context, j model.Job) error {
	if s.updateJobErr != nil {
		return s.updateJobErr
	}
	return s.fakeStore.UpdateJob(ctx, j)
}

func (s *injectedStore) UpsertRunner(ctx context.Context, r model.Runner) error {
	if s.upsertRunnerErr != nil {
		return s.upsertRunnerErr
	}
	return s.fakeStore.UpsertRunner(ctx, r)
}

func (s *injectedStore) HeartbeatLease(ctx context.Context, jobID, runnerID string, generation int64, expiresAt time.Time) error {
	if s.heartbeatHook != nil {
		s.heartbeatHook()
	}
	if s.heartbeatErr != nil {
		return s.heartbeatErr
	}
	return s.fakeStore.HeartbeatLease(ctx, jobID, runnerID, generation, expiresAt)
}

func (s *injectedStore) CancelRunJobs(ctx context.Context, runID, reason string) ([]string, error) {
	if s.cancelRunErr != nil {
		return nil, s.cancelRunErr
	}
	return s.fakeStore.CancelRunJobs(ctx, runID, reason)
}

func (s *injectedStore) ListRuns(ctx context.Context, limit int) ([]model.Run, error) {
	if s.listRunsErr != nil {
		return nil, s.listRunsErr
	}
	return s.fakeStore.ListRuns(ctx, limit)
}

func (s *injectedStore) ListExpiredRunningJobs(ctx context.Context, now time.Time, afterID string, limit int) ([]storage.RecoveryCandidate, error) {
	s.listExpiredCalls++
	if s.listExpiredErr != nil {
		return nil, s.listExpiredErr
	}
	return s.fakeStore.ListExpiredRunningJobs(ctx, now, afterID, limit)
}

func (s *injectedStore) ListQueueTimedOutJobs(ctx context.Context, now time.Time, afterID string, limit int) ([]storage.RecoveryCandidate, error) {
	s.listQueueTOCalls++
	if s.listQueueTOErr != nil {
		return nil, s.listQueueTOErr
	}
	return s.fakeStore.ListQueueTimedOutJobs(ctx, now, afterID, limit)
}

// RecoverExpiredLease lets a test fail ONE candidate persistently while the
// others in the same sweep recover, proving the sweep's cursor advances past
// a failed apply.
func (s *injectedStore) RecoverExpiredLease(ctx context.Context, jobID string, expectedGeneration int64, now time.Time) error {
	if s.recoverHook != nil {
		if err := s.recoverHook(jobID); err != nil {
			return err
		}
	}
	return s.fakeStore.RecoverExpiredLease(ctx, jobID, expectedGeneration, now)
}

// ExpireQueuedJob is the queue-timeout counterpart of the recover hook.
func (s *injectedStore) ExpireQueuedJob(ctx context.Context, jobID string, deadline time.Time) error {
	if s.expireHook != nil {
		if err := s.expireHook(jobID); err != nil {
			return err
		}
	}
	return s.fakeStore.ExpireQueuedJob(ctx, jobID, deadline)
}

func (s *injectedStore) ProfileForSerial(ctx context.Context, serial string) (model.RunnerProfile, bool, error) {
	if s.profileErr != nil {
		return model.RunnerProfile{}, false, s.profileErr
	}
	return s.fakeStore.ProfileForSerial(ctx, serial)
}

func (s *injectedStore) AcquireLease(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (model.Job, error) {
	if s.acquireLeaseHook != nil {
		if err := s.acquireLeaseHook(jobID); err != nil {
			return model.Job{}, err
		}
	}
	j, err := s.fakeStore.AcquireLease(ctx, jobID, runnerID, tokenHash, generation, expiresAt)
	if s.clearStartedAt {
		j.StartedAt = nil
	}
	return j, err
}

// leaseFixture seeds one queued job and one matching idle runner.
func leaseFixture(t *testing.T, st *fakeStore, job model.Job, runner model.Runner) time.Time {
	t.Helper()
	now := time.Now().UTC()
	ctx := context.Background()
	if err := st.InsertRun(ctx, model.Run{ID: job.RunID, Status: model.StatusQueued, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	if err := st.InsertJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	runner.Capacity = max(runner.Capacity, 1)
	if len(runner.Labels) == 0 {
		runner.Labels = []string{"container"}
	}
	if err := st.UpsertRunner(ctx, runner); err != nil {
		t.Fatal(err)
	}
	st.leaderOK = true
	return now
}

func TestIsLeaderNilStoreAndStoreError(t *testing.T) {
	s := &DBScheduler{LeaderKey: "k", LeaderTTL: time.Second}
	if s.IsLeader(context.Background()) {
		t.Fatal("nil store must not be leader")
	}

	st := newFakeStore()
	st.setLeader(false, errors.New("advisory lock unavailable"))
	s = NewDB(st, time.Second, nil, nil)
	if s.InitErr() == nil {
		t.Fatal("construction must record the leadership store error")
	}
	if s.IsLeader(context.Background()) {
		t.Fatal("a failing store must report not-leader")
	}
}

func TestLeaseStoreErrorPaths(t *testing.T) {
	ctx := context.Background()
	baseJob := model.Job{ID: "job-1", RunID: "run-1", Key: "build", Status: model.StatusQueued, RequiredLabels: []string{"container"}}
	baseRunner := model.Runner{ID: "runner-1", Name: "r1"}

	t.Run("get runner", func(t *testing.T) {
		st := newInjectedStore()
		now := leaseFixture(t, st.fakeStore, baseJob, baseRunner)
		st.getRunnerErr = errors.New("runner lookup failed")
		s := NewDB(st, time.Second, nil, nil)
		if _, _, _, err := s.Lease(ctx, "runner-1", now); err == nil || !strings.Contains(err.Error(), "runner lookup failed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("list queued", func(t *testing.T) {
		st := newInjectedStore()
		now := leaseFixture(t, st.fakeStore, baseJob, baseRunner)
		st.listQueuedErr = errors.New("queue listing failed")
		s := NewDB(st, time.Second, nil, nil)
		if _, _, _, err := s.Lease(ctx, "runner-1", now); err == nil || !strings.Contains(err.Error(), "queue listing failed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("list environment", func(t *testing.T) {
		st := newInjectedStore()
		job := baseJob
		job.Environment = "staging"
		job.EnvironmentConcurrency = 2
		job.RepoURL = "https://github.com/o/r.git"
		now := leaseFixture(t, st.fakeStore, job, baseRunner)
		st.listByEnvErr = errors.New("environment listing failed")
		s := NewDB(st, time.Second, nil, nil)
		if _, _, _, err := s.Lease(ctx, "runner-1", now); err == nil || !strings.Contains(err.Error(), "environment listing failed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("list run jobs", func(t *testing.T) {
		st := newInjectedStore()
		now := leaseFixture(t, st.fakeStore, baseJob, baseRunner)
		st.listByRunErr = errors.New("run listing failed")
		s := NewDB(st, time.Second, nil, nil)
		if _, _, _, err := s.Lease(ctx, "runner-1", now); err == nil || !strings.Contains(err.Error(), "run listing failed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("token generation", func(t *testing.T) {
		st := newInjectedStore()
		now := leaseFixture(t, st.fakeStore, baseJob, baseRunner)
		s := NewDB(st, time.Second, func() (string, error) { return "", errors.New("entropy pool empty") }, nil)
		if _, _, _, err := s.Lease(ctx, "runner-1", now); err == nil || !strings.Contains(err.Error(), "entropy pool") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestLeasePlainFallbackPaths(t *testing.T) {
	ctx := context.Background()
	job := model.Job{ID: "job-1", RunID: "run-1", Key: "build", Status: model.StatusQueued, RequiredLabels: []string{"container"}}
	runner := model.Runner{ID: "runner-1", Name: "r1", CostPerHour: 2.5, PowerWatts: 100}

	t.Run("success freezes rates and runner bookkeeping", func(t *testing.T) {
		st := newInjectedStore()
		now := leaseFixture(t, st.fakeStore, job, runner)
		s := NewDB(st, time.Minute, nil, nil)
		leased, raw, expires, err := s.Lease(ctx, "runner-1", now)
		if err != nil {
			t.Fatalf("Lease: %v", err)
		}
		if raw == "" || !expires.After(now) {
			t.Fatalf("raw/expires = %q/%v", raw, expires)
		}
		if leased.CostRate != 2.5 || leased.PowerWatts != 100 {
			t.Fatalf("frozen rates = %v/%v", leased.CostRate, leased.PowerWatts)
		}
		if leased.StartedAt == nil {
			t.Fatal("the plain lease path must stamp StartedAt")
		}
		ri, err := st.GetRunner(ctx, "runner-1")
		if err != nil {
			t.Fatal(err)
		}
		if len(ri.ActiveJobs) != 1 || ri.ActiveJobs[0] != "job-1" || !ri.Busy || ri.CurrentJob != "job-1" {
			t.Fatalf("runner after lease = %+v", ri)
		}
	})

	t.Run("store without a start timestamp", func(t *testing.T) {
		st := newInjectedStore()
		now := leaseFixture(t, st.fakeStore, job, runner)
		st.clearStartedAt = true
		s := NewDB(st, time.Minute, nil, nil)
		leased, _, _, err := s.Lease(ctx, "runner-1", now)
		if err != nil {
			t.Fatalf("Lease: %v", err)
		}
		if leased.StartedAt == nil {
			t.Fatal("the scheduler must stamp StartedAt when the store leaves it nil")
		}
	})

	t.Run("conflicting candidate is skipped", func(t *testing.T) {
		st := newInjectedStore()
		now := leaseFixture(t, st.fakeStore, job, runner)
		st.acquireLeaseHook = func(string) error { return storage.ErrLeaseConflict }
		s := NewDB(st, time.Second, nil, nil)
		if _, _, _, err := s.Lease(ctx, "runner-1", now); !errors.Is(err, ErrNoJobs) {
			t.Fatalf("error = %v, want ErrNoJobs", err)
		}
	})

	t.Run("generic acquire failure is returned", func(t *testing.T) {
		st := newInjectedStore()
		now := leaseFixture(t, st.fakeStore, job, runner)
		st.acquireLeaseHook = func(string) error { return errors.New("row locked") }
		s := NewDB(st, time.Second, nil, nil)
		if _, _, _, err := s.Lease(ctx, "runner-1", now); err == nil || !strings.Contains(err.Error(), "row locked") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("bookkeeping failures do not strand the lease", func(t *testing.T) {
		st := newInjectedStore()
		now := leaseFixture(t, st.fakeStore, job, runner)
		st.updateJobErr = errors.New("frozen-rate write failed")
		st.upsertRunnerErr = errors.New("runner write failed")
		s := NewDB(st, time.Second, nil, nil)
		leased, _, _, err := s.Lease(ctx, "runner-1", now)
		if err != nil {
			t.Fatalf("Lease: %v", err)
		}
		if leased.ID != "job-1" {
			t.Fatalf("leased = %+v", leased)
		}
	})
}

func TestLeaseAtomicErrorBranches(t *testing.T) {
	ctx := context.Background()
	job := model.Job{ID: "job-1", RunID: "run-1", Key: "build", Status: model.StatusQueued, RequiredLabels: []string{"container"}}
	runner := model.Runner{ID: "runner-1", Name: "r1"}

	t.Run("conflict then success", func(t *testing.T) {
		base := newAtomicFakeStore()
		now := leaseFixture(t, base.fakeStore, job, runner)
		fail := true
		st := &atomicOverrideStore{atomicFakeStore: base, hook: func(string) error {
			if fail {
				fail = false
				return storage.ErrLeaseConflict
			}
			return nil
		}}
		s := NewDB(st, time.Minute, nil, nil)
		if _, _, _, err := s.Lease(ctx, "runner-1", now); !errors.Is(err, ErrNoJobs) {
			t.Fatalf("error = %v, want ErrNoJobs after the conflict", err)
		}
	})

	t.Run("unknown atomic error", func(t *testing.T) {
		base := newAtomicFakeStore()
		now := leaseFixture(t, base.fakeStore, job, runner)
		st := &atomicOverrideStore{atomicFakeStore: base, hook: func(string) error { return errors.New("connection reset") }}
		s := NewDB(st, time.Minute, nil, nil)
		if _, _, _, err := s.Lease(ctx, "runner-1", now); err == nil || !strings.Contains(err.Error(), "connection reset") {
			t.Fatalf("error = %v", err)
		}
	})
}

// atomicOverrideStore injects a failure into the atomic claim.
type atomicOverrideStore struct {
	*atomicFakeStore
	hook func(jobID string) error
}

func (a *atomicOverrideStore) AcquireLeaseAtomic(ctx context.Context, claim storage.LeaseClaim) (model.Job, error) {
	if a.hook != nil {
		if err := a.hook(claim.JobID); err != nil {
			return model.Job{}, err
		}
	}
	return a.atomicFakeStore.AcquireLeaseAtomic(ctx, claim)
}

func TestEffectiveRunnerProfileError(t *testing.T) {
	st := newInjectedStore()
	st.profileErr = errors.New("profile table missing")
	now := time.Now().UTC()
	ctx := context.Background()
	if err := st.InsertRun(ctx, model.Run{ID: "run-1", Status: model.StatusQueued, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertJob(ctx, model.Job{ID: "job-1", RunID: "run-1", Key: "k", Status: model.StatusQueued, RequiredLabels: []string{"container"}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: "runner-1", Name: "r", Capacity: 1, Labels: []string{"container"}, CertSerial: "serial-1"}); err != nil {
		t.Fatal(err)
	}
	st.leaderOK = true
	s := NewDB(st, time.Minute, nil, nil)
	if _, _, _, err := s.Lease(ctx, "runner-1", now); err != nil {
		t.Fatalf("a failing profile lookup must fall back to the snapshot, got %v", err)
	}
}

func TestHeartbeatErrorPaths(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("unknown job", func(t *testing.T) {
		st := newInjectedStore()
		st.leaderOK = true
		s := NewDB(st, time.Second, nil, nil)
		if _, err := s.Heartbeat(ctx, "missing", "runner-1", nil, 1, now); err == nil {
			t.Fatal("unknown job must fail")
		}
	})

	t.Run("already cancelled", func(t *testing.T) {
		st := newInjectedStore()
		st.putJob(model.Job{ID: "job-1", RunID: "run-1", Status: model.StatusCancelled})
		s := NewDB(st, time.Second, nil, nil)
		cancelled, err := s.Heartbeat(ctx, "job-1", "runner-1", nil, 1, now)
		if err != nil || !cancelled {
			t.Fatalf("Heartbeat = %v,%v", cancelled, err)
		}
	})

	t.Run("conflict with concurrent cancellation", func(t *testing.T) {
		st := newInjectedStore()
		st.putJob(model.Job{ID: "job-1", RunID: "run-1", Status: model.StatusRunning})
		st.heartbeatErr = storage.ErrLeaseConflict
		// The conflict is observed while the job has been concurrently
		// cancelled, so the runner must stop instead of retrying.
		st.heartbeatHook = func() {
			st.mu.Lock()
			j := st.jobs["job-1"]
			j.Status = model.StatusCancelled
			st.jobs["job-1"] = j
			st.mu.Unlock()
		}
		s := NewDB(st, time.Second, nil, nil)
		cancelled, err := s.Heartbeat(ctx, "job-1", "runner-1", nil, 1, now)
		if err != nil || !cancelled {
			t.Fatalf("Heartbeat = %v,%v", cancelled, err)
		}
	})

	t.Run("conflict without cancellation", func(t *testing.T) {
		st := newInjectedStore()
		st.putJob(model.Job{ID: "job-1", RunID: "run-1", Status: model.StatusRunning})
		st.heartbeatErr = storage.ErrLeaseConflict
		s := NewDB(st, time.Second, nil, nil)
		if cancelled, err := s.Heartbeat(ctx, "job-1", "runner-1", nil, 1, now); err == nil || cancelled {
			t.Fatalf("Heartbeat = %v,%v", cancelled, err)
		}
	})

	t.Run("generic store failure", func(t *testing.T) {
		st := newInjectedStore()
		st.putJob(model.Job{ID: "job-1", RunID: "run-1", Status: model.StatusRunning})
		st.heartbeatErr = errors.New("write failed")
		s := NewDB(st, time.Second, nil, nil)
		if _, err := s.Heartbeat(ctx, "job-1", "runner-1", nil, 1, now); err == nil {
			t.Fatal("store failure must surface")
		}
	})

	t.Run("runner lookup failure is tolerated", func(t *testing.T) {
		st := newInjectedStore()
		st.putJob(model.Job{ID: "job-1", RunID: "run-1", Status: model.StatusRunning, LeaseRunnerID: "runner-1", LeaseGeneration: 1, LeaseExpiresAt: &now})
		st.getRunnerErr = errors.New("runner gone")
		s := NewDB(st, time.Second, nil, nil)
		cancelled, err := s.Heartbeat(ctx, "job-1", "runner-1", nil, 1, now.Add(time.Minute))
		if err != nil || cancelled {
			t.Fatalf("Heartbeat = %v,%v", cancelled, err)
		}
	})
}

func TestCancelRunError(t *testing.T) {
	st := newInjectedStore()
	st.cancelRunErr = errors.New("cancel transaction failed")
	s := NewDB(st, time.Second, nil, nil)
	if err := s.CancelRun(context.Background(), "run-1", "user"); err == nil {
		t.Fatal("CancelRun must surface the store error")
	}
}

func TestCancelJobsByRunnerEdges(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("empty runner id", func(t *testing.T) {
		s := NewDB(newFakeStore(), time.Second, nil, nil)
		if _, err := s.CancelJobsByRunner(ctx, "", "disable"); err == nil || !strings.Contains(err.Error(), "empty runner id") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("transaction failure is returned with zero partial state", func(t *testing.T) {
		st := newFakeStore()
		st.putJob(model.Job{ID: "job-run", RunID: "run-1", Key: "r", Status: model.StatusRunning, LeaseRunnerID: "runner-1", Attempts: 5, MaxInfraRetries: 1, LeaseExpiresAt: &now})
		st.putRunner(model.Runner{ID: "runner-1", Name: "r", Capacity: 1, ActiveJobs: []string{"job-run"}})
		st.revokeErr = errors.New("revoke transaction failed")
		s := NewDB(st, time.Second, nil, nil)
		count, err := s.CancelJobsByRunner(ctx, "runner-1", "disable")
		if count != 0 || err == nil {
			t.Fatalf("count/err = %d/%v, want the transaction failure returned", count, err)
		}
		// Adaptation note: the old multi-step sequence returned a count for
		// jobs already updated before a later step failed. The transactional
		// contract is all-or-nothing, so the job must be untouched.
		if j, _ := st.job("job-run"); j.Status != model.StatusRunning || j.LeaseRunnerID != "runner-1" {
			t.Fatalf("failed revocation left partial state: %+v", j)
		}
	})

	t.Run("non-running jobs are skipped", func(t *testing.T) {
		st := newFakeStore()
		st.putJob(model.Job{ID: "job-queued", RunID: "run-1", Key: "q", Status: model.StatusQueued, LeaseRunnerID: "runner-1"})
		st.putJob(model.Job{ID: "job-run", RunID: "run-1", Key: "r", Status: model.StatusRunning, LeaseRunnerID: "runner-1", Attempts: 5, MaxInfraRetries: 1, LeaseExpiresAt: &now})
		s := NewDB(st, time.Second, nil, nil)
		count, err := s.CancelJobsByRunner(ctx, "runner-1", "disable")
		if err != nil || count != 1 {
			t.Fatalf("count/err = %d/%v", count, err)
		}
		if j, _ := st.job("job-queued"); j.Status != model.StatusQueued {
			t.Fatalf("queued job changed: %+v", j)
		}
	})

	t.Run("one transactional call and an idempotent replay", func(t *testing.T) {
		st := newFakeStore()
		st.putJob(model.Job{ID: "job-run", RunID: "run-1", Key: "r", Status: model.StatusRunning, LeaseRunnerID: "runner-1", Attempts: 5, MaxInfraRetries: 1, LeaseExpiresAt: &now})
		st.putRunner(model.Runner{ID: "runner-1", Name: "r", Capacity: 1, ActiveJobs: []string{"job-run"}})
		s := NewDB(st, time.Second, nil, nil)
		count, err := s.CancelJobsByRunner(ctx, "runner-1", "disable")
		if err != nil || count != 1 {
			t.Fatalf("count/err = %d/%v", count, err)
		}
		// Adaptation note: the old scheduler drove UpdateJob + ReleaseRunnerJob
		// per job; the transactional contract must be the ONLY write path.
		if len(st.releaseRunnerCalls) != 0 || len(st.updateJobCalls) != 0 {
			t.Fatalf("multi-step recovery writes were used: release=%d update=%d", len(st.releaseRunnerCalls), len(st.updateJobCalls))
		}
		if len(st.revokeCalls) != 1 {
			t.Fatalf("revoke calls = %d, want exactly 1", len(st.revokeCalls))
		}
		// A second replica racing the same revocation observes an empty set.
		count, err = s.CancelJobsByRunner(ctx, "runner-1", "disable")
		if err != nil || count != 0 {
			t.Fatalf("replayed count/err = %d/%v, want 0/nil", count, err)
		}
	})
}

func TestRecoverExpiredErrorPaths(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("expired lease discovery failure", func(t *testing.T) {
		st := newInjectedStore()
		st.leaderOK = true
		st.listExpiredErr = errors.New("lease discovery failed")
		s := NewDB(st, time.Second, nil, nil)
		if err := s.RecoverExpired(ctx, now); err == nil || !strings.Contains(err.Error(), "lease discovery failed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("queue-timeout discovery failure", func(t *testing.T) {
		st := newInjectedStore()
		st.leaderOK = true
		st.listQueueTOErr = errors.New("queue discovery failed")
		s := NewDB(st, time.Second, nil, nil)
		if err := s.RecoverExpired(ctx, now); err == nil || !strings.Contains(err.Error(), "queue discovery failed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("queue timeout transaction failure leaves the job queued", func(t *testing.T) {
		st := newFakeStore()
		deadline := now.Add(-time.Minute)
		st.putJob(model.Job{ID: "job-1", RunID: "run-1", Key: "k", Status: model.StatusQueued, QueueDeadline: &deadline, RepoURL: "https://github.com/o/r.git"})
		st.putRun(model.Run{ID: "run-1", Status: model.StatusQueued, CreatedAt: now})
		st.leaderOK = true
		st.expireErr = errors.New("expire transaction failed")
		s := NewDB(st, time.Second, nil, nil)
		if err := s.RecoverExpired(ctx, now); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}
		// Adaptation note: the old scheduler applied the job write first and
		// released the queued quota best-effort afterwards; a failure left a
		// cancelled job with a leaked reservation. The transaction must roll
		// back completely.
		if j, _ := st.job("job-1"); j.Status != model.StatusQueued {
			t.Fatalf("failed expire left partial state: %+v", j)
		}

		st.expireErr = nil
		if err := s.RecoverExpired(ctx, now); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}
		j, ok := st.job("job-1")
		if !ok || j.Status != model.StatusCancelled {
			t.Fatalf("job after queue timeout = %+v", j)
		}
		if len(st.expireCalls) != 2 {
			t.Fatalf("expire calls = %d, want 2 (one failed, one committed)", len(st.expireCalls))
		}
	})

	t.Run("lease recovery transaction failure leaves every job untouched", func(t *testing.T) {
		st := newFakeStore()
		expired := now.Add(-time.Minute)
		st.putJob(model.Job{ID: "job-1", RunID: "run-1", Key: "k", Status: model.StatusRunning, LeaseRunnerID: "runner-1", LeaseGeneration: 1, LeaseExpiresAt: &expired, Attempts: 5, MaxInfraRetries: 0})
		st.putJob(model.Job{ID: "job-2", RunID: "run-1", Key: "k2", Status: model.StatusRunning, LeaseRunnerID: "runner-1", LeaseGeneration: 1, LeaseExpiresAt: &expired, Attempts: 0, MaxInfraRetries: 2})
		st.putRun(model.Run{ID: "run-1", Status: model.StatusRunning, CreatedAt: now})
		st.leaderOK = true
		st.recoverErr = errors.New("recover transaction failed")
		s := NewDB(st, time.Second, nil, nil)
		if err := s.RecoverExpired(ctx, now); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}

		st.recoverErr = nil
		if err := s.RecoverExpired(ctx, now); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}
		if j, _ := st.job("job-1"); j.Status != model.StatusFailure {
			t.Fatalf("exhausted job = %+v", j)
		}
		if j, _ := st.job("job-2"); j.Status != model.StatusQueued {
			t.Fatalf("retryable job = %+v", j)
		}
		if len(st.recoverCalls) != 4 {
			t.Fatalf("recover calls = %d, want 2 per pass x 2 passes", len(st.recoverCalls))
		}
	})
}

// TestRecoverExpiredPagesBoundedCandidatesAndAdvancesPastFailures drives the
// sweep with a page size smaller than the candidate set and one candidate
// whose applier fails on every attempt: every page must be visited, the
// failed row must not stall the candidates behind it, and the later
// candidates must be recovered exactly once. The queue-timeout sweep gets the
// same treatment.
func TestRecoverExpiredPagesBoundedCandidatesAndAdvancesPastFailures(t *testing.T) {
	oldPage := recoveryPageSize
	recoveryPageSize = 2
	t.Cleanup(func() { recoveryPageSize = oldPage })

	ctx := context.Background()
	now := time.Now().UTC()
	expired := now.Add(-time.Minute)

	st := newInjectedStore()
	st.leaderOK = true
	st.putRun(model.Run{ID: "run-1", Status: model.StatusRunning, CreatedAt: now})
	for _, id := range []string{"job-a", "job-b", "job-c", "job-d", "job-e"} {
		st.putJob(model.Job{ID: id, RunID: "run-1", Key: id, Status: model.StatusRunning, LeaseRunnerID: "runner-1", LeaseGeneration: 1, LeaseExpiresAt: &expired, Attempts: 5, MaxInfraRetries: 0})
	}
	for _, id := range []string{"q-a", "q-b", "q-c", "q-d", "q-e"} {
		dl := expired
		st.putJob(model.Job{ID: id, RunID: "run-1", Key: id, Status: model.StatusQueued, QueueDeadline: &dl})
	}
	st.recoverHook = func(jobID string) error {
		if jobID == "job-a" {
			return errors.New("persistently failing candidate")
		}
		return nil
	}
	st.expireHook = func(jobID string) error {
		if jobID == "q-a" {
			return errors.New("persistently failing queue candidate")
		}
		return nil
	}
	s := NewDB(st, time.Second, nil, nil)
	if err := s.RecoverExpired(ctx, now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}

	// Every page was requested: 5 candidates at page size 2 = 3 pages
	// (2+2+1) per sweep.
	if st.listExpiredCalls != 3 || st.listQueueTOCalls != 3 {
		t.Fatalf("discovery pages = %d lease / %d queue, want 3/3", st.listExpiredCalls, st.listQueueTOCalls)
	}
	for _, id := range []string{"job-b", "job-c", "job-d", "job-e"} {
		j, ok := st.job(id)
		if !ok || j.Status != model.StatusFailure {
			t.Fatalf("lease candidate %s after sweep = %+v, want failure", id, j)
		}
	}
	if j, _ := st.job("job-a"); j.Status != model.StatusRunning {
		t.Fatalf("persistently failing candidate = %+v, want still running", j)
	}
	for _, id := range []string{"q-b", "q-c", "q-d", "q-e"} {
		j, ok := st.job(id)
		if !ok || j.Status != model.StatusCancelled || j.Error != "queue timeout" {
			t.Fatalf("queue candidate %s after sweep = %+v, want cancelled/queue timeout", id, j)
		}
	}
	if j, _ := st.job("q-a"); j.Status != model.StatusQueued {
		t.Fatalf("persistently failing queue candidate = %+v, want still queued", j)
	}

	// A second sweep revisits the failed rows from the start (their ids are
	// below the cursor of the previous sweep) and touches nothing else: one
	// short page per sweep, lease and queue.
	if err := s.RecoverExpired(ctx, now); err != nil {
		t.Fatalf("replayed RecoverExpired: %v", err)
	}
	if st.listExpiredCalls != 4 || st.listQueueTOCalls != 4 {
		t.Fatalf("replayed discovery pages = %d lease / %d queue, want 4/4", st.listExpiredCalls, st.listQueueTOCalls)
	}
	for _, id := range []string{"job-b", "job-c", "job-d", "job-e", "q-b", "q-c", "q-d", "q-e"} {
		j, _ := st.job(id)
		if j.Status == model.StatusRunning || j.Status == model.StatusQueued {
			t.Fatalf("candidate %s was recovered twice: %+v", id, j)
		}
	}
}

func TestAppendUniqueAndCloneMap(t *testing.T) {
	in := []string{"a", "b"}
	if got := appendUnique(in, "a"); len(got) != 2 || got[0] != "a" {
		t.Fatalf("appendUnique duplicate = %v", got)
	}
	if got := appendUnique(in, "c"); len(got) != 3 || got[2] != "c" {
		t.Fatalf("appendUnique new = %v", got)
	}
	if got := cloneMap(nil); got != nil {
		t.Fatalf("cloneMap(nil) = %v", got)
	}
	src := map[string]string{"k": "v"}
	cloned := cloneMap(src)
	cloned["k"] = "changed"
	if src["k"] != "v" {
		t.Fatal("cloneMap must copy the map")
	}
}

func TestDownstreamDepthMemoization(t *testing.T) {
	// Diamond: a -> b, a -> c, b -> d, c -> d. visit(b) and visit(c) both
	// memoize d, so the second traversal hits the memo.
	g := &pipeline.Graph{Jobs: map[string]pipeline.CompiledJob{
		"a": {Needs: []string{"b", "c"}},
		"b": {Needs: []string{"d"}},
		"c": {Needs: []string{"d"}},
		"d": {},
	}}
	if got := DownstreamDepth(g, "d"); got != 2 {
		t.Fatalf("DownstreamDepth(d) = %d, want 2", got)
	}
	if got := DownstreamDepth(g, "b"); got != 1 {
		t.Fatalf("DownstreamDepth(b) = %d, want 1", got)
	}
	if got := DownstreamDepth(g, "missing"); got != 0 {
		t.Fatalf("DownstreamDepth(missing) = %d", got)
	}
}

func TestCollectNeedsOutputsEdges(t *testing.T) {
	jobs := map[string]model.Job{
		"a":     {ID: "a", Key: "cell", BaseKey: "base", Outputs: map[string]string{"x": "1"}},
		"b":     {ID: "b", Key: "other", BaseKey: "base", Outputs: map[string]string{"y": "2"}},
		"empty": {ID: "empty", Key: "empty"},
	}
	j := model.Job{ID: "j", Needs: []string{"a", "b", "empty", "missing"}}
	out := CollectNeedsOutputs(j, jobs)
	if len(out) != 2 || out["cell"]["x"] != "1" || out["other"]["y"] != "2" {
		t.Fatalf("outputs = %v", out)
	}
	if _, ok := out["base"]; ok {
		t.Fatal("a base key with two matrix cells must not be aliased")
	}

	single := model.Job{ID: "j2", Needs: []string{"a"}}
	out = CollectNeedsOutputs(single, jobs)
	if out["base"]["x"] != "1" || out["cell"]["x"] != "1" {
		t.Fatalf("single-cell outputs = %v", out)
	}
	// A nil output map on an upstream job is skipped.
	out = CollectNeedsOutputs(model.Job{Needs: []string{"empty"}}, jobs)
	if len(out) != 0 {
		t.Fatalf("empty outputs = %v", out)
	}
}

func TestWeakenedQuotaHelpers(t *testing.T) {
	if ok, err := WithinQuota(math.NaN(), 1, 1); ok || err == nil {
		t.Fatalf("NaN limit = %v,%v", ok, err)
	}
	if ok, err := WithinQuota(math.Inf(1), math.Inf(-1), 0); ok || err == nil {
		t.Fatalf("infinite values = %v,%v", ok, err)
	}
	if ok, err := WithinQuota(1, -1, 0); ok || err == nil {
		t.Fatalf("negative used = %v,%v", ok, err)
	}
	if ok, err := WithinQuota(1, 1, 1); ok || err != nil {
		t.Fatalf("over limit = %v,%v", ok, err)
	}
	if ok, err := WithinQuota(math.MaxInt64/2, math.MaxInt64, math.MaxInt64); ok || err != nil {
		t.Fatalf("int64-saturating total = %v,%v", ok, err)
	}
	if ok, err := WithinQuota(math.MaxInt64, math.MaxInt64, 1); !ok || err != nil {
		t.Fatalf("exact int64 limit = %v,%v", ok, err)
	}
	if got := SaturatingAdd(-5, 3); got != 3 {
		t.Fatalf("SaturatingAdd(-5,3) = %d", got)
	}
	if got := SaturatingAdd(3, -5); got != 3 {
		t.Fatalf("SaturatingAdd(3,-5) = %d", got)
	}
	if got := SaturatingAdd(math.MaxInt64, 1); got != math.MaxInt64 {
		t.Fatalf("saturation = %d", got)
	}
}
