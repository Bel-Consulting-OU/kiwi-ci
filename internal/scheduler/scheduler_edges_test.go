package scheduler

import (
	"context"
	"encoding/json"
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
	getRunnerErr       error
	listQueuedErr      error
	listByEnvErr       error
	listByRunErr       error
	updateJobErr       error
	upsertRunnerErr    error
	heartbeatErr       error
	heartbeatHook      func()
	cancelRunErr       error
	listRunsErr        error
	updateRunStatusErr error
	appendAuditErr     error
	profileErr         error
	acquireLeaseHook   func(jobID string) error
	clearStartedAt     bool
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

func (s *injectedStore) ListJobsByEnvironment(ctx context.Context, repoURL, environment string) ([]model.Job, error) {
	if s.listByEnvErr != nil {
		return nil, s.listByEnvErr
	}
	return s.fakeStore.ListJobsByEnvironment(ctx, repoURL, environment)
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

func (s *injectedStore) UpdateRunStatus(ctx context.Context, id string, status model.Status, startedAt, finishedAt *time.Time) error {
	if s.updateRunStatusErr != nil {
		return s.updateRunStatusErr
	}
	return s.fakeStore.UpdateRunStatus(ctx, id, status, startedAt, finishedAt)
}

func (s *injectedStore) AppendAudit(ctx context.Context, e model.AuditEvent) error {
	if s.appendAuditErr != nil {
		return s.appendAuditErr
	}
	return s.fakeStore.AppendAudit(ctx, e)
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

	t.Run("listing failure", func(t *testing.T) {
		st := &killErrStore{killStore: &killStore{fakeStore: newFakeStore()}}
		st.listErr = errors.New("listing failed")
		s := NewDB(st, time.Second, nil, nil)
		if _, err := s.CancelJobsByRunner(ctx, "runner-1", "disable"); err == nil {
			t.Fatal("listing failure must surface")
		}
	})

	t.Run("non-running jobs are skipped", func(t *testing.T) {
		st := &killAllStore{fakeStore: newFakeStore()}
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

	t.Run("update failure is recorded and skips the job", func(t *testing.T) {
		st := &killAllStore{fakeStore: newFakeStore()}
		st.putJob(model.Job{ID: "job-run", RunID: "run-1", Key: "r", Status: model.StatusRunning, LeaseRunnerID: "runner-1", Attempts: 5, MaxInfraRetries: 1, LeaseExpiresAt: &now})
		st.updateErr = errors.New("update failed")
		s := NewDB(st, time.Second, nil, nil)
		count, err := s.CancelJobsByRunner(ctx, "runner-1", "disable")
		if count != 0 || err == nil {
			t.Fatalf("count/err = %d/%v, want the update failure recorded", count, err)
		}
	})

	t.Run("runner release and recompute failures are logged", func(t *testing.T) {
		st := &killAllStore{fakeStore: newFakeStore()}
		st.putJob(model.Job{ID: "job-run", RunID: "run-1", Key: "r", Status: model.StatusRunning, LeaseRunnerID: "runner-1", Attempts: 5, MaxInfraRetries: 1, LeaseExpiresAt: &now})
		st.putRun(model.Run{ID: "run-1", Status: model.StatusRunning, CreatedAt: now})
		st.releaseErr = errors.New("release failed")
		st.listByRunErr = errors.New("list by run failed")
		s := NewDB(st, time.Second, nil, nil)
		count, err := s.CancelJobsByRunner(ctx, "runner-1", "disable")
		if err != nil || count != 1 {
			t.Fatalf("count/err = %d/%v", count, err)
		}

		st.listByRunErr = nil
		st.releaseErr = nil
		count, err = s.CancelJobsByRunner(ctx, "runner-1", "disable")
		if err != nil || count != 0 {
			t.Fatalf("second call count/err = %d/%v (job must now be terminal)", count, err)
		}
	})
}

type killErrStore struct {
	*killStore
	listErr        error
	updateErr      error
	releaseErr     error
	listByRunErr   error
	appendAuditErr error
}

func (k *killErrStore) ListJobsByRunner(ctx context.Context, runnerID string) ([]model.Job, error) {
	if k.listErr != nil {
		return nil, k.listErr
	}
	return k.killStore.ListJobsByRunner(ctx, runnerID)
}

func (k *killErrStore) UpdateJob(ctx context.Context, j model.Job) error {
	if k.updateErr != nil {
		return k.updateErr
	}
	return k.killStore.UpdateJob(ctx, j)
}

func (k *killErrStore) ReleaseRunnerJob(ctx context.Context, runnerID, jobID string, status model.Status) error {
	if k.releaseErr != nil {
		return k.releaseErr
	}
	return k.killStore.ReleaseRunnerJob(ctx, runnerID, jobID, status)
}

func (k *killErrStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	if k.listByRunErr != nil {
		return nil, k.listByRunErr
	}
	return k.killStore.ListJobsByRun(ctx, runID)
}

func (k *killErrStore) AppendAudit(ctx context.Context, e model.AuditEvent) error {
	if k.appendAuditErr != nil {
		return k.appendAuditErr
	}
	return k.killStore.AppendAudit(ctx, e)
}

func TestRecoverExpiredErrorPaths(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("list runs failure", func(t *testing.T) {
		st := newInjectedStore()
		st.leaderOK = true
		st.listRunsErr = errors.New("run listing failed")
		s := NewDB(st, time.Second, nil, nil)
		if err := s.RecoverExpired(ctx, now); err == nil || !strings.Contains(err.Error(), "run listing failed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("run job listing failure", func(t *testing.T) {
		st := newInjectedStore()
		st.leaderOK = true
		if err := st.InsertRun(ctx, model.Run{ID: "run-1", Status: model.StatusRunning, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		st.listByRunErr = errors.New("job listing failed")
		s := NewDB(st, time.Second, nil, nil)
		if err := s.RecoverExpired(ctx, now); err != nil {
			t.Fatalf("a single run listing failure must be logged and skipped: %v", err)
		}
	})

	t.Run("queue timeout write and quota release failures", func(t *testing.T) {
		st := &quotaErrStore{fakeStore: newFakeStore()}
		deadline := now.Add(-time.Minute)
		st.putJob(model.Job{ID: "job-1", RunID: "run-1", Key: "k", Status: model.StatusQueued, QueueDeadline: &deadline, RepoURL: "https://github.com/o/r.git"})
		st.putRun(model.Run{ID: "run-1", Status: model.StatusQueued, CreatedAt: now})
		st.leaderOK = true
		st.updateJobErr = errors.New("update failed")
		s := NewDB(st, time.Second, nil, nil)
		if err := s.RecoverExpired(ctx, now); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}

		st.updateJobErr = nil
		st.adjustQuotaErr = errors.New("quota counter write failed")
		if err := s.RecoverExpired(ctx, now); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}
		j, ok := st.job("job-1")
		if !ok || j.Status != model.StatusCancelled {
			t.Fatalf("job after queue timeout = %+v", j)
		}
	})

	t.Run("lease expiry write and runner release failures", func(t *testing.T) {
		st := &quotaErrStore{fakeStore: newFakeStore()}
		expired := now.Add(-time.Minute)
		st.putJob(model.Job{ID: "job-1", RunID: "run-1", Key: "k", Status: model.StatusRunning, LeaseRunnerID: "runner-1", LeaseExpiresAt: &expired, Attempts: 5, MaxInfraRetries: 0})
		st.putJob(model.Job{ID: "job-2", RunID: "run-1", Key: "k2", Status: model.StatusRunning, LeaseRunnerID: "runner-1", LeaseExpiresAt: &expired, Attempts: 0, MaxInfraRetries: 2})
		st.putRun(model.Run{ID: "run-1", Status: model.StatusRunning, CreatedAt: now})
		st.leaderOK = true
		st.updateJobErr = errors.New("update failed")
		st.releaseErr = errors.New("release failed")
		s := NewDB(st, time.Second, nil, nil)
		if err := s.RecoverExpired(ctx, now); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}

		st.updateJobErr = nil
		if err := s.RecoverExpired(ctx, now); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}
		st.releaseErr = nil
		if err := s.RecoverExpired(ctx, now); err != nil {
			t.Fatalf("RecoverExpired: %v", err)
		}
		if j, _ := st.job("job-1"); j.Status != model.StatusFailure {
			t.Fatalf("exhausted job = %+v", j)
		}
		if j, _ := st.job("job-2"); j.Status != model.StatusQueued {
			t.Fatalf("retryable job = %+v", j)
		}
	})
}

// killAllStore lists every job of the runner regardless of status, so the
// kill switch's non-running skip and per-stage failures are reachable.
type killAllStore struct {
	*fakeStore
	updateErr    error
	releaseErr   error
	listByRunErr error
}

func (k *killAllStore) ListJobsByRunner(ctx context.Context, runnerID string) ([]model.Job, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := []model.Job{}
	for _, j := range k.jobs {
		if j.LeaseRunnerID == runnerID {
			out = append(out, j)
		}
	}
	return out, nil
}

func (k *killAllStore) UpdateJob(ctx context.Context, j model.Job) error {
	if k.updateErr != nil {
		return k.updateErr
	}
	return k.fakeStore.UpdateJob(ctx, j)
}

func (k *killAllStore) ReleaseRunnerJob(ctx context.Context, runnerID, jobID string, status model.Status) error {
	if k.releaseErr != nil {
		return k.releaseErr
	}
	return k.fakeStore.ReleaseRunnerJob(ctx, runnerID, jobID, status)
}

func (k *killAllStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	if k.listByRunErr != nil {
		return nil, k.listByRunErr
	}
	return k.fakeStore.ListJobsByRun(ctx, runID)
}

// quotaErrStore injects queue-counter and job-write failures.
type quotaErrStore struct {
	*fakeStore
	updateJobErr    error
	releaseErr      error
	adjustQuotaErr  error
	appendAuditErr  error
	updateRunErr    error
	listJobsByRunEr error
}

func (q *quotaErrStore) UpdateJob(ctx context.Context, j model.Job) error {
	if q.updateJobErr != nil {
		return q.updateJobErr
	}
	return q.fakeStore.UpdateJob(ctx, j)
}

func (q *quotaErrStore) ReleaseRunnerJob(ctx context.Context, runnerID, jobID string, status model.Status) error {
	if q.releaseErr != nil {
		return q.releaseErr
	}
	return q.fakeStore.ReleaseRunnerJob(ctx, runnerID, jobID, status)
}

func (q *quotaErrStore) AdjustQuotaCounter(ctx context.Context, repoKey, teamKey string, runningDelta, queuedDelta int) error {
	if q.adjustQuotaErr != nil {
		return q.adjustQuotaErr
	}
	return q.fakeStore.AdjustQuotaCounter(ctx, repoKey, teamKey, runningDelta, queuedDelta)
}

func (q *quotaErrStore) AppendAudit(ctx context.Context, e model.AuditEvent) error {
	if q.appendAuditErr != nil {
		return q.appendAuditErr
	}
	return q.fakeStore.AppendAudit(ctx, e)
}

func (q *quotaErrStore) UpdateRunStatus(ctx context.Context, id string, status model.Status, startedAt, finishedAt *time.Time) error {
	if q.updateRunErr != nil {
		return q.updateRunErr
	}
	return q.fakeStore.UpdateRunStatus(ctx, id, status, startedAt, finishedAt)
}

func (q *quotaErrStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	if q.listJobsByRunEr != nil {
		return nil, q.listJobsByRunEr
	}
	return q.fakeStore.ListJobsByRun(ctx, runID)
}

func TestRecoverExpiredAuditFailureIsLogged(t *testing.T) {
	st := &quotaErrStore{fakeStore: newFakeStore()}
	deadline := time.Now().UTC().Add(-time.Minute)
	st.putJob(model.Job{ID: "job-1", RunID: "run-1", Key: "k", Status: model.StatusQueued, QueueDeadline: &deadline})
	st.putRun(model.Run{ID: "run-1", Status: model.StatusQueued})
	st.leaderOK = true
	st.appendAuditErr = errors.New("audit sink down")
	s := NewDB(st, time.Second, nil, nil)
	if err := s.RecoverExpired(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	if j, _ := st.job("job-1"); j.Status != model.StatusCancelled {
		t.Fatalf("job = %+v, want the queue timeout applied", j)
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

func TestReleaseQueuedQuotaLegacyStore(t *testing.T) {
	// A store without the counter contract is tolerated: the release is a
	// no-op instead of an error.
	st := &legacyQuotaStore{Store: newFakeStore()}
	s := &DBScheduler{Store: st, LeaderKey: "k", LeaderTTL: time.Second}
	s.releaseQueuedQuota(context.Background(), model.Job{ID: "j", RepoURL: "https://github.com/o/r.git"})
}

// legacyQuotaStore hides the QuotaCounterStore methods by embedding only the
// storage.Store interface.
type legacyQuotaStore struct {
	storage.Store
}

func TestRecomputeRunStatuses(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	started := now.Add(-time.Minute)
	finished := now.Add(-time.Second)

	cases := []struct {
		name   string
		run    model.Run
		jobs   map[string]model.Job
		want   model.Status
		wantNo bool
	}{
		{
			name: "all terminal with failure",
			run:  model.Run{ID: "run", Status: model.StatusRunning},
			jobs: map[string]model.Job{
				"a": {ID: "a", Status: model.StatusSuccess, StartedAt: &started, FinishedAt: &finished},
				"b": {ID: "b", Status: model.StatusBlocked},
			},
			want: model.StatusFailure,
		},
		{
			name: "all terminal cancelled",
			run:  model.Run{ID: "run", Status: model.StatusRunning},
			jobs: map[string]model.Job{
				"a": {ID: "a", Status: model.StatusSuccess},
				"b": {ID: "b", Status: model.StatusCancelled},
			},
			want: model.StatusCancelled,
		},
		{
			name: "all terminal success without finish times",
			run:  model.Run{ID: "run", Status: model.StatusRunning},
			jobs: map[string]model.Job{
				"a": {ID: "a", Status: model.StatusSuccess},
			},
			want: model.StatusSuccess,
		},
		{
			name: "running wins",
			run:  model.Run{ID: "run", Status: model.StatusQueued},
			jobs: map[string]model.Job{
				"a": {ID: "a", Status: model.StatusRunning},
				"b": {ID: "b", Status: model.StatusQueued},
			},
			want: model.StatusRunning,
		},
		{
			name: "waiting approval",
			run:  model.Run{ID: "run", Status: model.StatusQueued},
			jobs: map[string]model.Job{
				"a": {ID: "a", Status: model.StatusWaitingApproval},
			},
			want: model.StatusWaitingApproval,
		},
		{
			name: "otherwise queued",
			run:  model.Run{ID: "run", Status: model.StatusRunning},
			jobs: map[string]model.Job{
				"a": {ID: "a", Status: model.StatusQueued},
			},
			want: model.StatusQueued,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newFakeStore()
			st.putRun(tc.run)
			for id, j := range tc.jobs {
				j.RunID = tc.run.ID
				st.putJob(j)
				_ = id
			}
			s := &DBScheduler{Store: st, LeaderKey: "k", LeaderTTL: time.Second}
			s.recomputeRun(ctx, tc.run, tc.jobs)
			run, err := st.GetRun(ctx, tc.run.ID)
			if err != nil {
				t.Fatal(err)
			}
			if run.Status != tc.want {
				t.Fatalf("status = %v, want %v", run.Status, tc.want)
			}
			if tc.want == model.StatusSuccess && run.FinishedAt == nil {
				t.Fatal("terminal runs must get a finish time")
			}
		})
	}

	t.Run("cancelled run is untouched", func(t *testing.T) {
		st := newFakeStore()
		run := model.Run{ID: "run", Status: model.StatusCancelled}
		st.putRun(run)
		s := &DBScheduler{Store: st, LeaderKey: "k", LeaderTTL: time.Second}
		s.recomputeRun(ctx, run, map[string]model.Job{"a": {ID: "a", Status: model.StatusRunning}})
		got, _ := st.GetRun(ctx, "run")
		if got.Status != model.StatusCancelled {
			t.Fatalf("status = %v", got.Status)
		}
	})

	t.Run("empty job set is untouched", func(t *testing.T) {
		st := newFakeStore()
		run := model.Run{ID: "run", Status: model.StatusQueued}
		st.putRun(run)
		s := &DBScheduler{Store: st, LeaderKey: "k", LeaderTTL: time.Second}
		s.recomputeRun(ctx, run, nil)
		got, _ := st.GetRun(ctx, "run")
		if got.Status != model.StatusQueued {
			t.Fatalf("status = %v", got.Status)
		}
	})

	t.Run("update failure is logged", func(t *testing.T) {
		st := &quotaErrStore{fakeStore: newFakeStore()}
		st.updateRunErr = errors.New("run write failed")
		run := model.Run{ID: "run", Status: model.StatusQueued}
		st.putRun(run)
		s := &DBScheduler{Store: st, LeaderKey: "k", LeaderTTL: time.Second}
		s.recomputeRun(ctx, run, map[string]model.Job{"a": {ID: "a", Status: model.StatusRunning}})
	})
}

func TestRecomputeDependents(t *testing.T) {
	ctx := context.Background()

	t.Run("success dependency promotes waiting job", func(t *testing.T) {
		st := newFakeStore()
		jobs := map[string]model.Job{
			"up":   {ID: "up", Status: model.StatusSuccess},
			"down": {ID: "down", RunID: "run", Key: "down", Status: model.StatusQueued, Needs: []string{"up"}},
		}
		for _, j := range jobs {
			st.putJob(j)
		}
		s := &DBScheduler{Store: st, LeaderKey: "k", LeaderTTL: time.Second}
		s.recomputeDependents(ctx, jobs)
		j, _ := st.job("down")
		if j.DependencyStatus != model.StatusSuccess {
			t.Fatalf("dependency status = %v", j.DependencyStatus)
		}
	})

	t.Run("failed dependency blocks the job", func(t *testing.T) {
		st := newFakeStore()
		jobs := map[string]model.Job{
			"up":   {ID: "up", Status: model.StatusFailure},
			"down": {ID: "down", RunID: "run", Key: "down", Status: model.StatusQueued, Needs: []string{"up"}},
		}
		for _, j := range jobs {
			st.putJob(j)
		}
		s := &DBScheduler{Store: st, LeaderKey: "k", LeaderTTL: time.Second}
		s.recomputeDependents(ctx, jobs)
		j, _ := st.job("down")
		if j.Status != model.StatusBlocked || j.FinishedAt == nil {
			t.Fatalf("blocked job = %+v", j)
		}
	})

	t.Run("condition always admits a failed dependency", func(t *testing.T) {
		st := newFakeStore()
		jobs := map[string]model.Job{
			"up":   {ID: "up", Status: model.StatusFailure},
			"down": {ID: "down", RunID: "run", Key: "down", Status: model.StatusQueued, Needs: []string{"up"}, Condition: "always()"},
		}
		for _, j := range jobs {
			st.putJob(j)
		}
		s := &DBScheduler{Store: st, LeaderKey: "k", LeaderTTL: time.Second}
		s.recomputeDependents(ctx, jobs)
		j, _ := st.job("down")
		if j.Status != model.StatusQueued || j.DependencyStatus != model.StatusFailure {
			t.Fatalf("always job = %+v", j)
		}
	})

	t.Run("unchanged outcome is skipped", func(t *testing.T) {
		st := newFakeStore()
		jobs := map[string]model.Job{
			"up":   {ID: "up", Status: model.StatusSuccess},
			"down": {ID: "down", RunID: "run", Status: model.StatusQueued, Needs: []string{"up"}, DependencyStatus: model.StatusSuccess},
		}
		for _, j := range jobs {
			st.putJob(j)
		}
		s := &DBScheduler{Store: st, LeaderKey: "k", LeaderTTL: time.Second}
		s.recomputeDependents(ctx, jobs)
	})

	t.Run("update failure is logged", func(t *testing.T) {
		st := &quotaErrStore{fakeStore: newFakeStore()}
		st.updateJobErr = errors.New("update failed")
		jobs := map[string]model.Job{
			"up":   {ID: "up", Status: model.StatusSuccess},
			"down": {ID: "down", RunID: "run", Status: model.StatusQueued, Needs: []string{"up"}},
		}
		for _, j := range jobs {
			st.putJob(j)
		}
		s := &DBScheduler{Store: st, LeaderKey: "k", LeaderTTL: time.Second}
		s.recomputeDependents(ctx, jobs)
	})
}

func TestQueueTimeoutFromPayloadVariants(t *testing.T) {
	withTimeout := func(t *testing.T) []byte {
		t.Helper()
		cj := pipeline.CompiledJob{Job: pipeline.Job{QueueTimeout: pipeline.Duration{Duration: 30 * time.Second, Set: true}}}
		b, err := json.Marshal(cj)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	raw := withTimeout(t)

	cases := []struct {
		name string
		job  model.Job
		want time.Duration
	}{
		{"nil payload", model.Job{}, 0},
		{"nil effective job", model.Job{CompiledJobPayload: &model.CompiledJobPayload{}}, 0},
		{"raw message", model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: json.RawMessage(raw)}}, 30 * time.Second},
		{"byte slice", model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: raw}}, 30 * time.Second},
		{"string", model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: string(raw)}}, 30 * time.Second},
		{"struct value", model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: pipeline.CompiledJob{Job: pipeline.Job{QueueTimeout: pipeline.Duration{Duration: 5 * time.Second, Set: true}}}}}, 5 * time.Second},
		{"invalid json", model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: []byte("{nope")}}, 0},
		{"no timeout", model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: []byte("{}")}}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := queueTimeoutFromPayload(tc.job); got != tc.want {
				t.Fatalf("queueTimeoutFromPayload = %v, want %v", got, tc.want)
			}
		})
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
