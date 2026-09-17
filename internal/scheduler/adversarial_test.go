package scheduler

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const advRepo = "https://github.com/o/r.git"

// TestRecoverExpiredQueueTimeoutReleasesQueuedQuota pins the quota
// accounting of the queue-timeout cancellation: a queued job that expires
// never runs, so its reserved queued slot must be returned in the same
// recovery pass (repo AND team keys), exactly once even if recovery replays.
func TestRecoverExpiredQueueTimeoutReleasesQueuedQuota(t *testing.T) {
	f := newAtomicFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	team := storage.RepoTeamKey(advRepo)
	if team == "" {
		t.Fatal("test repository does not derive a team key")
	}
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour)})
	past := now.Add(-time.Minute)
	job := leaseTestJob("job", "run")
	job.CreatedAt = now.Add(-time.Hour)
	job.RepoURL = advRepo
	job.RepoFullName = "o/r"
	job.QueueDeadline = &past
	f.putJob(job)
	ctx := context.Background()
	repoID := storage.RepoIDForJob(job)
	if err := f.AdjustQuotaCounter(ctx, repoID, team, 0, 1); err != nil {
		t.Fatal(err)
	}
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.RecoverExpired(ctx, now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	j, _ := f.job("job")
	if j.Status != model.StatusCancelled || j.Error != "queue timeout" {
		t.Fatalf("job after queue timeout = %s/%q, want cancelled/queue timeout", j.Status, j.Error)
	}
	if rq := f.quotaQueued(repoID); rq != 0 {
		t.Fatalf("repo queued counter = %d, want 0 after queue-timeout cancel", rq)
	}
	if tq := f.quotaQueued(team); tq != 0 {
		t.Fatalf("team queued counter = %d, want 0 after queue-timeout cancel", tq)
	}
	// A replayed recovery must not release the slot again (it would clamp
	// a genuine reservation of another job to zero).
	f.putRun(model.Run{ID: "run2", Repo: advRepo, Status: model.StatusQueued, CreatedAt: now})
	second := leaseTestJob("other", "run2")
	second.RepoURL = advRepo
	second.RepoFullName = "o/r"
	second.CreatedAt = now
	f.putJob(second)
	if err := f.AdjustQuotaCounter(ctx, repoID, team, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverExpired(ctx, now); err != nil {
		t.Fatalf("replayed RecoverExpired: %v", err)
	}
	if got := f.quotaQueued(repoID); got != 1 {
		t.Fatalf("repo queued counter after replay = %d, want 1 (the live job's reservation)", got)
	}
	if got := f.quotaQueued(team); got != 1 {
		t.Fatalf("team queued counter after replay = %d, want 1", got)
	}
}

// TestRecoverExpiredWaitingApprovalQueueTimeout: the queue deadline applies
// to approval-waiting jobs too, and the release pass must not touch the
// running counter.
func TestRecoverExpiredWaitingApprovalQueueTimeout(t *testing.T) {
	f := newAtomicFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	team := storage.RepoTeamKey(advRepo)
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour)})
	past := now.Add(-time.Minute)
	job := leaseTestJob("job", "run")
	job.Status = model.StatusWaitingApproval
	job.CreatedAt = now.Add(-time.Hour)
	job.RepoURL = advRepo
	job.QueueDeadline = &past
	f.putJob(job)
	ctx := context.Background()
	repoID := storage.RepoIDForJob(job)
	if err := f.AdjustQuotaCounter(ctx, repoID, team, 0, 1); err != nil {
		t.Fatal(err)
	}
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.RecoverExpired(ctx, now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	j, _ := f.job("job")
	if j.Status != model.StatusCancelled {
		t.Fatalf("waiting-approval job status = %s, want cancelled", j.Status)
	}
	if f.quotaQueued(repoID) != 0 || f.quotaRunning(repoID) != 0 {
		t.Fatalf("counters = %d/%d, want 0/0", f.quotaRunning(repoID), f.quotaQueued(repoID))
	}
}

// TestLeaseQueueDeadlineBoundary: the deadline gate is strict (!After(now)),
// so a deadline exactly at the evaluation instant is already expired, and
// clock skew between enqueue and recovery never resurrects an expired job.
func TestLeaseQueueDeadlineBoundary(t *testing.T) {
	now := time.Now().UTC()
	deadline := now
	f := newAtomicFakeStore()
	f.setLeader(true, nil)
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 1})
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now})
	f.putJob(model.Job{ID: "job", RunID: "run", Key: "job", Status: model.StatusQueued, RepoURL: advRepo, CreatedAt: now.Add(-time.Hour), QueueDeadline: &deadline})
	s := NewDB(f, time.Minute, nil, nil)
	if _, _, _, err := s.Lease(context.Background(), "runner", now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease exactly at deadline = %v, want ErrNoJobs", err)
	}
	// One nanosecond later still leases.
	fut := now.Add(time.Nanosecond)
	j, _ := f.job("job")
	j.QueueDeadline = &fut
	f.putJob(j)
	if _, _, _, err := s.Lease(context.Background(), "runner", now); err != nil {
		t.Fatalf("lease one tick before deadline: %v", err)
	}
}

// TestLeaseExpiryBoundaryClockSkew: lease expiry is evaluated strictly
// (expires_at <= now is expired). A lease expiring exactly at the recovery
// instant is recovered; one nanosecond later it is still live.
func TestLeaseExpiryBoundaryClockSkew(t *testing.T) {
	now := time.Now().UTC()
	f := newAtomicFakeStore()
	f.setLeader(true, nil)
	f.putRun(model.Run{ID: "run", Status: model.StatusRunning, CreatedAt: now.Add(-time.Hour)})
	exp := now
	job := leaseTestJob("job", "run")
	job.Status = model.StatusRunning
	job.Attempts = 1
	job.MaxInfraRetries = 3
	job.LeaseRunnerID = "runner"
	job.LeaseTokenHash = []byte("hash")
	job.LeaseGeneration = 1
	job.LeaseExpiresAt = &exp
	f.putJob(job)
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 1})
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.RecoverExpired(context.Background(), now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	recovered, _ := f.job("job")
	if recovered.Status != model.StatusQueued || recovered.LeaseRunnerID != "" {
		t.Fatalf("lease expiring exactly at now not recovered: %s/%q", recovered.Status, recovered.LeaseRunnerID)
	}
	// One nanosecond in the future: the lease survives recovery.
	alive := exp.Add(time.Nanosecond)
	job.Status = model.StatusRunning
	job.LeaseRunnerID = "runner"
	job.LeaseTokenHash = []byte("hash")
	job.LeaseExpiresAt = &alive
	f.putJob(job)
	if err := s.RecoverExpired(context.Background(), now); err != nil {
		t.Fatalf("RecoverExpired (live lease): %v", err)
	}
	still, _ := f.job("job")
	if still.Status != model.StatusRunning {
		t.Fatalf("live lease recovered prematurely: %s", still.Status)
	}
}

// TestLeaseEnvironmentConcurrencyRepoScoped: the environment concurrency
// key is (repository, environment). Two repositories using the same
// environment name lease in parallel; a second job of the SAME repository
// and environment is rejected with ErrEnvConcurrency even on a free runner.
func TestLeaseEnvironmentConcurrencyRepoScoped(t *testing.T) {
	f := newAtomicFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now})
	jobs := map[string]model.Job{}
	for i, repo := range []string{"https://github.com/o/r.git", "https://github.com/other/s.git"} {
		j := leaseTestJob([]string{"job1", "job2"}[i], "run")
		j.RepoURL = repo
		j.RepoFullName = strings.TrimPrefix(repo, "https://github.com/")
		j.Environment = "prod"
		j.EnvironmentConcurrency = 1
		jobs[j.ID] = j
	}
	blocked := leaseTestJob("job3", "run")
	blocked.RepoURL = "https://github.com/o/r.git"
	blocked.RepoFullName = "o/r"
	blocked.Environment = "prod"
	blocked.EnvironmentConcurrency = 1
	jobs[blocked.ID] = blocked
	for _, j := range jobs {
		f.putJob(j)
	}
	f.putRunner(model.Runner{ID: "r1", Name: "r1", Capacity: 1})
	f.putRunner(model.Runner{ID: "r2", Name: "r2", Capacity: 1})
	s := NewDB(f, time.Minute, nil, nil)
	// Each repository claims its own environment slot in parallel.
	if _, _, _, err := s.Lease(context.Background(), "r1", now); err != nil {
		t.Fatalf("repo-o prod lease: %v", err)
	}
	if _, _, _, err := s.Lease(context.Background(), "r2", now); err != nil {
		t.Fatalf("repo-other prod lease: %v", err)
	}
	// The remaining same-repo/same-env job finds no environment slot.
	if _, _, _, err := s.Lease(context.Background(), "r1", now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("third prod lease = %v, want ErrNoJobs", err)
	}
	f.mu.Lock()
	var running []string
	for _, j := range f.jobs {
		if j.Status == model.StatusRunning {
			running = append(running, j.ID)
		}
	}
	f.mu.Unlock()
	if len(running) != 2 {
		t.Fatalf("running jobs = %v, want exactly 2 (one per repository)", running)
	}
}

// TestLeaseSingleJobEightPollersOneWinner races eight concurrent Lease calls
// for ONE job on a capacity-8 runner: exactly one wins, attempts/started_at
// are stamped once, and every loser leaves the job queued.
func TestLeaseSingleJobEightPollersOneWinner(t *testing.T) {
	f := newAtomicFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now})
	f.putJob(leaseTestJob("job", "run"))
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 8, CostPerHour: 1.25, PowerWatts: 3})
	s := NewDB(f, time.Minute, nil, nil)
	const pollers = 8
	type res struct {
		job *model.Job
		err error
	}
	start := make(chan struct{})
	results := make(chan res, pollers)
	var wg sync.WaitGroup
	for i := 0; i < pollers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			j, _, _, err := s.Lease(context.Background(), "runner", now)
			results <- res{j, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	won, lost := 0, 0
	for r := range results {
		switch {
		case r.err == nil:
			won++
			if r.job.Attempts != 1 || r.job.StartedAt == nil {
				t.Fatalf("winner attempts/started_at = %d/%v, want 1/set", r.job.Attempts, r.job.StartedAt)
			}
			if r.job.CostRate != 1.25 || r.job.PowerWatts != 3 {
				t.Fatalf("winner rates = %v/%v, want 1.25/3", r.job.CostRate, r.job.PowerWatts)
			}
		case errors.Is(r.err, ErrNoJobs):
			lost++
		default:
			t.Fatalf("unexpected lease error: %v", r.err)
		}
	}
	if won != 1 || lost != pollers-1 {
		t.Fatalf("winners=%d losers=%d, want 1/%d", won, lost, pollers-1)
	}
	j, _ := f.job("job")
	if j.Status != model.StatusRunning || j.Attempts != 1 || j.LeaseGeneration != 1 {
		t.Fatalf("stored job = %s attempts=%d gen=%d, want running/1/1", j.Status, j.Attempts, j.LeaseGeneration)
	}
	ri, _ := f.GetRunner(context.Background(), "runner")
	if len(ri.ActiveJobs) != 1 {
		t.Fatalf("runner active jobs = %v, want exactly 1", ri.ActiveJobs)
	}
}
