package scheduler

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// leaseTestJob builds a queued job for the shared lease tests.
func leaseTestJob(id, runID string) model.Job {
	return model.Job{
		ID: id, RunID: runID, Key: "build", Status: model.StatusQueued,
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		CreatedAt: time.Now().UTC().Add(-time.Minute),
	}
}

// requeueJob simulates the scheduler's lost-runner recovery for a leased
// job: the job returns to queued with its lease cleared and the runner slot
// released through the store.
func requeueJob(t *testing.T, st *atomicFakeStore, jobID, runnerID string) {
	t.Helper()
	j, ok := st.job(jobID)
	if !ok {
		t.Fatalf("job %s missing", jobID)
	}
	j.Status = model.StatusQueued
	j.Error = "runner lease expired; retrying"
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	if err := st.UpdateJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	delete(st.active, runnerID)
	st.mu.Unlock()
	if err := st.fakeStore.ReleaseRunnerJob(context.Background(), runnerID, jobID, model.StatusFailure); err != nil {
		t.Fatal(err)
	}
}

// TestLeaseIncrementsAttemptsOnceAndPreservesStartedAt: the atomic claim
// increments attempts exactly once, stamps started_at on the FIRST lease
// only, and a lost-runner re-lease consumes one further attempt while the
// original started_at survives.
func TestLeaseIncrementsAttemptsOnceAndPreservesStartedAt(t *testing.T) {
	st := newAtomicFakeStore()
	st.setLeader(true, nil)
	now := time.Now().UTC()
	_ = st.InsertRun(context.Background(), model.Run{ID: "run1", Status: model.StatusQueued, CreatedAt: now})
	_ = st.InsertJob(context.Background(), leaseTestJob("job1", "run1"))
	_ = st.UpsertRunner(context.Background(), model.Runner{ID: "r1", Name: "r1", Capacity: 2, CostPerHour: 2.5, PowerWatts: 42})
	s := NewDB(st, time.Minute, nil, nil)

	first, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC())
	if err != nil {
		t.Fatalf("first lease: %v", err)
	}
	if first.Attempts != 1 {
		t.Fatalf("attempts after first lease = %d, want 1", first.Attempts)
	}
	if first.StartedAt == nil {
		t.Fatal("started_at not set on first lease")
	}
	if first.CostRate != 2.5 || first.PowerWatts != 42 {
		t.Fatalf("frozen rates = %v/%v, want 2.5/42", first.CostRate, first.PowerWatts)
	}
	originalStart := *first.StartedAt

	requeueJob(t, st, "job1", "r1")
	second, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC())
	if err != nil {
		t.Fatalf("re-lease: %v", err)
	}
	if second.Attempts != 2 {
		t.Fatalf("attempts after lost-runner re-lease = %d, want 2", second.Attempts)
	}
	if second.StartedAt == nil || !second.StartedAt.Equal(originalStart) {
		t.Fatalf("started_at after re-lease = %v, want preserved %v", second.StartedAt, originalStart)
	}
}

// TestLeaseAtomicRefusesZeroCapacityDisabledDraining: the claim predicate
// rejects zero-capacity, disabled and draining runners.
func TestLeaseAtomicRefusesZeroCapacityDisabledDraining(t *testing.T) {
	cases := []struct {
		name   string
		runner model.Runner
	}{
		{"zero capacity", model.Runner{ID: "r1", Name: "r1", Capacity: 0}},
		{"disabled", model.Runner{ID: "r1", Name: "r1", Capacity: 2, Disabled: true}},
		{"draining", model.Runner{ID: "r1", Name: "r1", Capacity: 2, Draining: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newAtomicFakeStore()
			st.setLeader(true, nil)
			_ = st.InsertRun(context.Background(), model.Run{ID: "run1", Status: model.StatusQueued, CreatedAt: time.Now().UTC()})
			_ = st.InsertJob(context.Background(), leaseTestJob("job1", "run1"))
			_ = st.UpsertRunner(context.Background(), tc.runner)
			s := NewDB(st, time.Minute, nil, nil)
			if _, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
				t.Fatalf("lease = %v, want ErrNoJobs", err)
			}
			if j, _ := st.job("job1"); j.Status != model.StatusQueued {
				t.Fatalf("job mutated by refused lease: %+v", j)
			}
		})
	}
}

// TestLeaseResolvesLiveProfileRepoACL: the DB scheduler resolves the live
// linked profile at lease time. Shrinking the profile's repository ACL
// after registration immediately stops matching jobs.
func TestLeaseResolvesLiveProfileRepoACL(t *testing.T) {
	st := newAtomicFakeStore()
	st.setLeader(true, nil)
	_ = st.InsertRun(context.Background(), model.Run{ID: "run1", Status: model.StatusQueued, CreatedAt: time.Now().UTC()})
	_ = st.InsertJob(context.Background(), leaseTestJob("job1", "run1"))
	// The registration snapshot carries an empty ACL (no restriction); the
	// linked profile restricts the runner to a different repository.
	_ = st.UpsertRunner(context.Background(), model.Runner{ID: "r1", Name: "r1", Capacity: 2, CertSerial: "cert-1"})
	_ = st.UpsertProfile(context.Background(), model.RunnerProfile{ID: "p1", MaxCapacity: 2, Repositories: []string{"github.com/o/other"}})
	_ = st.BindCertProfile(context.Background(), "cert-1", "p1")
	s := NewDB(st, time.Minute, nil, nil)
	if _, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease against live profile ACL = %v, want ErrNoJobs", err)
	}
	// Widen the live profile: the same job now leases.
	_ = st.UpsertProfile(context.Background(), model.RunnerProfile{ID: "p1", MaxCapacity: 2, Repositories: []string{"github.com/o/r"}})
	if _, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC()); err != nil {
		t.Fatalf("lease after profile widen: %v", err)
	}
}

// TestLeaseEnvironmentConcurrencyOneWinner: two concurrent polls against
// environment concurrency 1 yield exactly one lease.
func TestLeaseEnvironmentConcurrencyOneWinner(t *testing.T) {
	st := newAtomicFakeStore()
	st.setLeader(true, nil)
	_ = st.InsertRun(context.Background(), model.Run{ID: "run1", Status: model.StatusQueued, CreatedAt: time.Now().UTC()})
	job1 := leaseTestJob("job1", "run1")
	job1.Environment = "prod"
	job1.EnvironmentConcurrency = 1
	job2 := leaseTestJob("job2", "run1")
	job2.Environment = "prod"
	job2.EnvironmentConcurrency = 1
	_ = st.InsertJob(context.Background(), job1)
	_ = st.InsertJob(context.Background(), job2)
	_ = st.UpsertRunner(context.Background(), model.Runner{ID: "r1", Name: "r1", Capacity: 1})
	_ = st.UpsertRunner(context.Background(), model.Runner{ID: "r2", Name: "r2", Capacity: 1})
	s := NewDB(st, time.Minute, nil, nil)
	type result struct{ err error }
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, runner := range []string{"r1", "r2"} {
		wg.Add(1)
		go func(runner string) {
			defer wg.Done()
			_, _, _, err := s.Lease(context.Background(), runner, time.Now().UTC())
			results <- result{err}
		}(runner)
	}
	wg.Wait()
	close(results)
	var won int
	for r := range results {
		if r.err == nil {
			won++
			continue
		}
		if !errors.Is(r.err, ErrNoJobs) {
			t.Fatalf("unexpected lease error: %v", r.err)
		}
	}
	if won != 1 {
		t.Fatalf("environment-concurrency winners = %d, want exactly 1", won)
	}
}

// TestLeaseQuotaConcurrencyOnlyOneRunning: with a repo concurrency limit of
// 1 the conditional queued->running transition admits exactly one lease.
func TestLeaseQuotaConcurrencyOnlyOneRunning(t *testing.T) {
	st := newAtomicFakeStore()
	st.setLeader(true, nil)
	_ = st.InsertRun(context.Background(), model.Run{ID: "run1", Status: model.StatusQueued, CreatedAt: time.Now().UTC()})
	for _, id := range []string{"job1", "job2"} {
		_ = st.InsertJob(context.Background(), leaseTestJob(id, "run1"))
	}
	_ = st.UpsertRunner(context.Background(), model.Runner{ID: "r1", Name: "r1", Capacity: 2})
	s := NewDB(st, time.Minute, nil, nil)
	s.SetQuotaLimits(1, 0)
	if _, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC()); err != nil {
		t.Fatalf("first quota lease: %v", err)
	}
	if _, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("second quota lease = %v, want ErrNoJobs", err)
	}
	running := 0
	for _, id := range []string{"job1", "job2"} {
		if j, _ := st.job(id); j.Status == model.StatusRunning {
			running++
		}
	}
	if running != 1 {
		t.Fatalf("running jobs = %d, want exactly 1", running)
	}
}

// TestLeaseEnforcedEmptyPolicyDeniesAll: a job whose effective policy is
// ENFORCED but grants no runtime is never leased.
func TestLeaseEnforcedEmptyPolicyDeniesAll(t *testing.T) {
	st := newAtomicFakeStore()
	st.setLeader(true, nil)
	_ = st.InsertRun(context.Background(), model.Run{ID: "run1", Status: model.StatusQueued, CreatedAt: time.Now().UTC()})
	job := leaseTestJob("job1", "run1")
	job.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1, EffectivePolicy: policy.Capabilities{Enforced: true}}
	_ = st.InsertJob(context.Background(), job)
	_ = st.UpsertRunner(context.Background(), model.Runner{ID: "r1", Name: "r1", Capacity: 2})
	s := NewDB(st, time.Minute, nil, nil)
	if _, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("enforced-empty-policy lease = %v, want ErrNoJobs", err)
	}
	// Granting the job's runtime makes it leasable again.
	granted := leaseTestJob("job2", "run1")
	granted.CompiledJobPayload = &model.CompiledJobPayload{
		SchemaVersion:   1,
		EffectiveJob:    compiledJobWithRuntime("job2", "run1", "https://github.com/o/r.git", "o/r", "container").CompiledJobPayload.EffectiveJob,
		EffectivePolicy: policy.Capabilities{Enforced: true, Container: true},
	}
	_ = st.InsertJob(context.Background(), granted)
	if _, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC()); err != nil {
		t.Fatalf("enforced-granted-policy lease: %v", err)
	}
}

// TestLeaseLiveProfileCapacityShrinkTakesNoWork: shrinking the live
// profile's max capacity to 0 denies further leases even though the
// registration snapshot still says 2.
func TestLeaseLiveProfileCapacityShrinkTakesNoWork(t *testing.T) {
	st := newAtomicFakeStore()
	st.setLeader(true, nil)
	_ = st.InsertRun(context.Background(), model.Run{ID: "run1", Status: model.StatusQueued, CreatedAt: time.Now().UTC()})
	_ = st.InsertJob(context.Background(), leaseTestJob("job1", "run1"))
	_ = st.UpsertRunner(context.Background(), model.Runner{ID: "r1", Name: "r1", Capacity: 2, CertSerial: "cert-1"})
	_ = st.UpsertProfile(context.Background(), model.RunnerProfile{ID: "p1", MaxCapacity: 1})
	_ = st.BindCertProfile(context.Background(), "cert-1", "p1")
	s := NewDB(st, time.Minute, nil, nil)
	if _, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC()); err != nil {
		t.Fatalf("initial profile lease: %v", err)
	}
	_ = st.UpsertProfile(context.Background(), model.RunnerProfile{ID: "p1", MaxCapacity: 0})
	_ = st.InsertJob(context.Background(), leaseTestJob("job2", "run1"))
	if _, _, _, err := s.Lease(context.Background(), "r1", time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("zero-capacity profile lease = %v, want ErrNoJobs", err)
	}
}
