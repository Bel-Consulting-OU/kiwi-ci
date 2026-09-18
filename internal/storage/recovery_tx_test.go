package storage

// Behavior tests for the transactional recovery/revocation contract
// (RecoveryStore) against the in-memory store and the fault-injection
// wrapper. The real-PostgreSQL counterparts live in the *_it_test.go files.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

const (
	recRunID   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01"
	recJobRet  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02"
	recJobFail = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03"
	recDepID   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04"
	recOther   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa05"
	recRunner1 = "cccccccccccccccccccccccccccccc01"
	recRunner2 = "cccccccccccccccccccccccccccccc02"
	recRepo    = "https://github.com/o/r.git"
)

var recRepoID = RepoIDFor("", recRepo, "o/r")

// recSeedLeased plants one run with a leased job on runner1, a dependent
// queued behind it and a queued reservation, plus a job on another runner
// that must stay untouched.
func recSeedLeased(t *testing.T, m *memStore, attempts, maxRetries int) {
	t.Helper()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	run := model.Run{ID: recRunID, Repo: recRepo, RepoFullName: "o/r", Status: model.StatusRunning, CreatedAt: now}
	if err := m.InsertRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	leased := model.Job{ID: recJobRet, RunID: recRunID, Key: "build", RepoURL: recRepo, RepoFullName: "o/r", Status: model.StatusRunning,
		Attempts: attempts, MaxInfraRetries: maxRetries, LeaseRunnerID: recRunner1, LeaseTokenHash: []byte{1}, LeaseGeneration: 2, LeaseExpiresAt: &exp, CreatedAt: now}
	if err := m.InsertJob(context.Background(), leased); err != nil {
		t.Fatal(err)
	}
	dep := model.Job{ID: recDepID, RunID: recRunID, Key: "deploy", RepoURL: recRepo, RepoFullName: "o/r", Status: model.StatusQueued, Condition: "success()", Needs: []string{recJobRet}, CreatedAt: now}
	if err := m.InsertJob(context.Background(), dep); err != nil {
		t.Fatal(err)
	}
	other := model.Job{ID: recOther, RunID: recRunID + "o", Key: "other", RepoURL: recRepo, RepoFullName: "o/r", Status: model.StatusRunning,
		Attempts: 1, MaxInfraRetries: 2, LeaseRunnerID: recRunner2, LeaseGeneration: 1, LeaseExpiresAt: &exp, CreatedAt: now}
	if err := m.InsertRun(context.Background(), model.Run{ID: recRunID + "o", Repo: recRepo, Status: model.StatusRunning, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := m.InsertJob(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertRunner(context.Background(), model.Runner{ID: recRunner1, Name: "r1", Capacity: 2, ActiveJobs: []string{recJobRet}, Failed: 7}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertRunner(context.Background(), model.Runner{ID: recRunner2, Name: "r2", Capacity: 1, ActiveJobs: []string{recOther}}); err != nil {
		t.Fatal(err)
	}
	// Running reservation for the leased job plus a queued reservation for
	// the dependent: the revocation must release exactly the leased slot.
	m.adjustQuotaLocked(recRepoID, 1, 1)
}

func TestMemStoreRevokeRunnerLeasesAtomic(t *testing.T) {
	m := newMemStore()
	recSeedLeased(t, m, 1, 2)
	m.recoveryFaultOps = 0
	ctx := context.Background()

	revoked, err := m.RevokeRunnerLeases(ctx, recRunner1, "runner disabled")
	if err != nil {
		t.Fatalf("RevokeRunnerLeases: %v", err)
	}
	if len(revoked) != 1 || revoked[0] != recJobRet {
		t.Fatalf("revoked = %v, want [%s]", revoked, recJobRet)
	}
	j, err := m.GetJob(ctx, recJobRet)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != model.StatusQueued || j.Error != "runner disabled; retrying" {
		t.Fatalf("revoked job = %s/%q, want queued/retrying", j.Status, j.Error)
	}
	if j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("lease not cleared: %+v", j)
	}
	if j.Attempts != 1 {
		t.Fatalf("attempts = %d, want the lease-time increment only", j.Attempts)
	}
	ri, _ := m.GetRunner(ctx, recRunner1)
	if len(ri.ActiveJobs) != 0 || ri.Busy || ri.CurrentJob != "" {
		t.Fatalf("runner1 after revocation = active=%v busy=%v current=%q", ri.ActiveJobs, ri.Busy, ri.CurrentJob)
	}
	if ri.Failed != 8 {
		t.Fatalf("runner1 failed counter = %d, want 8 (one invalidated lease)", ri.Failed)
	}
	other, _ := m.GetRunner(ctx, recRunner2)
	if len(other.ActiveJobs) != 1 || other.ActiveJobs[0] != recOther {
		t.Fatalf("runner2 active jobs = %v, want untouched", other.ActiveJobs)
	}
	if other.Failed != 0 {
		t.Fatalf("runner2 failed counter = %d, want untouched", other.Failed)
	}
	if running, queued, _ := m.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 2 {
		t.Fatalf("quota after revocation = %d/%d, want 0/2", running, queued)
	}
	// The revoked job was REQUEUED, so its dependent is still waiting on a
	// non-terminal need: it stays queued (the blocking case is covered by
	// the budget-exhausted test below).
	dep, _ := m.GetJob(ctx, recDepID)
	if dep.Status != model.StatusQueued {
		t.Fatalf("dependent of a requeued job = %s, want queued", dep.Status)
	}
	audit, _ := m.ReadAudit(ctx, 10)
	actions := map[string]bool{}
	for _, e := range audit {
		actions[e.Action] = true
	}
	if !actions["job.runner_disabled_requeued"] {
		t.Fatalf("audit missing requeue event: %+v", audit)
	}

	// A second replica racing the same revocation is a no-op: no double
	// release, no second failure counter bump.
	again, err := m.RevokeRunnerLeases(ctx, recRunner1, "runner disabled")
	if err != nil || len(again) != 0 {
		t.Fatalf("replayed revocation = %v/%v, want empty/nil", again, err)
	}
	if running, queued, _ := m.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 2 {
		t.Fatalf("quota after replay = %d/%d, want unchanged 0/2", running, queued)
	}
	if ri, _ := m.GetRunner(ctx, recRunner1); ri.Failed != 8 {
		t.Fatalf("runner1 failed after replay = %d, want 8", ri.Failed)
	}
}

func TestMemStoreRevokeRunnerLeasesCancelsWhenBudgetExhausted(t *testing.T) {
	m := newMemStore()
	recSeedLeased(t, m, 3, 2)
	ctx := context.Background()
	revoked, err := m.RevokeRunnerLeases(ctx, recRunner1, "runner disabled")
	if err != nil || len(revoked) != 1 {
		t.Fatalf("revoke = %v/%v", revoked, err)
	}
	j, _ := m.GetJob(ctx, recJobRet)
	if j.Status != model.StatusCancelled || j.Error != "runner disabled" || j.FinishedAt == nil {
		t.Fatalf("exhausted job = %+v, want cancelled with finish time", j)
	}
	if j.Attempts != 3 {
		t.Fatalf("attempts = %d, want 3 (no recovery increment)", j.Attempts)
	}
	if running, queued, _ := m.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 1 {
		t.Fatalf("quota after cancel = %d/%d, want 0/1", running, queued)
	}
	audit, _ := m.ReadAudit(ctx, 10)
	found := false
	for _, e := range audit {
		if e.Action == "job.runner_disabled_cancelled" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit missing cancel event: %+v", audit)
	}
	// The cancelled job's success()-conditioned dependent is blocked in the
	// same transaction.
	dep, _ := m.GetJob(ctx, recDepID)
	if dep.Status != model.StatusBlocked || dep.DependencyStatus != model.StatusCancelled {
		t.Fatalf("dependent of a cancelled job = %s/%s, want blocked/cancelled", dep.Status, dep.DependencyStatus)
	}
}

func TestMemStoreRecoveryCrashWindowRollsBack(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("RevokeRunnerLeases", func(t *testing.T) {
		m := newMemStore()
		recSeedLeased(t, m, 1, 2)
		baseline := m.snapshot()
		// Stage the job write, the quota move, the audit and the runner
		// update, then fail before the dependent/run recompute commits: the
		// overlay must be discarded and the baseline stay byte-identical.
		m.recoveryFaultOps = 4
		m.recoveryFaultErr = errors.New("injected revocation failure")
		revoked, err := m.RevokeRunnerLeases(ctx, recRunner1, "runner disabled")
		if err == nil || len(revoked) != 0 {
			t.Fatalf("revoke = %v/%v, want injected failure", revoked, err)
		}
		if got := m.snapshot(); !reflect.DeepEqual(got, baseline) {
			t.Fatalf("failed revocation left partial state:\n before: %+v\n after:  %+v", baseline, got)
		}
	})

	t.Run("RecoverExpiredLease", func(t *testing.T) {
		m := newMemStore()
		recSeedLeased(t, m, 1, 2)
		m.mu.Lock()
		j := m.jobs[recJobRet]
		expired := now.Add(-time.Minute)
		j.LeaseExpiresAt = &expired
		m.jobs[recJobRet] = j
		m.mu.Unlock()
		baseline := m.snapshot()
		// The run recompute is the last staged write; failing there proves
		// the whole transaction (job, quota, runner, audit, dependents)
		// rolls back.
		m.recoveryFaultOps = 6
		m.recoveryFaultErr = errors.New("injected recovery failure")
		if err := m.RecoverExpiredLease(ctx, recJobRet, 2, now); err == nil {
			t.Fatal("expected injected recovery failure")
		}
		if got := m.snapshot(); !reflect.DeepEqual(got, baseline) {
			t.Fatalf("failed recovery left partial state:\n before: %+v\n after:  %+v", baseline, got)
		}
	})

	t.Run("ExpireQueuedJob", func(t *testing.T) {
		m := newMemStore()
		recSeedLeased(t, m, 1, 2)
		m.mu.Lock()
		j := m.jobs[recDepID]
		expired := now.Add(-time.Minute)
		j.QueueDeadline = &expired
		m.jobs[recDepID] = j
		m.mu.Unlock()
		baseline := m.snapshot()
		// Last staged write is the run recompute.
		m.recoveryFaultOps = 5
		m.recoveryFaultErr = errors.New("injected expire failure")
		if err := m.ExpireQueuedJob(ctx, recDepID, expired); err == nil {
			t.Fatal("expected injected expire failure")
		}
		if got := m.snapshot(); !reflect.DeepEqual(got, baseline) {
			t.Fatalf("failed expire left partial state:\n before: %+v\n after:  %+v", baseline, got)
		}
	})
}

func TestMemStoreRecoverExpiredLeaseAtomic(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	m := newMemStore()
	recSeedLeased(t, m, 1, 2)
	m.mu.Lock()
	j := m.jobs[recJobRet]
	expired := now.Add(-time.Minute)
	j.LeaseExpiresAt = &expired
	m.jobs[recJobRet] = j
	m.mu.Unlock()

	// A generation mismatch is a race with a re-lease: leave the job alone.
	if err := m.RecoverExpiredLease(ctx, recJobRet, 9, now); err != nil {
		t.Fatalf("mismatched generation = %v, want no-op", err)
	}
	if j, _ := m.GetJob(ctx, recJobRet); j.Status != model.StatusRunning {
		t.Fatalf("job after mismatched generation = %s, want running", j.Status)
	}

	if err := m.RecoverExpiredLease(ctx, recJobRet, 2, now); err != nil {
		t.Fatalf("RecoverExpiredLease: %v", err)
	}
	j, _ = m.GetJob(ctx, recJobRet)
	if j.Status != model.StatusQueued || j.Error != "runner lease expired; retrying" {
		t.Fatalf("recovered job = %s/%q, want queued/retrying", j.Status, j.Error)
	}
	if j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("lease not cleared: %+v", j)
	}
	if j.Attempts != 1 {
		t.Fatalf("attempts = %d, want the lease-time increment only", j.Attempts)
	}
	ri, _ := m.GetRunner(ctx, recRunner1)
	if len(ri.ActiveJobs) != 0 || ri.Failed != 8 {
		t.Fatalf("runner after recovery = active=%v failed=%d, want empty/8", ri.ActiveJobs, ri.Failed)
	}
	if running, queued, _ := m.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 2 {
		t.Fatalf("quota after recovery = %d/%d, want 0/2", running, queued)
	}
	// The recovered job was requeued (non-terminal), so the dependent is
	// still waiting; the exhausted path below blocks it.
	dep, _ := m.GetJob(ctx, recDepID)
	if dep.Status != model.StatusQueued {
		t.Fatalf("dependent after requeue = %s, want queued", dep.Status)
	}

	// Exactly once: the replay observes a queued job and changes nothing.
	if err := m.RecoverExpiredLease(ctx, recJobRet, 2, now); err != nil {
		t.Fatalf("replayed recovery: %v", err)
	}
	if running, queued, _ := m.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 2 {
		t.Fatalf("quota after replayed recovery = %d/%d, want unchanged 0/2", running, queued)
	}
	if ri, _ := m.GetRunner(ctx, recRunner1); ri.Failed != 8 {
		t.Fatalf("runner failed after replay = %d, want 8", ri.Failed)
	}

	// A budget-exhausted lease fails terminally.
	m2 := newMemStore()
	recSeedLeased(t, m2, 3, 2)
	m2.mu.Lock()
	j2 := m2.jobs[recJobRet]
	j2.LeaseExpiresAt = &expired
	m2.jobs[recJobRet] = j2
	m2.mu.Unlock()
	if err := m2.RecoverExpiredLease(ctx, recJobRet, 2, now); err != nil {
		t.Fatalf("RecoverExpiredLease (exhausted): %v", err)
	}
	j2, _ = m2.GetJob(ctx, recJobRet)
	if j2.Status != model.StatusFailure || j2.FinishedAt == nil {
		t.Fatalf("exhausted job = %+v, want failure", j2)
	}
	if running, queued, _ := m2.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 1 {
		t.Fatalf("quota after exhaustion = %d/%d, want 0/1", running, queued)
	}
	if dep2, _ := m2.GetJob(ctx, recDepID); dep2.Status != model.StatusBlocked {
		t.Fatalf("dependent of an exhausted lease = %s, want blocked", dep2.Status)
	}
}

func TestMemStoreRecoverExpiredLeaseLiveLeaseUntouched(t *testing.T) {
	m := newMemStore()
	recSeedLeased(t, m, 1, 2)
	now := time.Now().UTC()
	baseline := m.snapshot()
	if err := m.RecoverExpiredLease(ctx(), recJobRet, 2, now); err != nil {
		t.Fatalf("RecoverExpiredLease: %v", err)
	}
	if got := m.snapshot(); !reflect.DeepEqual(got, baseline) {
		t.Fatalf("live lease was recovered:\n before: %+v\n after:  %+v", baseline, got)
	}
}

func TestMemStoreExpireQueuedJobAtomic(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	m := newMemStore()
	recSeedLeased(t, m, 1, 2)
	m.mu.Lock()
	j := m.jobs[recDepID]
	deadline := now.Add(-time.Minute)
	j.QueueDeadline = &deadline
	m.jobs[recDepID] = j
	m.mu.Unlock()

	// A stale (future) observation of the deadline must not expire the job.
	if err := m.ExpireQueuedJob(ctx, recDepID, deadline.Add(-time.Hour)); err != nil {
		t.Fatalf("stale deadline: %v", err)
	}
	if j, _ := m.GetJob(ctx, recDepID); j.Status != model.StatusQueued {
		t.Fatalf("job with stale deadline = %s, want queued", j.Status)
	}

	if err := m.ExpireQueuedJob(ctx, recDepID, deadline); err != nil {
		t.Fatalf("ExpireQueuedJob: %v", err)
	}
	j, _ = m.GetJob(ctx, recDepID)
	if j.Status != model.StatusCancelled || j.Error != "queue timeout" || j.FinishedAt == nil {
		t.Fatalf("expired job = %+v, want cancelled/queue timeout", j)
	}
	if running, queued, _ := m.QuotaCounts(ctx, recRepoID, ""); running != 1 || queued != 0 {
		t.Fatalf("quota after expire = %d/%d, want 1/0", running, queued)
	}
	if _, err := m.GetJob(ctx, recOther); err != nil {
		t.Fatal(err)
	}
	audit, _ := m.ReadAudit(ctx, 10)
	found := false
	for _, e := range audit {
		if e.Action == "job.queue_timeout" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit missing queue timeout event: %+v", audit)
	}

	// Replay releases nothing a second time.
	if err := m.ExpireQueuedJob(ctx, recDepID, deadline); err != nil {
		t.Fatalf("replayed expire: %v", err)
	}
	if running, queued, _ := m.QuotaCounts(ctx, recRepoID, ""); running != 1 || queued != 0 {
		t.Fatalf("quota after replayed expire = %d/%d, want unchanged 1/0", running, queued)
	}
}

// TestMemStoreRecoveryConcurrentReplicas races two callers through the same
// store: the mutex-serialized transitions must behave exactly like two
// database transactions — one wins, the other observes nothing to do, and
// every counter moves exactly once.
func TestMemStoreRecoveryConcurrentReplicas(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	now := time.Now().UTC()
	recSeedLeased(t, m, 1, 2)
	m.mu.Lock()
	j := m.jobs[recJobRet]
	expired := now.Add(-time.Minute)
	j.LeaseExpiresAt = &expired
	m.jobs[recJobRet] = j
	m.mu.Unlock()

	var wg sync.WaitGroup
	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			revoked, err := m.RevokeRunnerLeases(ctx, recRunner1, "runner disabled")
			if err != nil {
				t.Errorf("concurrent revoke: %v", err)
				results <- -1
				return
			}
			results <- len(revoked)
		}()
	}
	wg.Wait()
	close(results)
	total := 0
	for n := range results {
		total += n
	}
	if total != 1 {
		t.Fatalf("total revoked across replicas = %d, want 1", total)
	}
	if ri, _ := m.GetRunner(ctx, recRunner1); ri.Failed != 8 {
		t.Fatalf("runner failed = %d, want 8 (exactly one accounting)", ri.Failed)
	}
	if running, queued, _ := m.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 2 {
		t.Fatalf("quota = %d/%d, want exactly-once release 0/2", running, queued)
	}

	// Concurrent expired-lease recovery: exactly one transition applies.
	var wg2 sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			if err := m.RecoverExpiredLease(ctx, recJobRet, 2, now); err != nil {
				t.Errorf("concurrent recovery: %v", err)
			}
		}()
	}
	wg2.Wait()
	if j, _ := m.GetJob(ctx, recJobRet); j.Status != model.StatusQueued {
		t.Fatalf("job after concurrent recovery = %s, want queued", j.Status)
	}
	if ri, _ := m.GetRunner(ctx, recRunner1); ri.Failed != 8 {
		t.Fatalf("runner failed after concurrent recovery = %d, want still 8", ri.Failed)
	}
}

// TestFaultyStoreRecoveryInjection proves the fault wrapper fails closed
// before touching the inner store for each transactional recovery method.
func TestFaultyStoreRecoveryInjection(t *testing.T) {
	for name, call := range map[string]func(*FaultyStore) error{
		"RevokeRunnerLeases": func(f *FaultyStore) error {
			_, err := f.RevokeRunnerLeases(ctx(), recRunner1, "disable")
			return err
		},
		"RecoverExpiredLease": func(f *FaultyStore) error {
			return f.RecoverExpiredLease(ctx(), recJobRet, 2, time.Now().UTC())
		},
		"ExpireQueuedJob": func(f *FaultyStore) error {
			return f.ExpireQueuedJob(ctx(), recDepID, time.Now().UTC())
		},
	} {
		t.Run(name, func(t *testing.T) {
			inner := newMemStore()
			recSeedLeased(t, inner, 1, 2)
			baseline := inner.snapshot()
			fs := &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom}
			if err := call(fs); !errors.Is(err, errBoom) {
				t.Fatalf("injected fault = %v, want errBoom", err)
			}
			if got := inner.snapshot(); !reflect.DeepEqual(got, baseline) {
				t.Fatalf("faulted wrapper leaked a write: %+v", got)
			}
		})
	}
}

// TestQueueDeadlineForVariants pins the canonical deadline derivation moved
// from the scheduler package: the persisted deadline wins, the compiled
// payload's queue_timeout is the fallback, and malformed payloads never
// invent a deadline.
func TestQueueDeadlineForVariants(t *testing.T) {
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
	created := time.Unix(5000, 0).UTC()
	want := created.Add(30 * time.Second)

	cases := []struct {
		name string
		job  model.Job
		want *time.Time
	}{
		{"nil payload", model.Job{}, nil},
		{"nil effective job", model.Job{CompiledJobPayload: &model.CompiledJobPayload{}}, nil},
		{"raw message", model.Job{CreatedAt: created, CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: json.RawMessage(raw)}}, &want},
		{"byte slice", model.Job{CreatedAt: created, CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: raw}}, &want},
		{"string", model.Job{CreatedAt: created, CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: string(raw)}}, &want},
		{"struct value", model.Job{CreatedAt: created, CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: pipeline.CompiledJob{Job: pipeline.Job{QueueTimeout: pipeline.Duration{Duration: 5 * time.Second, Set: true}}}}}, ptrTime(created.Add(5 * time.Second))},
		{"invalid json", model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: []byte("{nope")}}, nil},
		{"no timeout", model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: []byte("{}")}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := QueueDeadlineFor(tc.job)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("QueueDeadlineFor = %v, want nil", got)
				}
				return
			}
			if got == nil || !got.Equal(*tc.want) {
				t.Fatalf("QueueDeadlineFor = %v, want %v", got, *tc.want)
			}
		})
	}

	// The persisted field wins over the payload-derived fallback.
	persisted := time.Unix(9000, 0).UTC()
	j := model.Job{CreatedAt: created, QueueDeadline: &persisted, CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: raw}}
	if got := QueueDeadlineFor(j); got == nil || !got.Equal(persisted) {
		t.Fatalf("persisted deadline = %v, want %v", got, persisted)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
