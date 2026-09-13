package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func testHash(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func TestNewDBDefaults(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	s := NewDB(f, 0, nil, nil)
	if s.InitErr() != nil {
		t.Fatalf("InitErr = %v, want nil", s.InitErr())
	}
	if s.LeaseDuration != DefaultLeaseDuration {
		t.Errorf("LeaseDuration = %v, want %v", s.LeaseDuration, DefaultLeaseDuration)
	}
	tok, err := s.NewToken()
	if err != nil {
		t.Fatalf("default token gen: %v", err)
	}
	if len(tok) != 64 {
		t.Errorf("default token length = %d, want 64", len(tok))
	}
	want := testHash(tok)
	got := s.HashToken(tok)
	if len(got) != len(want) {
		t.Fatalf("hash length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("default hash mismatch: %x vs %x", got, want)
		}
	}
}

func TestNewDBStandbyWhenLeadershipHeldElsewhere(t *testing.T) {
	f := newFakeStore()
	f.setLeader(false, nil)
	s := NewDB(f, time.Minute, nil, nil)
	if s.InitErr() != nil {
		t.Fatalf("InitErr = %v, want nil (standby is not an error)", s.InitErr())
	}
	if s.IsLeader(context.Background()) {
		t.Fatal("expected standby")
	}
	if _, _, _, err := s.Lease(context.Background(), "runner", time.Now()); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("Lease on standby = %v, want ErrNotLeader", err)
	}
	// Promotion: the leadership claim is won later, and the very next lease
	// proceeds (the server runs RecoverExpired once on this edge).
	f.setLeader(true, nil)
	if !s.IsLeader(context.Background()) {
		t.Fatal("expected promotion")
	}
}

func TestNewDBInitErrOnStoreFailure(t *testing.T) {
	f := newFakeStore()
	f.setLeader(false, errors.New("boom"))
	s := NewDB(f, time.Minute, nil, nil)
	if s.InitErr() == nil {
		t.Fatal("InitErr = nil, want store failure")
	}
}

func TestLeaseDelegatesTokenAndHash(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 1, LastSeen: now})
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now})
	f.putJob(model.Job{ID: "job", RunID: "run", Key: "build", Status: model.StatusQueued, Priority: 3, CreatedAt: now})

	rawToken := "tok-123"
	s := NewDB(f, time.Minute, func() (string, error) { return rawToken, nil }, testHash)
	s.LeaderKey = "test-key"
	if !s.IsLeader(context.Background()) {
		t.Fatal("expected leader")
	}
	j, raw, expires, err := s.Lease(context.Background(), "runner", now)
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if j == nil || j.ID != "job" {
		t.Fatalf("leased job = %+v, want job", j)
	}
	if raw != rawToken {
		t.Errorf("raw token = %q, want %q", raw, rawToken)
	}
	wantExpiry := now.Add(time.Minute)
	if !expires.Equal(wantExpiry) {
		t.Errorf("expiry = %v, want %v", expires, wantExpiry)
	}
	if len(f.acquireCalls) != 1 {
		t.Fatalf("acquire calls = %d, want 1", len(f.acquireCalls))
	}
	ac := f.acquireCalls[0]
	if ac.JobID != "job" || ac.RunnerID != "runner" {
		t.Errorf("acquire args = %+v", ac)
	}
	if hex.EncodeToString(ac.TokenHash) != hex.EncodeToString(testHash(rawToken)) {
		t.Errorf("token hash = %x, want %x", ac.TokenHash, testHash(rawToken))
	}
	cur, _ := f.job("job")
	if ac.Generation != 1 || cur.LeaseGeneration != 1 {
		t.Errorf("generation = %d (acquire) / %d (job), want 1/1 (0+1)", ac.Generation, cur.LeaseGeneration)
	}
	ri, err := f.GetRunner(context.Background(), "runner")
	if err != nil {
		t.Fatalf("runner after lease: %v", err)
	}
	if len(ri.ActiveJobs) != 1 || ri.ActiveJobs[0] != "job" {
		t.Errorf("runner active jobs = %v, want [job]", ri.ActiveJobs)
	}
	if j.NeedsOutputs == nil {
		t.Error("leased job NeedsOutputs not populated")
	}
}

func TestLeaseRunnerAtCapacity(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 1, Busy: true, ActiveJobs: []string{"other"}})
	f.putJob(model.Job{ID: "job", RunID: "run", Status: model.StatusQueued, CreatedAt: now})
	s := NewDB(f, time.Minute, nil, nil)
	_, _, _, err := s.Lease(context.Background(), "runner", now)
	if !errors.Is(err, ErrNoJobs) {
		t.Fatalf("Lease at capacity = %v, want ErrNoJobs", err)
	}
}

func TestLeaseSkipsUnreadyDependencies(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 3})
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now})
	// dep is queued (not terminal) and itself requires a label this runner
	// lacks, so neither dep nor its dependent can be leased.
	f.putJob(model.Job{ID: "dep", RunID: "run", Key: "dep", Status: model.StatusQueued, RequiredLabels: []string{"mac"}, CreatedAt: now})
	f.putJob(model.Job{ID: "job1", RunID: "run", Key: "job1", Status: model.StatusQueued, Needs: []string{"dep"}, CreatedAt: now})
	s := NewDB(f, time.Minute, nil, nil)
	if _, _, _, err := s.Lease(context.Background(), "runner", now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("Lease with pending dep = %v, want ErrNoJobs", err)
	}
	// A failed dep: under the unified evaluator an empty condition behaves
	// like success(), so the dependent is blocked and must not be leased.
	f.putJob(model.Job{ID: "dep2", RunID: "run", Key: "dep2", Status: model.StatusFailure, CreatedAt: now})
	f.putJob(model.Job{ID: "job2", RunID: "run", Key: "job2", Status: model.StatusQueued, Needs: []string{"dep2"}, CreatedAt: now})
	if _, _, _, err := s.Lease(context.Background(), "runner", now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("Lease with failed dep and empty condition = %v, want ErrNoJobs", err)
	}
	// A failure()-conditioned dependent is also leasable after the failed
	// dep, and a success()-conditioned one is not.
	f.putJob(model.Job{ID: "dep3", RunID: "run", Key: "dep3", Status: model.StatusFailure, CreatedAt: now})
	f.putJob(model.Job{ID: "job3", RunID: "run", Key: "job3", Status: model.StatusQueued, Condition: "failure()", Needs: []string{"dep3"}, CreatedAt: now})
	f.putJob(model.Job{ID: "job4", RunID: "run", Key: "job4", Status: model.StatusQueued, Condition: "success()", Needs: []string{"dep3"}, CreatedAt: now})
	j, _, _, err := s.Lease(context.Background(), "runner", now)
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if j.ID != "job3" {
		t.Errorf("leased %s, want job3 (failure() allows failure outcome, success() does not)", j.ID)
	}
}

func TestHeartbeatReportsCancellation(t *testing.T) {
	f := newFakeStore()
	now := time.Now().UTC()
	f.putJob(model.Job{ID: "job", RunID: "run", Status: model.StatusCancelled})
	s := NewDB(f, time.Minute, nil, nil)
	cancelled, err := s.Heartbeat(context.Background(), "job", "runner", nil, 1, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Heartbeat cancelled job: %v", err)
	}
	if !cancelled {
		t.Error("Heartbeat = not cancelled, want cancelled")
	}

	f.putJob(model.Job{ID: "job2", RunID: "run", Status: model.StatusRunning, LeaseRunnerID: "runner", LeaseGeneration: 1})
	exp := now.Add(time.Minute)
	cancelled, err = s.Heartbeat(context.Background(), "job2", "runner", testHash("t"), 1, exp)
	if err != nil {
		t.Fatalf("Heartbeat running job: %v", err)
	}
	if cancelled {
		t.Error("Heartbeat = cancelled, want not cancelled")
	}
	if len(f.heartbeatCalls) != 1 || f.heartbeatCalls[0].JobID != "job2" || !f.heartbeatCalls[0].ExpiresAt.Equal(exp) {
		t.Errorf("heartbeat calls = %+v", f.heartbeatCalls)
	}
}

func TestCompleteBuildsReceipt(t *testing.T) {
	f := newFakeStore()
	f.putJob(model.Job{ID: "job", RunID: "run", Status: model.StatusRunning, LeaseRunnerID: "runner", LeaseGeneration: 7})
	s := NewDB(f, time.Minute, nil, nil)
	err := s.Complete(context.Background(), "job", 7, "runner", model.StatusSuccess, "", map[string]string{"out": "1"}, "hash-abc")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if len(f.completeCalls) != 1 {
		t.Fatalf("complete calls = %d, want 1", len(f.completeCalls))
	}
	c := f.completeCalls[0]
	if c.Receipt.JobID != "job" || c.Receipt.Generation != 7 || c.Receipt.RunnerID != "runner" || c.Receipt.ResultHash != "hash-abc" {
		t.Errorf("receipt = %+v", c.Receipt)
	}
	if c.Status != model.StatusSuccess || c.Outputs["out"] != "1" {
		t.Errorf("complete args = %+v", c)
	}
	// Idempotent replay: the exact same completion is acknowledged again.
	if err := s.Complete(context.Background(), "job", 7, "runner", model.StatusSuccess, "", map[string]string{"out": "1"}, "hash-abc"); err != nil {
		t.Fatalf("replayed Complete: %v", err)
	}
	if len(f.completeCalls) != 2 {
		t.Errorf("complete calls after replay = %d, want 2 (delegated, store dedupes)", len(f.completeCalls))
	}
}

func TestCancelRunDelegates(t *testing.T) {
	f := newFakeStore()
	now := time.Now().UTC()
	f.putRun(model.Run{ID: "run", Status: model.StatusRunning, CreatedAt: now})
	f.putJob(model.Job{ID: "job", RunID: "run", Status: model.StatusRunning})
	f.putJob(model.Job{ID: "done", RunID: "run", Status: model.StatusSuccess})
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.CancelRun(context.Background(), "run", "user says stop"); err != nil {
		t.Fatalf("CancelRun: %v", err)
	}
	if len(f.cancelRunCalls) != 1 || f.cancelRunCalls[0].RunID != "run" || f.cancelRunCalls[0].Reason != "user says stop" {
		t.Errorf("cancel calls = %+v", f.cancelRunCalls)
	}
	if j, _ := f.job("job"); j.Status != model.StatusCancelled {
		t.Errorf("running job status = %q, want cancelled", j.Status)
	}
	if j, _ := f.job("done"); j.Status != model.StatusSuccess {
		t.Errorf("terminal job status = %q, want success", j.Status)
	}
}

func TestEnqueueInsertsRunAndJobs(t *testing.T) {
	f := newFakeStore()
	now := time.Now().UTC()
	run := model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now}
	jobs := map[string]model.Job{
		"job1": {ID: "job1", RunID: "run", Key: "a", Status: model.StatusQueued, CreatedAt: now},
		"job2": {ID: "job2", RunID: "run", Key: "b", Status: model.StatusQueued, Needs: []string{"job1"}, CreatedAt: now},
	}
	deps := map[string][]string{"job1": nil, "job2": {"job1"}}
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.Enqueue(context.Background(), run, jobs, deps, false); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if len(f.insertRunCalls) != 1 || f.insertRunCalls[0].ID != "run" {
		t.Errorf("insert run calls = %+v", f.insertRunCalls)
	}
	if len(f.insertJobCalls) != 2 {
		t.Errorf("insert job calls = %d, want 2", len(f.insertJobCalls))
	}
}

func TestEnqueueSupersedesConcurrencyGroup(t *testing.T) {
	f := newFakeStore()
	now := time.Now().UTC()
	f.putRun(model.Run{ID: "old", Repo: "repo", ConcurrencyGroup: "grp", Status: model.StatusRunning, CreatedAt: now})
	f.putJob(model.Job{ID: "oldjob", RunID: "old", Status: model.StatusQueued})
	f.putRun(model.Run{ID: "unrelated", Repo: "repo", ConcurrencyGroup: "other", Status: model.StatusRunning, CreatedAt: now})
	f.putJob(model.Job{ID: "otherjob", RunID: "unrelated", Status: model.StatusQueued})
	run := model.Run{ID: "new", Repo: "repo", ConcurrencyGroup: "grp", Status: model.StatusQueued, CreatedAt: now}
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.Enqueue(context.Background(), run, map[string]model.Job{"newjob": {ID: "newjob", RunID: "new", Status: model.StatusQueued}}, nil, true); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if len(f.cancelRunCalls) != 1 || f.cancelRunCalls[0].RunID != "old" {
		t.Errorf("cancel calls = %+v, want exactly [old]", f.cancelRunCalls)
	}
	if j, _ := f.job("oldjob"); j.Status != model.StatusCancelled {
		t.Errorf("superseded job status = %q, want cancelled", j.Status)
	}
	if j, _ := f.job("otherjob"); j.Status != model.StatusQueued {
		t.Errorf("unrelated job status = %q, want queued", j.Status)
	}
}

func TestRecoverExpiredRequeuesWithinBudget(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	exp := now.Add(-time.Minute)
	f.putRun(model.Run{ID: "run", Status: model.StatusRunning, CreatedAt: now})
	f.putJob(model.Job{ID: "job", RunID: "run", Key: "build", Status: model.StatusRunning, Attempts: 1, MaxInfraRetries: 2, LeaseRunnerID: "runner", LeaseGeneration: 1, LeaseExpiresAt: &exp})
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 1, ActiveJobs: []string{"job"}})
	s := NewDB(f, time.Minute, nil, nil)
	if !s.IsLeader(context.Background()) {
		t.Fatal("expected leader")
	}
	if err := s.RecoverExpired(context.Background(), now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	j, _ := f.job("job")
	if j.Status != model.StatusQueued {
		t.Errorf("job status = %q, want queued", j.Status)
	}
	if j.LeaseRunnerID != "" || j.LeaseExpiresAt != nil || j.LeaseTokenHash != nil {
		t.Errorf("lease not cleared: %+v", j)
	}
	if len(f.releaseRunnerCalls) != 1 || f.releaseRunnerCalls[0].RunnerID != "runner" {
		t.Errorf("release calls = %+v", f.releaseRunnerCalls)
	}
	audits := f.audits()
	if len(audits) != 1 || audits[0].Action != "job.lease_expired" {
		t.Errorf("audit events = %+v, want one job.lease_expired", audits)
	}
}

func TestRecoverExpiredFailsWhenBudgetExhausted(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	exp := now.Add(-time.Minute)
	f.putRun(model.Run{ID: "run", Status: model.StatusRunning, CreatedAt: now})
	f.putJob(model.Job{ID: "job", RunID: "run", Key: "build", Status: model.StatusRunning, Attempts: 3, MaxInfraRetries: 2, LeaseRunnerID: "runner", LeaseGeneration: 1, LeaseExpiresAt: &exp})
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 1})
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.RecoverExpired(context.Background(), now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	j, _ := f.job("job")
	if j.Status != model.StatusFailure {
		t.Errorf("job status = %q, want failure", j.Status)
	}
	if j.FinishedAt == nil {
		t.Error("job FinishedAt not set")
	}
	audits := f.audits()
	if len(audits) != 1 || audits[0].Action != "job.lost_runner" {
		t.Errorf("audit events = %+v, want one job.lost_runner", audits)
	}
	run, _ := f.GetRun(context.Background(), "run")
	if run.Status != model.StatusFailure {
		t.Errorf("run status = %q, want failure", run.Status)
	}
}

func TestRecoverExpiredRequiresLeader(t *testing.T) {
	f := newFakeStore()
	f.setLeader(false, nil)
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.RecoverExpired(context.Background(), time.Now()); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("RecoverExpired on standby = %v, want ErrNotLeader", err)
	}
}

func TestRecoverExpiredSkipsUnexpiredLeases(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	fut := now.Add(time.Hour)
	f.putRun(model.Run{ID: "run", Status: model.StatusRunning, CreatedAt: now})
	f.putJob(model.Job{ID: "job", RunID: "run", Status: model.StatusRunning, Attempts: 1, MaxInfraRetries: 2, LeaseRunnerID: "runner", LeaseExpiresAt: &fut})
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.RecoverExpired(context.Background(), now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	j, _ := f.job("job")
	if j.Status != model.StatusRunning {
		t.Errorf("job status = %q, want running (lease still valid)", j.Status)
	}
	if len(f.audits()) != 0 {
		t.Errorf("unexpected audit events: %+v", f.audits())
	}
}

func TestRecoverExpiredBlocksDependents(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	exp := now.Add(-time.Minute)
	f.putRun(model.Run{ID: "run", Status: model.StatusRunning, CreatedAt: now})
	f.putJob(model.Job{ID: "up", RunID: "run", Key: "up", Status: model.StatusRunning, Attempts: 9, MaxInfraRetries: 1, LeaseRunnerID: "runner", LeaseExpiresAt: &exp})
	// A success()-conditioned dependent cannot run on a failed dep: blocked.
	f.putJob(model.Job{ID: "down", RunID: "run", Key: "down", Status: model.StatusQueued, Condition: "success()", Needs: []string{"up"}})
	// Under the unified evaluator an empty condition behaves like success():
	// a failed dependency blocks the dependent.
	f.putJob(model.Job{ID: "free", RunID: "run", Key: "free", Status: model.StatusQueued, Needs: []string{"up"}})
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.RecoverExpired(context.Background(), now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	j, _ := f.job("down")
	if j.Status != model.StatusBlocked {
		t.Errorf("dependent status = %q, want blocked", j.Status)
	}
	if j.DependencyStatus != model.StatusFailure {
		t.Errorf("dependent DependencyStatus = %q, want failure", j.DependencyStatus)
	}
	j, _ = f.job("free")
	if j.Status != model.StatusBlocked {
		t.Errorf("unconditioned dependent status = %q, want blocked", j.Status)
	}
	if j.DependencyStatus != model.StatusFailure {
		t.Errorf("unconditioned dependent DependencyStatus = %q, want failure", j.DependencyStatus)
	}
}
