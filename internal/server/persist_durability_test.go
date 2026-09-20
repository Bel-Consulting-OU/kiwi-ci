package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// usageMetricsSnapshot reads the process-local usage counters under the
// metrics lock.
func usageMetricsSnapshot(s *Server) (cost, energy float64) {
	s.Metrics.mu.Lock()
	defer s.Metrics.mu.Unlock()
	return s.Metrics.counters["kiwi_usage_cost_total"][""], s.Metrics.counters["kiwi_usage_energy_total"][""]
}

// registerUsageRunner registers a runner carrying usage rates and leases the
// run's first job, mirroring the TestCompletionAggregatesUsage fixture.
func registerUsageRunner(t *testing.T, s *Server) (string, Task) {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2,"cost_per_hour":7200,"power_watts":500}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	return ri.ID, task
}

// TestReadinessDegradedOnPersistFailureAndHeals pins the degraded-state
// contract end to end through the persistFailForTest seam: a mutation whose
// snapshot write fails arms the degraded readiness signal (503 +
// X-Kiwi-State: degraded + a FIXED body), and the next successful persist
// heals it. The body must never echo the raw persist error or a path:
// /readiness is unauthenticated (X1A).
func TestReadinessDegradedOnPersistFailureAndHeals(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	seamErr := errors.New("synthetic snapshot write failure")

	t.Run("registration arms degraded readiness", func(t *testing.T) {
		s.persistFailForTest = seamErr
		// The cheapest persisting mutation: runner registration. It answers
		// 200 (the in-memory registration succeeded) and deliberately does
		// not propagate the persist error; readiness is the fail-closed
		// signal.
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
			`{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
		if w.Code != http.StatusOK {
			t.Fatalf("register = %d, want 200: %s", w.Code, w.Body.String())
		}
		w = doJSON(t, s, http.MethodGet, "/readiness", "", "")
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("readiness after failed persist = %d, want 503: %s", w.Code, w.Body.String())
		}
		if got := w.Header().Get("X-Kiwi-State"); got != "degraded" {
			t.Fatalf("X-Kiwi-State = %q, want degraded", got)
		}
		body := w.Body.String()
		if body != statePersistenceDegradedBody+"\n" {
			t.Fatalf("readiness body = %q, want the fixed %q", body, statePersistenceDegradedBody)
		}
		if strings.Contains(body, seamErr.Error()) {
			t.Fatalf("readiness body leaked the persist error: %q", body)
		}
		if strings.Contains(body, dir) {
			t.Fatalf("readiness body leaked the data directory path: %q", body)
		}
	})

	t.Run("successful persist heals readiness", func(t *testing.T) {
		s.persistFailForTest = nil
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
			`{"name":"r2","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
		if w.Code != http.StatusOK {
			t.Fatalf("healing register = %d, want 200: %s", w.Code, w.Body.String())
		}
		w = doJSON(t, s, http.MethodGet, "/readiness", "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("readiness after successful persist = %d, want 200: %s", w.Code, w.Body.String())
		}
		if got := w.Header().Get("X-Kiwi-State"); got != "" {
			t.Fatalf("X-Kiwi-State after heal = %q, want empty", got)
		}
	})

	t.Run("completion failure answers 503", func(t *testing.T) {
		if _, err := s.enqueue(context.Background(), SubmitRun{
			RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
			Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
		}); err != nil {
			t.Fatal(err)
		}
		runnerID, task := leaseRunJob(t, s)
		s.persistFailForTest = seamErr
		if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("complete with a broken snapshot store = %d, want 503: %s", w.Code, w.Body.String())
		}
		w := doJSON(t, s, http.MethodGet, "/readiness", "", "")
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("X-Kiwi-State") != "degraded" {
			t.Fatalf("readiness after failed completion = %d/%q, want 503/degraded", w.Code, w.Header().Get("X-Kiwi-State"))
		}
		// Clearing the fault lets the retry heal both the completion and the
		// readiness signal.
		s.persistFailForTest = nil
		if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
			t.Fatalf("retried complete = %d: %s", w.Code, w.Body.String())
		}
		if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusOK {
			t.Fatalf("readiness after healed completion = %d, want 200", w.Code)
		}
	})
}

// queuedJobForRun returns the (single-job) run's job under s.mu.
func queuedJobForRun(t *testing.T, s *Server, run model.Run) model.Job {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.RunID == run.ID {
			return j
		}
	}
	t.Fatalf("no job for run %s", run.ID)
	return model.Job{}
}

// TestLeaseRefusedWhileDegradedAndHeals is the X1B regression for the
// security-relevant lease path: a lease token is a capability for a running
// job that the snapshot must contain, so while a failed snapshot write has
// armed stateDegraded a lease request is refused with 503 and never receives
// a token; once a later persist heals the state the same queued job leases
// normally.
func TestLeaseRefusedWhileDegradedAndHeals(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Register the runner while the store is healthy; the refusal below can
	// then only come from the degraded gate, not from a missing runner.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	seamErr := errors.New("synthetic snapshot write failure")
	s.persistFailForTest = seamErr
	// Arm the degraded state with another persisting mutation; registration
	// answers 200 and /readiness is the fail-closed signal.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"r2","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`); w.Code != http.StatusOK {
		t.Fatalf("degrading register: %d %s", w.Code, w.Body.String())
	}
	if !s.stateDegraded.Load() {
		t.Fatal("failed persist did not arm stateDegraded")
	}

	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("lease while degraded = %d, want 503: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if body != statePersistenceDegradedBody+"\n" {
		t.Fatalf("refused lease body = %q, want the fixed %q", body, statePersistenceDegradedBody)
	}
	if strings.Contains(body, "token") || strings.Contains(body, seamErr.Error()) {
		t.Fatalf("refused lease body leaked a token or the persist error: %q", body)
	}
	if j := queuedJobForRun(t, s, run); j.Status != model.StatusQueued {
		t.Fatalf("refused lease changed the job status to %q, want queued", j.Status)
	}

	// Clearing the fault lets the next persist heal the state; the same job
	// then leases normally and hands the runner a token.
	s.persistFailForTest = nil
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"r3","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`); w.Code != http.StatusOK {
		t.Fatalf("healing register: %d %s", w.Code, w.Body.String())
	}
	if s.stateDegraded.Load() {
		t.Fatal("successful persist did not heal stateDegraded")
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("lease after heal = %d, want 200: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.LeaseToken == "" || task.Job.ID == "" {
		t.Fatalf("healed lease = %+v, want a token for the queued job", task)
	}
}

// TestLeasePersistFailureWithholdsTokenAndRecovers pins the post-claim half
// of X1B: the claim's own snapshot write fails after the in-memory claim was
// installed, so the handler answers 503 without a token AND rolls the claim
// back wholesale — the job stays queued (attempt not consumed, token hash
// cleared) and the runner slot is free — instead of retaining a phantom lease
// only expired-lease recovery could ever reclaim. Healing the store lets the
// SAME job lease exactly once, and the durable snapshot contains that one
// claim.
func TestLeasePersistFailureWithholdsTokenAndRecovers(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	pre := queuedJobForRun(t, s, run)
	s.mu.Lock()
	preActive := len(s.runners[ri.ID].ActiveJobs)
	s.mu.Unlock()
	seamErr := errors.New("synthetic snapshot write failure")
	// The server is healthy at entry, so the claim runs and it is the
	// claim's own persist that fails and arms the degraded state.
	s.persistFailForTest = seamErr
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("lease whose claim write fails = %d, want 503: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if body != statePersistenceDegradedBody+"\n" {
		t.Fatalf("refused lease body = %q, want the fixed %q", body, statePersistenceDegradedBody)
	}
	if strings.Contains(body, "token") {
		t.Fatalf("refused lease body leaked a token: %q", body)
	}
	if !s.stateDegraded.Load() {
		t.Fatal("failed claim persist did not arm stateDegraded")
	}
	// The claim is rolled back wholesale: queued, attempt unconsumed, no
	// token hash in memory, no runner slot held.
	j := queuedJobForRun(t, s, run)
	if j.Status != model.StatusQueued || j.Attempts != pre.Attempts || j.LeaseTokenHash != nil || j.LeaseRunnerID != "" {
		t.Fatalf("failed-persist claim not rolled back: %+v", j)
	}
	s.mu.Lock()
	active := len(s.runners[ri.ID].ActiveJobs)
	s.mu.Unlock()
	if active != preActive {
		t.Fatalf("failed-persist claim changed the runner slots: %d -> %d", preActive, active)
	}

	// Healing the store lets the same queued job lease exactly once: one
	// attempt consumed, one runner slot held, one durable claim. The failed
	// write armed the degraded gate, so heal it with a succeeding persist
	// first (the gate refuses new leases until then, by design).
	s.persistFailForTest = nil
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"r1-heal","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`); w.Code != http.StatusOK {
		t.Fatalf("healing register: %d %s", w.Code, w.Body.String())
	}
	if s.stateDegraded.Load() {
		t.Fatal("successful persist did not heal stateDegraded")
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("lease after heal = %d, want 200: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.LeaseToken == "" || task.Job.ID != pre.ID {
		t.Fatalf("healed lease = %+v, want a token for %s", task, pre.ID)
	}
	if task.Job.Attempts != pre.Attempts+1 {
		t.Fatalf("healed lease attempts = %d, want exactly %d (failed claim must not consume one)", task.Job.Attempts, pre.Attempts+1)
	}
	snap, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	disk := snap.Jobs[pre.ID]
	if disk.Status != model.StatusRunning || disk.LeaseRunnerID != ri.ID || len(disk.LeaseTokenHash) == 0 || disk.Attempts != pre.Attempts+1 {
		t.Fatalf("healed lease not durable exactly once: %+v", disk)
	}
}

// TestCompletePersistFailureRetryAccountsUsageOnce is the A1 regression: the
// first delivery fails its snapshot write (503) and must leave no usage claim
// behind; the retry re-runs the whole completion and accounts usage exactly
// once. Against the pre-fix ordering the first attempt's in-memory usage
// marker survived, the retry matched the receipt, and effectUsageAccount
// short-circuited on the marker — accounting the usage never once.
func TestCompletePersistFailureRetryAccountsUsageOnce(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID, task := registerUsageRunner(t, s)
	time.Sleep(20 * time.Millisecond) // non-zero billable duration

	seamErr := errors.New("synthetic snapshot write failure")
	s.persistFailForTest = seamErr
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("first complete = %d, want 503: %s", w.Code, w.Body.String())
	}

	// The failed attempt must be rolled back wholesale: no metrics, no
	// trailing-window entry, no usage marker, and the job restored to its
	// leased running state so the retry takes the primary completion path
	// again instead of the receipt replay path.
	costBefore, energyBefore := usageMetricsSnapshot(s)
	if costBefore != 0 || energyBefore != 0 {
		t.Fatalf("failed persist moved usage metrics: cost=%v energy=%v", costBefore, energyBefore)
	}
	s.usageMu.Lock()
	usageLen := len(s.usage)
	s.usageMu.Unlock()
	if usageLen != 0 {
		t.Fatalf("failed persist appended %d usage window entries", usageLen)
	}
	s.mu.Lock()
	j := s.jobs[task.Job.ID]
	runnerCompleted := s.runners[runnerID].Completed
	s.mu.Unlock()
	if j.UsageRecorded || j.Cost != 0 || j.EnergyWh != 0 {
		t.Fatalf("failed persist left a usage claim: %+v", j)
	}
	if j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID || j.LeaseTokenHash == nil {
		t.Fatalf("failed persist did not restore the pre-completion job: %+v", j)
	}
	if runnerCompleted != 0 {
		t.Fatalf("failed persist counted the completion on the runner: completed=%d", runnerCompleted)
	}

	// Retry with the store healthy: the whole path re-runs and accounts
	// usage once.
	s.persistFailForTest = nil
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("retried complete = %d: %s", w.Code, w.Body.String())
	}
	costOnce, energyOnce := usageMetricsSnapshot(s)
	if costOnce <= 0 || energyOnce <= 0 {
		t.Fatalf("retry did not account usage: cost=%v energy=%v", costOnce, energyOnce)
	}
	s.usageMu.Lock()
	if len(s.usage) != 1 {
		s.usageMu.Unlock()
		t.Fatalf("usage window entries after retry = %d, want exactly 1", len(s.usage))
	}
	windowCost := s.usage[0].Cost
	s.usageMu.Unlock()
	if windowCost != costOnce {
		t.Fatalf("usage window cost = %v, metrics cost = %v; want one accounting", windowCost, costOnce)
	}
	s.mu.Lock()
	j = s.jobs[task.Job.ID]
	runnerCompleted = s.runners[runnerID].Completed
	s.mu.Unlock()
	if !j.UsageRecorded || j.Cost <= 0 || j.EnergyWh <= 0 {
		t.Fatalf("job usage after retry = %+v", j)
	}
	if runnerCompleted != 1 {
		t.Fatalf("runner completions after retry = %d, want exactly 1", runnerCompleted)
	}

	// A duplicate delivery after the retry must short-circuit on the
	// receipt/marker and never account again.
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("duplicate complete = %d: %s", w.Code, w.Body.String())
	}
	costAfter, energyAfter := usageMetricsSnapshot(s)
	if costAfter != costOnce || energyAfter != energyOnce {
		t.Fatalf("duplicate delivery moved usage metrics: %v/%v -> %v/%v", costOnce, energyOnce, costAfter, energyAfter)
	}
	s.usageMu.Lock()
	usageLen = len(s.usage)
	s.usageMu.Unlock()
	if usageLen != 1 {
		t.Fatalf("usage window entries after duplicate = %d, want 1", usageLen)
	}
}

// TestEffectUsageAccountMemoryMarkerRaceSingleWinner races the memory-mode
// usage effect: the marker re-check under s.mu admits exactly one record, so
// the metrics and the trailing window see a single accounting even when every
// caller observed an unrecorded job before entering.
func TestEffectUsageAccountMemoryMarkerRaceSingleWinner(t *testing.T) {
	s := New("token")
	started := time.Now().UTC().Add(-time.Hour)
	s.mu.Lock()
	s.jobs["job-usage-race"] = model.Job{ID: "job-usage-race", RunID: "run-usage-race", Key: "build", StartedAt: &started, CostRate: 10, PowerWatts: 100}
	s.mu.Unlock()

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.effectUsageAccount(context.Background(), model.Job{
				ID: "job-usage-race", RunID: "run-usage-race", Key: "build",
				StartedAt: &started, CostRate: 10, PowerWatts: 100,
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("usage effect: %v", err)
		}
	}

	cost, energy := usageMetricsSnapshot(s)
	if cost <= 0 || energy <= 0 {
		t.Fatalf("usage never accounted: cost=%v energy=%v", cost, energy)
	}
	s.usageMu.Lock()
	if len(s.usage) != 1 {
		s.usageMu.Unlock()
		t.Fatalf("usage window entries = %d, want exactly 1", len(s.usage))
	}
	if s.usage[0].Cost != cost {
		entryCost := s.usage[0].Cost
		s.usageMu.Unlock()
		t.Fatalf("usage window cost = %v, metrics cost = %v; want one accounting", entryCost, cost)
	}
	s.usageMu.Unlock()
	s.mu.Lock()
	recorded := s.jobs["job-usage-race"].UsageRecorded
	s.mu.Unlock()
	if !recorded {
		t.Fatal("usage marker not set after the race")
	}
}

// TestEffectUsageAccountDBRecordUsageOnceBranches pins the DB-mode
// exactly-once arbitration: a store error fails closed without moving any
// metric, a lost race (won=false) moves nothing, and the winner accounts
// exactly once even when a stale caller retries.
func TestEffectUsageAccountDBRecordUsageOnceBranches(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	started := time.Now().UTC().Add(-time.Hour)
	job := model.Job{ID: "job-usage-db", RunID: "run-usage-db", Key: "build", StartedAt: &started, CostRate: 10, PowerWatts: 100}
	f.mu.Lock()
	f.jobs[job.ID] = job
	f.mu.Unlock()

	t.Run("store error fails closed", func(t *testing.T) {
		f.mu.Lock()
		f.updateJobErr = errors.New("usage row write failed")
		f.mu.Unlock()
		if err := s.effectUsageAccount(ctx, job); err == nil {
			t.Fatal("recordable job with a failing store must return the error")
		}
		if cost, energy := usageMetricsSnapshot(s); cost != 0 || energy != 0 {
			t.Fatalf("failed RecordUsageOnce moved metrics: cost=%v energy=%v", cost, energy)
		}
		f.mu.Lock()
		marked := f.jobs[job.ID].UsageRecorded
		f.mu.Unlock()
		if marked {
			t.Fatal("failed RecordUsageOnce marked usage recorded")
		}
	})

	t.Run("won=false moves nothing", func(t *testing.T) {
		f.mu.Lock()
		f.updateJobErr = nil
		winner := f.jobs[job.ID]
		winner.UsageRecorded = true
		winner.Cost = 1
		winner.EnergyWh = 1
		f.jobs[job.ID] = winner
		f.mu.Unlock()
		// The effect's copy predates the concurrent winner (marker false):
		// the store transition returns won=false and no metric may move.
		if err := s.effectUsageAccount(ctx, job); err != nil {
			t.Fatalf("lost race = %v, want nil", err)
		}
		if cost, energy := usageMetricsSnapshot(s); cost != 0 || energy != 0 {
			t.Fatalf("lost race moved metrics: cost=%v energy=%v", cost, energy)
		}
	})

	t.Run("won=true accounts exactly once", func(t *testing.T) {
		f.mu.Lock()
		reset := f.jobs[job.ID]
		reset.UsageRecorded = false
		reset.Cost = 0
		reset.EnergyWh = 0
		f.jobs[job.ID] = reset
		f.mu.Unlock()
		if err := s.effectUsageAccount(ctx, job); err != nil {
			t.Fatalf("winner = %v", err)
		}
		costOnce, energyOnce := usageMetricsSnapshot(s)
		if costOnce <= 0 || energyOnce <= 0 {
			t.Fatalf("winner did not account usage: cost=%v energy=%v", costOnce, energyOnce)
		}
		// A stale replay (marker false on the caller's copy, true in the
		// store) must lose the transition and not move the metrics again.
		if err := s.effectUsageAccount(ctx, job); err != nil {
			t.Fatalf("stale replay = %v", err)
		}
		costAfter, energyAfter := usageMetricsSnapshot(s)
		if costAfter != costOnce || energyAfter != energyOnce {
			t.Fatalf("stale replay moved metrics: %v/%v -> %v/%v", costOnce, energyOnce, costAfter, energyAfter)
		}
		f.mu.Lock()
		stored := f.jobs[job.ID]
		f.mu.Unlock()
		if !stored.UsageRecorded || stored.Cost <= 0 {
			t.Fatalf("stored usage after winner = %+v", stored)
		}
	})

	t.Run("store without the exactly-once contract fails closed", func(t *testing.T) {
		// fcPlainStore hides every extension interface, so the effect cannot
		// arbitrate the transition; it must refuse instead of falling back to
		// a last-writer-wins read-modify-write.
		plain := New("token")
		plain.DB = fcPlainStore{newDBFakeStore()}
		err := plain.effectUsageAccount(ctx, job)
		if err == nil {
			t.Fatal("store without UsageOnceStore = nil error, want fail-closed refusal")
		}
		if !strings.Contains(err.Error(), "exactly-once") {
			t.Fatalf("fail-closed error = %v, want the contract diagnostic", err)
		}
		if cost, energy := usageMetricsSnapshot(plain); cost != 0 || energy != 0 {
			t.Fatalf("fail-closed refusal moved metrics: cost=%v energy=%v", cost, energy)
		}
	})
}
