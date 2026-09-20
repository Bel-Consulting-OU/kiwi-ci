package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// rollbackFanoutPipeline has two independent container jobs so one runner
// with capacity >= 2 can hold two active jobs at once.
const rollbackFanoutPipeline = `version: 1
jobs:
  alpha:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo alpha
  beta:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo beta
`

// rollbackDependencyPipeline has a dependent job that becomes terminally
// blocked while the primary job fails.
const rollbackDependencyPipeline = `version: 1
jobs:
  primary:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo primary
  dependent:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    needs:
      - primary
    steps:
      - run: echo dependent
`

// leaseNextRollbackTask leases the next queued job for an already registered
// runner.
func leaseNextRollbackTask(t *testing.T, s *Server, runnerID string) Task {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next = %d, want 200: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	return task
}

// registerRollbackRunner registers a container runner with the given
// capacity and returns its ID.
func registerRollbackRunner(t *testing.T, s *Server, capacity int) string {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		fmt.Sprintf(`{"name":"rb","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":%d}`, capacity))
	if w.Code != http.StatusOK {
		t.Fatalf("register = %d, want 200: %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	return ri.ID
}

// TestCompletionRollbackRestoresRunnerActiveJobsExactly is the CRITICAL 1
// regression: releaseRunnerLocked removed the completed job from the
// runner's ActiveJobs with an in-place compaction (removeString's out :=
// in[:0]), which overwrote the backing array a completion rollback had
// captured. Rolling back a failed-persist completion therefore restored a
// corrupted ActiveJobs: the completed job was lost and the surviving
// (last) job duplicated. The test completes a NON-last active job through a
// failing persist and asserts the runner record is byte-for-byte the
// pre-completion one, then retries and pins the final accounting.
func TestCompletionRollbackRestoresRunnerActiveJobsExactly(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: rollbackFanoutPipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 2)
	first := leaseNextRollbackTask(t, s, runnerID)
	second := leaseNextRollbackTask(t, s, runnerID)

	// Pre-completion runner state: both leased jobs, in lease order.
	s.mu.Lock()
	pre := s.runners[runnerID]
	preActive := slices.Clone(pre.ActiveJobs)
	preBusy, preCurrent, preCompleted := pre.Busy, pre.CurrentJob, pre.Completed
	s.mu.Unlock()
	if len(preActive) != 2 || preActive[0] != first.Job.ID || preActive[1] != second.Job.ID {
		t.Fatalf("pre-completion ActiveJobs = %v, want [%s %s]", preActive, first.Job.ID, second.Job.ID)
	}
	if !preBusy || preCurrent != first.Job.ID || preCompleted != 0 {
		t.Fatalf("pre-completion runner = busy=%v current=%q completed=%d", preBusy, preCurrent, preCompleted)
	}

	// Complete the NON-last active job through a failing snapshot write.
	seamErr := errors.New("synthetic snapshot write failure")
	s.persistFailForTest = seamErr
	if w := completeTask(t, s, first, runnerID, "success"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("complete with a broken snapshot store = %d, want 503: %s", w.Code, w.Body.String())
	}

	s.mu.Lock()
	got := s.runners[runnerID]
	gotActive := slices.Clone(got.ActiveJobs)
	gotBusy, gotCurrent, gotCompleted := got.Busy, got.CurrentJob, got.Completed
	restoredJob := s.jobs[first.Job.ID]
	_, hasReceipt := s.completions[completionReceiptKey(first.Job.ID, first.LeaseGeneration, runnerID)]
	s.mu.Unlock()

	if !slices.Equal(gotActive, preActive) {
		t.Fatalf("rollback corrupted runner ActiveJobs: got %v, want exactly %v (completed job lost / last job duplicated)", gotActive, preActive)
	}
	if gotBusy != preBusy || gotCurrent != preCurrent || gotCompleted != preCompleted {
		t.Fatalf("rollback did not restore runner accounting: busy=%v current=%q completed=%d, want %v/%q/%d",
			gotBusy, gotCurrent, gotCompleted, preBusy, preCurrent, preCompleted)
	}
	if restoredJob.Status != model.StatusRunning || restoredJob.LeaseRunnerID != runnerID || restoredJob.LeaseTokenHash == nil {
		t.Fatalf("rollback did not restore the leased running job: %+v", restoredJob)
	}
	if hasReceipt {
		t.Fatal("rollback left the completion receipt behind")
	}

	// Clear the seam: the retry re-runs the whole completion and accounts
	// the first job exactly once.
	s.persistFailForTest = nil
	if w := completeTask(t, s, first, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("retried complete = %d, want 204: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	afterFirst := s.runners[runnerID]
	afterFirstActive := slices.Clone(afterFirst.ActiveJobs)
	firstJob := s.jobs[first.Job.ID]
	s.mu.Unlock()
	if !slices.Equal(afterFirstActive, []string{second.Job.ID}) {
		t.Fatalf("ActiveJobs after retried completion = %v, want [%s]", afterFirstActive, second.Job.ID)
	}
	if afterFirst.CurrentJob != second.Job.ID || afterFirst.Busy || afterFirst.Completed != 1 {
		t.Fatalf("runner after retried completion = busy=%v current=%q completed=%d", afterFirst.Busy, afterFirst.CurrentJob, afterFirst.Completed)
	}
	if firstJob.Status != model.StatusSuccess || !firstJob.UsageRecorded {
		t.Fatalf("first job after retried completion = %+v", firstJob)
	}

	// Completing the last active job drains the runner exactly.
	if w := completeTask(t, s, second, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete second = %d, want 204: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	finalRunner := s.runners[runnerID]
	finalActive := slices.Clone(finalRunner.ActiveJobs)
	secondJob := s.jobs[second.Job.ID]
	s.mu.Unlock()
	if len(finalActive) != 0 || finalRunner.CurrentJob != "" || finalRunner.Busy || finalRunner.Completed != 2 {
		t.Fatalf("runner after both completions: active=%v current=%q busy=%v completed=%d",
			finalActive, finalRunner.CurrentJob, finalRunner.Busy, finalRunner.Completed)
	}
	if secondJob.Status != model.StatusSuccess {
		t.Fatalf("second job = %+v", secondJob)
	}
}

// TestCompletionRollbackRestoresDependentJobAndRun is the CRITICAL 2
// regression: scheduleStateLocked terminally blocks a dependency-blocked
// dependent while the primary completion is applied, but the rollback only
// restored the completed job and its run. A failed-persist completion of a
// FAILING primary therefore left the dependent blocked in memory; a retried
// completion reporting SUCCESS then could never schedule it (it was already
// terminal), and the following persist wrote the wedged dependent to disk.
// The test forces the persist failure, asserts the dependent and its run are
// back to their pre-completion state, retries with success, and asserts the
// memory and reloaded disk state are mutually consistent.
func TestCompletionRollbackRestoresDependentJobAndRun(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: rollbackDependencyPipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 2)
	task := leaseNextRollbackTask(t, s, runnerID)

	// Locate the dependent job and snapshot the pre-completion state.
	var primaryID, dependentID string
	s.mu.Lock()
	for id, j := range s.jobs {
		if j.RunID != run.ID {
			continue
		}
		switch j.Key {
		case "primary":
			primaryID = id
		case "dependent":
			dependentID = id
		}
	}
	prePrimary := s.jobs[primaryID]
	preDependent := s.jobs[dependentID]
	preRun := s.runs[run.ID]
	s.mu.Unlock()
	if primaryID == "" || dependentID == "" {
		t.Fatalf("jobs not found: primary=%q dependent=%q", primaryID, dependentID)
	}
	if prePrimary.Status != model.StatusRunning || preDependent.Status != model.StatusQueued {
		t.Fatalf("pre-completion states: primary=%s dependent=%s", prePrimary.Status, preDependent.Status)
	}

	// First attempt: the primary FAILS, which blocks the dependent, but the
	// snapshot write fails and the whole path must roll back.
	seamErr := errors.New("synthetic snapshot write failure")
	s.persistFailForTest = seamErr
	if w := completeTask(t, s, task, runnerID, "failure"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("complete with a broken snapshot store = %d, want 503: %s", w.Code, w.Body.String())
	}

	s.mu.Lock()
	afterRollbackPrimary := s.jobs[primaryID]
	afterRollbackDependent := s.jobs[dependentID]
	afterRollbackRun := s.runs[run.ID]
	_, hasReceipt := s.completions[completionReceiptKey(task.Job.ID, task.LeaseGeneration, runnerID)]
	s.mu.Unlock()
	if afterRollbackPrimary.Status != prePrimary.Status || afterRollbackPrimary.Error != prePrimary.Error {
		t.Fatalf("rollback did not restore the primary: %+v, want status=%s error=%q", afterRollbackPrimary, prePrimary.Status, prePrimary.Error)
	}
	if afterRollbackDependent.Status != preDependent.Status || afterRollbackDependent.DependencyStatus != preDependent.DependencyStatus {
		t.Fatalf("rollback left the dependent mutated: status=%s dependency=%s, want %s/%s (blocked by a completion that never became durable)",
			afterRollbackDependent.Status, afterRollbackDependent.DependencyStatus, preDependent.Status, preDependent.DependencyStatus)
	}
	if afterRollbackRun.Status != preRun.Status || afterRollbackRun.FinishedAt != nil {
		t.Fatalf("rollback left the run re-aggregated: status=%s finished=%v, want status=%s finished=nil",
			afterRollbackRun.Status, afterRollbackRun.FinishedAt, preRun.Status)
	}
	if hasReceipt {
		t.Fatal("rollback left the completion receipt behind")
	}

	// Clear the seam and retry with SUCCESS: the dependent must reflect the
	// retried result, not the failed attempt's.
	s.persistFailForTest = nil
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("retried complete = %d, want 204: %s", w.Code, w.Body.String())
	}

	s.mu.Lock()
	memPrimary := s.jobs[primaryID]
	memDependent := s.jobs[dependentID]
	memRun := s.runs[run.ID]
	s.mu.Unlock()
	if memPrimary.Status != model.StatusSuccess {
		t.Fatalf("primary after retry = %s, want success", memPrimary.Status)
	}
	if memDependent.Status == model.StatusBlocked || memDependent.Status.Terminal() {
		t.Fatalf("dependent after successful retry = %s (dependency=%s): terminally blocked by a completion that never became durable",
			memDependent.Status, memDependent.DependencyStatus)
	}
	if memDependent.Status != model.StatusQueued || memDependent.DependencyStatus != model.StatusSuccess {
		t.Fatalf("dependent after retry = status=%s dependency=%s, want queued/success", memDependent.Status, memDependent.DependencyStatus)
	}
	if memRun.Status != model.StatusQueued {
		t.Fatalf("run after retry = %s, want queued (primary success, dependent still queued)", memRun.Status)
	}

	// The disk reload must agree with memory: the dependent must not carry
	// the failed attempt's terminal block.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	diskPrimary := s2.jobs[primaryID]
	diskDependent := s2.jobs[dependentID]
	diskRun := s2.runs[run.ID]
	s2.mu.Unlock()
	if diskPrimary.Status != memPrimary.Status {
		t.Fatalf("disk primary = %s, memory = %s", diskPrimary.Status, memPrimary.Status)
	}
	if diskDependent.Status != memDependent.Status || diskDependent.DependencyStatus != memDependent.DependencyStatus {
		t.Fatalf("disk dependent = status=%s dependency=%s, memory = %s/%s",
			diskDependent.Status, diskDependent.DependencyStatus, memDependent.Status, memDependent.DependencyStatus)
	}
	if diskRun.Status != memRun.Status {
		t.Fatalf("disk run = %s, memory = %s", diskRun.Status, memRun.Status)
	}
	if diskDependent.Status == model.StatusBlocked {
		t.Fatal("disk persisted a dependent terminally blocked by a completion that never became durable")
	}
}

// TestCompletionRollbackRestoresSingleActiveJobRunner is the capacity-1
// common case: completing the ONLY active job through a failing persist must
// restore the single-job ActiveJobs slice exactly (the pre-fix in-place
// compaction happened to survive len==1, so this guards the fix against
// over-correction).
func TestCompletionRollbackRestoresSingleActiveJobRunner(t *testing.T) {
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
	runnerID := registerRollbackRunner(t, s, 1)
	task := leaseNextRollbackTask(t, s, runnerID)

	s.mu.Lock()
	pre := s.runners[runnerID]
	preActive := slices.Clone(pre.ActiveJobs)
	preBusy, preCurrent, preCompleted := pre.Busy, pre.CurrentJob, pre.Completed
	s.mu.Unlock()
	if !slices.Equal(preActive, []string{task.Job.ID}) || !preBusy || preCurrent != task.Job.ID {
		t.Fatalf("pre-completion runner = active=%v busy=%v current=%q, want [%s]/true/%s", preActive, preBusy, preCurrent, task.Job.ID, task.Job.ID)
	}

	seamErr := errors.New("synthetic snapshot write failure")
	s.persistFailForTest = seamErr
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("complete with a broken snapshot store = %d, want 503: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	got := s.runners[runnerID]
	gotActive := slices.Clone(got.ActiveJobs)
	gotJob := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if !slices.Equal(gotActive, preActive) || got.Busy != preBusy || got.CurrentJob != preCurrent || got.Completed != preCompleted {
		t.Fatalf("rollback over-corrected the single active job: active=%v busy=%v current=%q completed=%d, want %v/%v/%q/%d",
			gotActive, got.Busy, got.CurrentJob, got.Completed, preActive, preBusy, preCurrent, preCompleted)
	}
	if gotJob.Status != model.StatusRunning || gotJob.LeaseRunnerID != runnerID {
		t.Fatalf("single active job not restored: %+v", gotJob)
	}

	s.persistFailForTest = nil
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("retried complete = %d, want 204: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	finalRunner := s.runners[runnerID]
	finalActive := slices.Clone(finalRunner.ActiveJobs)
	s.mu.Unlock()
	if len(finalActive) != 0 || finalRunner.CurrentJob != "" || finalRunner.Busy || finalRunner.Completed != 1 {
		t.Fatalf("runner after retried completion: active=%v current=%q busy=%v completed=%d",
			finalActive, finalRunner.CurrentJob, finalRunner.Busy, finalRunner.Completed)
	}
}
