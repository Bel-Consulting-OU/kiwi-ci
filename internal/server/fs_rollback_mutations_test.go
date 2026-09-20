package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// captureStateForTest snapshots the authoritative in-memory maps under s.mu,
// using the same capture the production rollback uses, so a test comparing
// before/after sees exactly what a rollback would restore.
func captureStateForTest(t *testing.T, s *Server) stateRollback {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.captureStateRollbackLocked()
}

// TestHeartbeatPersistFailureRollsBackExpiryAndRefuses is B1: a heartbeat
// whose snapshot write fails must not extend the lease. Before the fix the
// handler mutated the in-memory expiry, ignored the persist result and
// answered 200 with the extended deadline, so the runner adopted a deadline
// the disk never recorded (duplicate-execution window after a crash).
func TestHeartbeatPersistFailureRollsBackExpiryAndRefuses(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
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
	oldExp := *s.jobs[task.Job.ID].LeaseExpiresAt
	oldSeen := s.runners[runnerID].LastSeen
	s.mu.Unlock()

	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token",
		string(leaseBodyFor(t, runnerID, task.LeaseToken, task.LeaseGeneration, nil)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("heartbeat with a broken snapshot store = %d, want 503: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "heartbeat not durable\n" {
		t.Fatalf("refused heartbeat body = %q, want the fixed %q", body, "heartbeat not durable\n")
	}
	if w.Header().Get("Content-Type") == "application/json" {
		t.Fatalf("refused heartbeat answered JSON: %q", w.Body.String())
	}

	s.mu.Lock()
	gotExp := *s.jobs[task.Job.ID].LeaseExpiresAt
	gotSeen := s.runners[runnerID].LastSeen
	s.mu.Unlock()
	if !gotExp.Equal(oldExp) {
		t.Fatalf("failed-persist heartbeat moved the in-memory expiry: %v -> %v", oldExp, gotExp)
	}
	if !gotSeen.Equal(oldSeen) {
		t.Fatalf("failed-persist heartbeat moved LastSeen: %v -> %v", oldSeen, gotSeen)
	}

	// Healing the store lets the same heartbeat extend the lease; the 200
	// carries the new deadline only after the write succeeded.
	s.persistFailForTest = nil
	w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token",
		string(leaseBodyFor(t, runnerID, task.LeaseToken, task.LeaseGeneration, nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("healed heartbeat = %d, want 200: %s", w.Code, w.Body.String())
	}
	var hb HeartbeatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &hb); err != nil {
		t.Fatal(err)
	}
	if !hb.LeaseExpiresAt.After(oldExp) {
		t.Fatalf("healed heartbeat expiry %v did not extend past %v", hb.LeaseExpiresAt, oldExp)
	}
	s.mu.Lock()
	memExp := *s.jobs[task.Job.ID].LeaseExpiresAt
	s.mu.Unlock()
	if !memExp.Equal(hb.LeaseExpiresAt) {
		t.Fatalf("memory expiry %v != acknowledged expiry %v", memExp, hb.LeaseExpiresAt)
	}
	snap, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	diskExp := snap.Jobs[task.Job.ID].LeaseExpiresAt
	if diskExp == nil {
		t.Fatal("durable snapshot lost the heartbeat lease expiry")
	}
	if !diskExp.Equal(hb.LeaseExpiresAt) {
		t.Fatalf("durable snapshot expiry %v != acknowledged expiry %v (the runner adopted a deadline the disk never recorded)", *diskExp, hb.LeaseExpiresAt)
	}
}

// TestCancelPersistFailureRollsBackAndPublishesNothing is B2: a cancel whose
// snapshot write fails must restore every job/run/runner-slot mutation the
// cancel path made, answer 503, and enqueue no forge intent.
func TestCancelPersistFailureRollsBackAndPublishesNothing(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	// Configure GitHub publishing so a real publication intent would be
	// observable in the outbox.
	s.GitHubToken = "publish-token"
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push", Pipeline: smokePipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseRunJob(t, s)
	if task.Job.RunID != run.ID {
		t.Fatalf("leased job %s belongs to run %s, want %s", task.Job.ID, task.Job.RunID, run.ID)
	}
	baseline := len(s.outbox.Pending())
	pre := captureStateForTest(t, s)

	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cancel with a broken snapshot store = %d, want 503: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "cancel state not durable\n" {
		t.Fatalf("refused cancel body = %q, want the fixed %q", body, "cancel state not durable\n")
	}
	post := captureStateForTest(t, s)
	if !reflect.DeepEqual(pre, post) {
		t.Fatalf("failed-persist cancel changed in-memory state:\npre  runs=%v jobs=%v runners=%v\npost runs=%v jobs=%v runners=%v",
			pre.runs, pre.jobs, pre.runners, post.runs, post.jobs, post.runners)
	}
	if got := s.runs[run.ID].Status; got != pre.runs[run.ID].Status {
		t.Fatalf("failed-persist cancel left run status %s, want %s", got, pre.runs[run.ID].Status)
	}
	if got := s.jobs[task.Job.ID]; got.Status != model.StatusRunning || got.LeaseRunnerID != runnerID || got.LeaseTokenHash == nil {
		t.Fatalf("failed-persist cancel mutated the leased job: %+v", got)
	}
	if pending := len(s.outbox.Pending()); pending != baseline {
		t.Fatalf("failed-persist cancel created %d publication intent(s), want 0 (baseline %d)", pending-baseline, baseline)
	}

	// Heal: the cancel applies exactly once and its publication intents
	// exist. A repeated cancel must not change the state or add intents
	// (deterministic intent IDs dedupe).
	s.persistFailForTest = nil
	w = doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("healed cancel = %d, want 200: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	cancelledRun := s.runs[run.ID]
	cancelledJob := s.jobs[task.Job.ID]
	cancelledRunner := s.runners[runnerID]
	s.mu.Unlock()
	if cancelledRun.Status != model.StatusCancelled || cancelledRun.FinishedAt == nil {
		t.Fatalf("healed cancel run = %+v", cancelledRun)
	}
	if cancelledJob.Status != model.StatusCancelled || cancelledJob.LeaseTokenHash != nil {
		t.Fatalf("healed cancel job = %+v", cancelledJob)
	}
	if len(cancelledRunner.ActiveJobs) != 0 || cancelledRunner.Busy || cancelledRunner.CurrentJob != "" {
		t.Fatalf("healed cancel runner = %+v", cancelledRunner)
	}
	pendingAfterFirst := len(s.outbox.Pending())
	if pendingAfterFirst <= baseline {
		t.Fatalf("healed cancel left no publication intent (%d, baseline %d)", pendingAfterFirst, baseline)
	}
	finishedAt := *cancelledRun.FinishedAt
	if w = doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("repeated cancel = %d, want 200: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	againRun := s.runs[run.ID]
	s.mu.Unlock()
	if !againRun.FinishedAt.Equal(finishedAt) {
		t.Fatalf("repeated cancel moved finished_at: %v -> %v", finishedAt, againRun.FinishedAt)
	}
	if pending := len(s.outbox.Pending()); pending != pendingAfterFirst {
		t.Fatalf("repeated cancel added %d duplicate publication intent(s)", pending-pendingAfterFirst)
	}
}

// TestEnqueuePersistFailureLeavesNoGhostRunOrClaim is B3: an fs-mode enqueue
// whose snapshot write fails must restore the whole pre-enqueue map state, so
// no ghost run/job/contract/downstream link/occurrence claim can be committed
// by a later successful persist or duplicated by a client retry.
func TestEnqueuePersistFailureLeavesNoGhostRunOrClaim(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	nominal := time.Now().UTC().Truncate(time.Second)
	in := SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
		Metadata:      map[string]string{"github_delivery": "del-1"},
		ScheduleClaim: &storage.ScheduleClaim{ScheduleID: "sched-1", Nominal: nominal},
		DownstreamLaunch: &storage.DownstreamLaunchClaim{
			LinkKey:       "link-1",
			StableChildID: "stable-child-1",
		},
	}
	pre := captureStateForTest(t, s)

	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	run, err := s.enqueueID(context.Background(), in, "run-fixed-1")
	if err == nil {
		t.Fatalf("enqueue with a broken snapshot store = nil error, run %+v", run)
	}
	post := captureStateForTest(t, s)
	if !reflect.DeepEqual(pre, post) {
		t.Fatalf("failed-persist enqueue left state behind:\nruns=%v jobs=%v contracts=%v deliveries=%v links=%v occurrences=%v",
			s.runs, s.jobs, s.contracts, s.deliveries, s.downstreamLinks, s.occurrences)
	}
	s.mu.Lock()
	_, hasRun := s.runs["run-fixed-1"]
	_, hasDelivery := s.deliveries["del-1"]
	_, hasLink := s.downstreamLinks["link-1"]
	_, hasOccurrence := s.occurrences["sched-1"]
	s.mu.Unlock()
	if hasRun || hasDelivery || hasLink || hasOccurrence {
		t.Fatalf("ghost claims after failed enqueue: run=%v delivery=%v link=%v occurrence=%v", hasRun, hasDelivery, hasLink, hasOccurrence)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-fixed-1", "token", ""); w.Code != http.StatusNotFound {
		t.Fatalf("ghost run visible through the API: GET = %d, want 404", w.Code)
	}
	snap, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Runs) != 0 || len(snap.Jobs) != 0 || len(snap.DownstreamLinks) != 0 {
		t.Fatalf("failed enqueue left durable state: runs=%d jobs=%d links=%d", len(snap.Runs), len(snap.Jobs), len(snap.DownstreamLinks))
	}

	// Heal: the same submission creates exactly one run and its claims.
	s.persistFailForTest = nil
	run2, err := s.enqueueID(context.Background(), in, "run-fixed-1")
	if err != nil {
		t.Fatalf("healed enqueue: %v", err)
	}
	if run2.ID != "run-fixed-1" {
		t.Fatalf("healed enqueue run = %s, want run-fixed-1", run2.ID)
	}
	s.mu.Lock()
	runCount := len(s.runs)
	jobCount := len(s.jobs)
	_, deliveryClaimed := s.deliveries["del-1"]
	link := s.downstreamLinks["link-1"]
	s.mu.Unlock()
	if runCount != 1 || jobCount == 0 {
		t.Fatalf("healed enqueue runs=%d jobs=%d, want exactly 1 run and >0 jobs", runCount, jobCount)
	}
	if !deliveryClaimed {
		t.Fatal("healed enqueue did not claim the webhook delivery")
	}
	if link.ChildRunID != run2.ID || link.StableChildID != "stable-child-1" {
		t.Fatalf("healed enqueue link = %+v, want child %s", link, run2.ID)
	}

	// A forge retry of the same delivery returns the original run and creates
	// no duplicate.
	replay := in
	replay.ScheduleClaim = nil
	replay.DownstreamLaunch = nil
	run3, err := s.enqueueID(context.Background(), replay, "run-fixed-2")
	if err != nil {
		t.Fatalf("webhook replay: %v", err)
	}
	if run3.ID != run2.ID {
		t.Fatalf("webhook replay returned run %s, want original %s", run3.ID, run2.ID)
	}
	s.mu.Lock()
	runCount = len(s.runs)
	s.mu.Unlock()
	if runCount != 1 {
		t.Fatalf("webhook replay created a duplicate run: %d runs", runCount)
	}
}

// TestEnqueuePersistFailureRevivesSupersededRun is the supersession half of
// B3: a failing enqueue that already cancelled the concurrency-group
// incumbent must restore that run and all its jobs, so the incumbent is not
// terminally cancelled by an enqueue that never became durable.
func TestEnqueuePersistFailureRevivesSupersededRun(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	incumbent, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: concurrencyPipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	preRun := s.runs[incumbent.ID]
	preJobCount := 0
	for _, j := range s.jobs {
		if j.RunID == incumbent.ID {
			preJobCount++
		}
	}
	s.mu.Unlock()
	if preRun.Status != model.StatusQueued || preJobCount == 0 {
		t.Fatalf("incumbent fixture = %+v (%d jobs)", preRun, preJobCount)
	}

	submit := SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: concurrencyPipeline,
	}
	pre := captureStateForTest(t, s)
	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	if _, err := s.enqueueID(context.Background(), submit, "superseder-1"); err == nil {
		t.Fatal("superseding enqueue with a broken snapshot store returned nil error")
	}
	post := captureStateForTest(t, s)
	if !reflect.DeepEqual(pre, post) {
		t.Fatalf("failed superseding enqueue left the incumbent mutated: run=%+v jobs=%v", post.runs[incumbent.ID], post.jobs)
	}
	s.mu.Lock()
	revived := s.runs[incumbent.ID]
	revivedJobs := 0
	for _, j := range s.jobs {
		if j.RunID == incumbent.ID && !j.Status.Terminal() {
			revivedJobs++
		}
	}
	_, ghost := s.runs["superseder-1"]
	s.mu.Unlock()
	if revived.Status != model.StatusQueued || revivedJobs != preJobCount {
		t.Fatalf("incumbent not revived: run=%+v jobs=%d want %d", revived, revivedJobs, preJobCount)
	}
	if ghost {
		t.Fatal("failed superseding enqueue left the ghost run behind")
	}

	// Heal: the superseding enqueue lands and terminally cancels the
	// incumbent exactly as the durable path requires.
	s.persistFailForTest = nil
	superseder, err := s.enqueueID(context.Background(), submit, "superseder-1")
	if err != nil {
		t.Fatalf("healed superseding enqueue: %v", err)
	}
	s.mu.Lock()
	cancelledIncumbent := s.runs[incumbent.ID]
	totalRuns := len(s.runs)
	s.mu.Unlock()
	if superseder.ID != "superseder-1" || totalRuns != 2 {
		t.Fatalf("healed enqueue runs=%d superseder=%s", totalRuns, superseder.ID)
	}
	if cancelledIncumbent.Status != model.StatusCancelled {
		t.Fatalf("healed supersession incumbent = %+v, want cancelled", cancelledIncumbent)
	}
}

// TestRunnerDrainPersistFailureRollsBack is B4: a drain whose snapshot write
// fails restores the runner and answers 503.
func TestRunnerDrainPersistFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 1)
	pre := captureStateForTest(t, s)

	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/drain", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("drain with a broken snapshot store = %d, want 503: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "runner drain not durable\n" {
		t.Fatalf("refused drain body = %q", body)
	}
	post := captureStateForTest(t, s)
	if !reflect.DeepEqual(pre, post) {
		t.Fatalf("failed-persist drain changed runner state: pre=%+v post=%+v", pre.runners[runnerID], post.runners[runnerID])
	}
	if s.runners[runnerID].Draining {
		t.Fatal("failed-persist drain left Draining set")
	}

	s.persistFailForTest = nil
	if w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/drain", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("healed drain = %d, want 200: %s", w.Code, w.Body.String())
	}
	if !s.runners[runnerID].Draining {
		t.Fatal("healed drain did not set Draining")
	}
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	persisted := s2.runners[runnerID]
	s2.mu.Unlock()
	if !persisted.Draining {
		t.Fatal("drain was not durable across restart")
	}
}

// TestRunnerEnablePersistFailureRollsBack is B4: an enable whose snapshot
// write fails restores the disabled/draining flags and answers 503.
func TestRunnerEnablePersistFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 1)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("disable setup = %d: %s", w.Code, w.Body.String())
	}
	if !s.runners[runnerID].Disabled {
		t.Fatal("disable setup did not set Disabled")
	}
	pre := captureStateForTest(t, s)

	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/enable", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("enable with a broken snapshot store = %d, want 503: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "runner enable not durable\n" {
		t.Fatalf("refused enable body = %q", body)
	}
	post := captureStateForTest(t, s)
	if !reflect.DeepEqual(pre, post) {
		t.Fatalf("failed-persist enable changed runner state: pre=%+v post=%+v", pre.runners[runnerID], post.runners[runnerID])
	}
	if !s.runners[runnerID].Disabled {
		t.Fatal("failed-persist enable cleared Disabled")
	}

	s.persistFailForTest = nil
	if w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/enable", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("healed enable = %d, want 200: %s", w.Code, w.Body.String())
	}
	got := s.runners[runnerID]
	if got.Disabled || got.Draining {
		t.Fatalf("healed enable runner = %+v, want both flags cleared", got)
	}
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	persisted := s2.runners[runnerID]
	s2.mu.Unlock()
	if persisted.Disabled || persisted.Draining {
		t.Fatalf("enable was not durable across restart: %+v", persisted)
	}
}

// TestRunnerDisablePersistFailureRollsBack is B4: a kill switch whose
// snapshot write fails must not cancel in-memory leases it cannot make
// durable; every job/run/runner mutation is restored and the request answers
// 503.
func TestRunnerDisablePersistFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
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
	runnerID := registerRollbackRunner(t, s, 1)
	task := leaseNextRollbackTask(t, s, runnerID)
	pre := captureStateForTest(t, s)

	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("disable with a broken snapshot store = %d, want 503: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "runner disable not durable\n" {
		t.Fatalf("refused disable body = %q", body)
	}
	post := captureStateForTest(t, s)
	if !reflect.DeepEqual(pre, post) {
		t.Fatalf("failed-persist disable changed state: run=%+v job=%+v runner=%+v", post.runs[run.ID], post.jobs[task.Job.ID], post.runners[runnerID])
	}
	if got := s.jobs[task.Job.ID]; got.Status != model.StatusRunning || got.LeaseTokenHash == nil {
		t.Fatalf("failed-persist disable cancelled the lease: %+v", got)
	}
	if got := s.runners[runnerID]; got.Disabled || len(got.ActiveJobs) != 1 || got.ActiveJobs[0] != task.Job.ID {
		t.Fatalf("failed-persist disable mutated the runner: %+v", got)
	}

	s.persistFailForTest = nil
	if w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("healed disable = %d, want 200: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	gotRun := s.runs[run.ID]
	gotJob := s.jobs[task.Job.ID]
	gotRunner := s.runners[runnerID]
	s.mu.Unlock()
	if !gotRunner.Disabled || len(gotRunner.ActiveJobs) != 0 {
		t.Fatalf("healed disable runner = %+v", gotRunner)
	}
	if gotJob.Status != model.StatusCancelled || gotJob.LeaseTokenHash != nil {
		t.Fatalf("healed disable job = %+v", gotJob)
	}
	if gotRun.Status != model.StatusCancelled {
		t.Fatalf("healed disable run = %+v", gotRun)
	}

	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	diskRunner := s2.runners[runnerID]
	diskJob := s2.jobs[task.Job.ID]
	diskRun := s2.runs[run.ID]
	s2.mu.Unlock()
	if !diskRunner.Disabled || diskJob.Status != model.StatusCancelled || diskRun.Status != model.StatusCancelled {
		t.Fatalf("disable not durable across restart: runner=%+v job=%+v run=%+v", diskRunner, diskJob, diskRun)
	}
}

// TestApprovePersistFailureRollsBack is B4: an approval whose snapshot write
// fails restores the waiting job and answers 503; healing reapplies the
// approval durably and moves the wait metric exactly once.
func TestApprovePersistFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: approvalPipeline,
	}); err != nil {
		t.Fatal(err)
	}
	var jobID string
	s.mu.Lock()
	for id, j := range s.jobs {
		if j.ApprovalRequired {
			jobID = id
		}
	}
	preJob := s.jobs[jobID]
	pre := s.captureStateRollbackLocked()
	s.mu.Unlock()
	if jobID == "" || preJob.Status != model.StatusWaitingApproval || preJob.WaitingSince == nil {
		t.Fatalf("approval fixture job = %+v", preJob)
	}

	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/approve", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("approve with a broken snapshot store = %d, want 503: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "approval not durable\n" {
		t.Fatalf("refused approval body = %q", body)
	}
	post := captureStateForTest(t, s)
	if !reflect.DeepEqual(pre, post) {
		t.Fatalf("failed-persist approval changed state: job=%+v", post.jobs[jobID])
	}
	s.mu.Lock()
	rolledBack := s.jobs[jobID]
	s.mu.Unlock()
	if rolledBack.Status != model.StatusWaitingApproval || rolledBack.ApprovedBy != "" || rolledBack.WaitingSince == nil {
		t.Fatalf("failed-persist approval mutated the job: %+v", rolledBack)
	}

	s.persistFailForTest = nil
	if w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/approve", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("healed approve = %d, want 200: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	approved := s.jobs[jobID]
	s.mu.Unlock()
	if approved.Status != model.StatusQueued || approved.ApprovedBy == "" || approved.WaitingSince != nil {
		t.Fatalf("healed approval job = %+v", approved)
	}
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	persisted := s2.jobs[jobID]
	s2.mu.Unlock()
	if persisted.Status != model.StatusQueued || persisted.ApprovedBy == "" {
		t.Fatalf("approval not durable across restart: %+v", persisted)
	}
}

// TestMaintainLeaseRecoveryPersistFailureRollsBack is B5: the maintenance
// recovery pass must roll its requeue/timeout mutations back when the
// snapshot write fails, so the in-memory state matches the disk and the next
// tick re-runs the recovery instead of double-requeueing a pass that never
// became durable.
func TestMaintainLeaseRecoveryPersistFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
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
	runnerID := registerRollbackRunner(t, s, 1)
	task := leaseNextRollbackTask(t, s, runnerID)

	now := time.Now().UTC()
	past := now.Add(-time.Minute)
	s.mu.Lock()
	expired := s.jobs[task.Job.ID]
	expired.LeaseExpiresAt = &past
	s.jobs[task.Job.ID] = expired
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	pre := s.captureStateRollbackLocked()
	attempts := pre.jobs[task.Job.ID].Attempts
	s.mu.Unlock()

	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	s.maintainMemoryTick(context.Background(), now)
	if !s.stateDegraded.Load() {
		t.Fatal("failed recovery persist did not arm the degraded state")
	}
	post := captureStateForTest(t, s)
	if !reflect.DeepEqual(pre, post) {
		t.Fatalf("failed-persist recovery changed state: job=%+v runner=%+v run=%+v", post.jobs[task.Job.ID], post.runners[runnerID], post.runs[run.ID])
	}
	s.mu.Lock()
	stillRunning := s.jobs[task.Job.ID]
	stillActive := len(s.runners[runnerID].ActiveJobs)
	s.mu.Unlock()
	if stillRunning.Status != model.StatusRunning || stillRunning.LeaseTokenHash == nil {
		t.Fatalf("failed-persist recovery requeued the job: %+v", stillRunning)
	}
	if stillActive != 1 {
		t.Fatalf("failed-persist recovery released the runner slot: active=%d", stillActive)
	}

	// Heal: the next tick re-runs the recovery once and it becomes durable.
	s.persistFailForTest = nil
	s.maintainMemoryTick(context.Background(), now)
	s.mu.Lock()
	requeued := s.jobs[task.Job.ID]
	activeAfter := len(s.runners[runnerID].ActiveJobs)
	s.mu.Unlock()
	if requeued.Status != model.StatusQueued || requeued.LeaseRunnerID != "" || requeued.LeaseTokenHash != nil {
		t.Fatalf("healed recovery did not requeue the job: %+v", requeued)
	}
	if requeued.Attempts != attempts {
		t.Fatalf("recovery changed attempts: %d -> %d", attempts, requeued.Attempts)
	}
	if activeAfter != 0 {
		t.Fatalf("healed recovery left %d active job(s) on the runner", activeAfter)
	}
	snap, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if disk := snap.Jobs[task.Job.ID]; disk.Status != model.StatusQueued {
		t.Fatalf("durable snapshot job = %+v, want queued", disk)
	}

	// A further tick must not double-requeue the already-queued job.
	s.maintainMemoryTick(context.Background(), now.Add(time.Second))
	s.mu.Lock()
	after := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if after.Status != model.StatusQueued || after.Attempts != attempts {
		t.Fatalf("extra recovery tick re-processed the requeued job: %+v", after)
	}
}

// TestFSAdminAuditFailureBlocksMutation is B7 for the fs path: with the audit
// journal unwritable, an admin mutation is refused (503) before it changes
// any state; once the journal is writable the mutation applies and the audit
// row is durable.
func TestFSAdminAuditFailureBlocksMutation(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 1)
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: approvalPipeline,
	}); err != nil {
		t.Fatal(err)
	}
	var runID, approvalJobID string
	s.mu.Lock()
	for id := range s.runs {
		runID = id
	}
	for id, j := range s.jobs {
		if j.ApprovalRequired {
			approvalJobID = id
		}
	}
	s.mu.Unlock()
	if approvalJobID == "" {
		t.Fatal("approval fixture job not found")
	}
	runStatusBefore := s.runs[runID].Status

	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.Remove(auditPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.MkdirAll(auditPath, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(auditPath) })

	checkNoAudit := func(t *testing.T, path string) {
		t.Helper()
		w := doJSON(t, s, http.MethodPost, path, "token", "")
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s with an unwritable audit journal = %d, want 503: %s", path, w.Code, w.Body.String())
		}
		if body := w.Body.String(); body != "audit unavailable\n" {
			t.Fatalf("%s refusal body = %q, want %q", path, body, "audit unavailable\n")
		}
	}
	checkNoAudit(t, "/api/v1/runners/"+runnerID+"/drain")
	if s.runners[runnerID].Draining {
		t.Fatal("audit-blocked drain still mutated the runner")
	}
	checkNoAudit(t, "/api/v1/jobs/"+approvalJobID+"/approve")
	if got := s.jobs[approvalJobID]; got.ApprovedBy != "" || got.Status != model.StatusWaitingApproval {
		t.Fatalf("audit-blocked approve mutated the job: %+v", got)
	}
	checkNoAudit(t, "/api/v1/runs/"+runID+"/cancel")
	if got := s.runs[runID].Status; got != runStatusBefore {
		t.Fatalf("audit-blocked cancel mutated the run: %s -> %s", runStatusBefore, got)
	}

	// Healing the journal lets the mutation land; its audit row is readable.
	if err := os.RemoveAll(auditPath); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/drain", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("healed drain = %d, want 200: %s", w.Code, w.Body.String())
	}
	events, err := s.store.ReadAudit(100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "runner.drain" {
			found = true
		}
	}
	if !found {
		t.Fatal("durable drain left no audit row")
	}
}

// TestDBAuditFailureBlocksAdminMutations is B7 for the DB path: the fake
// store's audit-failure seam proves that an unwritable audit row refuses the
// approval/cancel/disable before their store mutation runs.
func TestDBAuditFailureBlocksAdminMutations(t *testing.T) {
	f := newDBFakeStore()
	s := New("admin")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.jobs["job-wait"] = model.Job{ID: "job-wait", RunID: "run-1", Key: "deploy", Status: model.StatusWaitingApproval, ApprovalRequired: true, Environment: "prod"}
	f.runs["run-1"] = model.Run{ID: "run-1", Status: model.StatusQueued, ConcurrencyGroup: "grp"}
	f.runners["runner-1"] = model.Runner{ID: "runner-1", Name: "r1", Capacity: 1}
	f.auditErr = errors.New("audit down")
	f.mu.Unlock()

	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-wait/approve", "admin", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("approve with unwritable audit = %d, want 503: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/run-1/cancel", "admin", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cancel with unwritable audit = %d, want 503: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-1/disable", "admin", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("disable with unwritable audit = %d, want 503: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	gotJob := f.jobs["job-wait"]
	gotRun := f.runs["run-1"]
	gotRunner := f.runners["runner-1"]
	f.mu.Unlock()
	if gotJob.Status != model.StatusWaitingApproval || gotJob.ApprovedBy != "" {
		t.Fatalf("audit-blocked approve mutated the job: %+v", gotJob)
	}
	if gotRun.Status != model.StatusQueued {
		t.Fatalf("audit-blocked cancel mutated the run: %+v", gotRun)
	}
	if gotRunner.Disabled {
		t.Fatalf("audit-blocked disable mutated the runner: %+v", gotRunner)
	}

	// Heal the audit path: each mutation now lands and writes its row.
	f.mu.Lock()
	f.auditErr = nil
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-wait/approve", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("healed approve = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/run-1/cancel", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("healed cancel = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-1/disable", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("healed disable = %d: %s", w.Code, w.Body.String())
	}
	audits, err := f.ReadAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range audits {
		seen[e.Action] = true
	}
	for _, action := range []string{"job.approved", "run.cancelled", "runner.disable"} {
		if !seen[action] {
			t.Fatalf("healed %s left no audit row (rows=%v)", action, seen)
		}
	}
}
