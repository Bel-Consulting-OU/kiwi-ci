package server

// fs_durability_retention_test.go pins the P1 fs-mode over-rollback fix: a
// post-rename directory-fsync failure (fsutil.Renamed) means the atomic write
// ALREADY published the new bytes, so a snapshot mutation must NOT roll its
// in-memory state back — that would leave memory denying the visible file and
// let a later successful persist erase the published state. Every mutation
// that rides the fs snapshot (or its own atomic file) is driven through a
// real directory-fsync fault and must assert:
//
//	(a) the request/return is a durability failure (503 where an HTTP
//	    handler exists) with the fixed opaque body and no success payload;
//	(b) the published state is RETAINED in memory and equals the visible
//	    file (memory == disk);
//	(c) readiness is degraded (noteFilePersistResult armed the directory);
//	(d) a restart over the same data dir sees the published state;
//	(e) a later successful persist does not revert it.
//
// The four auditor reproductions (completion, cancelRun, enqueue, lease
// recovery) are the first four tests. Pre-rename rollback remains covered by
// fs_failure_matrix_test.go / fs_rollback_mutations_test.go and must be
// unchanged.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

// fsRetentionAssertStateJSONContains fails unless state.json carries want.
func fsRetentionAssertStateJSONContains(t *testing.T, dir, want string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if !bytes.Contains(b, []byte(want)) {
		t.Fatalf("state.json does not contain %q:\n%s", want, b)
	}
}

// fsRetentionAssertDegraded fails unless the mutation armed degraded readiness
// through noteFilePersistResult / noteSnapshotPersistResult.
func fsRetentionAssertDegraded(t *testing.T, s *Server) {
	t.Helper()
	if !s.stateDegraded.Load() {
		t.Fatal("published-uncertain write did not leave readiness degraded")
	}
	w := doJSON(t, s, http.MethodGet, "/readiness", "", "")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("X-Kiwi-State") != "degraded" {
		t.Fatalf("readiness after a published-uncertain write = %d/%q, want 503/degraded",
			w.Code, w.Header().Get("X-Kiwi-State"))
	}
}

// TestAuditorCompletionDirSyncFailureRetainsState is auditor reproduction 1:
// completion persist -> rollbackCompletionLocked. Under a dir-sync fault the
// terminal job, usage marker and receipt are published; memory must retain
// them, the restart must see success, and a later persist must not revert to
// running.
func TestAuditorCompletionDirSyncFailureRetainsState(t *testing.T) {
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
	runnerID, task := registerUsageRunner(t, s)

	restore := failDirSync(t)
	w := completeTask(t, s, task, runnerID, "success")
	restore()

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("completion under a dir-sync fault = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "state not durable\n" {
		t.Fatalf("published completion refusal body = %q, want %q", got, "state not durable\n")
	}

	// (b) memory retains the published terminal state and receipt.
	s.mu.Lock()
	job := s.jobs[task.Job.ID]
	receipts := len(s.completions)
	s.mu.Unlock()
	if job.Status != model.StatusSuccess || !job.UsageRecorded {
		t.Fatalf("published completion was rolled back: %+v", job)
	}
	if receipts != 1 {
		t.Fatalf("published completion receipts = %d, want 1", receipts)
	}
	fsRetentionAssertStateJSONContains(t, dir, `"status": "success"`)

	// (c) readiness is degraded until a same-directory persist succeeds.
	fsRetentionAssertDegraded(t, s)

	// (d) a restart sees the published completion.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	restarted := s2.jobs[task.Job.ID]
	restartedReceipts := len(s2.completions)
	s2.mu.Unlock()
	if restarted.Status != model.StatusSuccess || !restarted.UsageRecorded {
		t.Fatalf("restart did not see the published completion: %+v", restarted)
	}
	if restartedReceipts != 1 {
		t.Fatalf("restart completion receipts = %d, want 1", restartedReceipts)
	}

	// (e) a later successful persist does not revert the published state.
	if err := s.persistLocked(); err != nil {
		t.Fatalf("reconcile persist: %v", err)
	}
	if s.stateDegraded.Load() {
		t.Fatal("successful reconcile did not clear the degraded marker")
	}
	fsRetentionAssertStateJSONContains(t, dir, `"status": "success"`)
}

// TestAuditorCancelDirSyncFailureRetainsState is auditor reproduction 2:
// cancelRun persist -> rollbackStateLocked. Under a dir-sync fault the run is
// published as cancelled; memory must stay cancelled, the restart must see
// cancelled, and a later persist must not un-cancel it.
func TestAuditorCancelDirSyncFailureRetainsState(t *testing.T) {
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
	leaseRunJob(t, s)

	restore := failDirSync(t)
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", "")
	restore()

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cancel under a dir-sync fault = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "state not durable\n" {
		t.Fatalf("published cancel refusal body = %q, want %q", got, "state not durable\n")
	}

	s.mu.Lock()
	got := s.runs[run.ID]
	s.mu.Unlock()
	if got.Status != model.StatusCancelled || got.FinishedAt == nil {
		t.Fatalf("published cancel was rolled back: %+v", got)
	}
	fsRetentionAssertStateJSONContains(t, dir, `"status": "cancelled"`)
	fsRetentionAssertDegraded(t, s)

	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	restarted := s2.runs[run.ID]
	s2.mu.Unlock()
	if restarted.Status != model.StatusCancelled {
		t.Fatalf("restart did not see the published cancellation: %+v", restarted)
	}

	if err := s.persistLocked(); err != nil {
		t.Fatalf("reconcile persist: %v", err)
	}
	fsRetentionAssertStateJSONContains(t, dir, `"status": "cancelled"`)
}

// TestAuditorEnqueueDirSyncFailureRetainsState is auditor reproduction 3:
// enqueue persist -> rollbackStateLocked. Under a dir-sync fault the run is
// published; memory must hold exactly that run (no ghost-on-restart) and a
// later persist must not erase it.
func TestAuditorEnqueueDirSyncFailureRetainsState(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	submit := `{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","event":"push","pipeline":` + jsonString(smokePipeline) + `}`

	restore := failDirSync(t)
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", submit)
	restore()

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("enqueue under a dir-sync fault = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "state not durable\n" {
		t.Fatalf("published enqueue refusal body = %q, want %q", got, "state not durable\n")
	}
	if bytes.Contains(w.Body.Bytes(), []byte(`"id"`)) {
		t.Fatalf("published enqueue leaked a run body: %q", w.Body.String())
	}

	s.mu.Lock()
	if len(s.runs) != 1 || len(s.jobs) != 1 {
		runs, jobs := len(s.runs), len(s.jobs)
		s.mu.Unlock()
		t.Fatalf("published enqueue rolled back: runs=%d jobs=%d, want 1/1", runs, jobs)
	}
	var runID string
	for id := range s.runs {
		runID = id
	}
	s.mu.Unlock()
	fsRetentionAssertStateJSONContains(t, dir, runID)
	fsRetentionAssertDegraded(t, s)

	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	restartedRuns := len(s2.runs)
	_, present := s2.runs[runID]
	s2.mu.Unlock()
	if !present || restartedRuns != 1 {
		t.Fatalf("restart did not see exactly the published run: present=%v runs=%d", present, restartedRuns)
	}

	if err := s.persistLocked(); err != nil {
		t.Fatalf("reconcile persist: %v", err)
	}
	fsRetentionAssertStateJSONContains(t, dir, runID)
}

// TestAuditorLeaseRecoveryDirSyncFailureRetainsState is auditor reproduction
// 4: maintainMemoryTick persist -> rollbackStateLocked. Under a dir-sync fault
// the expired lease recovery is published (job requeued); memory must stay
// requeued, the restart must see queued, and a later persist must not revert
// the recovery.
func TestAuditorLeaseRecoveryDirSyncFailureRetainsState(t *testing.T) {
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
	now := time.Now().UTC()
	past := now.Add(-time.Minute)
	s.mu.Lock()
	expired := s.jobs[task.Job.ID]
	expired.LeaseExpiresAt = &past
	s.jobs[task.Job.ID] = expired
	err = s.persistLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	restore := failDirSync(t)
	s.maintainMemoryTick(context.Background(), now)
	restore()

	s.mu.Lock()
	job := s.jobs[task.Job.ID]
	active := len(s.runners[runnerID].ActiveJobs)
	s.mu.Unlock()
	if job.Status != model.StatusQueued || job.LeaseTokenHash != nil || job.LeaseRunnerID != "" {
		t.Fatalf("published recovery was rolled back: %+v", job)
	}
	if active != 0 {
		t.Fatalf("published recovery left %d active job(s) on the runner", active)
	}
	fsRetentionAssertStateJSONContains(t, dir, `"status": "queued"`)
	fsRetentionAssertDegraded(t, s)

	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	restarted := s2.jobs[task.Job.ID]
	s2.mu.Unlock()
	if restarted.Status != model.StatusQueued || restarted.LeaseRunnerID != "" {
		t.Fatalf("restart did not see the published recovery: %+v", restarted)
	}

	if err := s.persistLocked(); err != nil {
		t.Fatalf("reconcile persist: %v", err)
	}
	fsRetentionAssertStateJSONContains(t, dir, `"status": "queued"`)
}

// TestHeartbeatDirSyncFailureRetainsExtendedLease pins the heartbeat path: a
// dir-sync fault leaves the extended deadline published, so memory must keep
// it (not re-issue the old expired lease), the disk must match, and a retry
// after reconcile must still operate on the durable deadline.
func TestHeartbeatDirSyncFailureRetainsExtendedLease(t *testing.T) {
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
	runnerID, task := leaseRunJob(t, s)
	s.mu.Lock()
	oldExp := *s.jobs[task.Job.ID].LeaseExpiresAt
	oldSeen := s.runners[runnerID].LastSeen
	s.mu.Unlock()

	restore := failDirSync(t)
	w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token",
		string(leaseBodyFor(t, runnerID, task.LeaseToken, task.LeaseGeneration, nil)))
	restore()

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("heartbeat under a dir-sync fault = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "state not durable\n" {
		t.Fatalf("published heartbeat refusal body = %q, want %q", got, "state not durable\n")
	}

	s.mu.Lock()
	memExp := *s.jobs[task.Job.ID].LeaseExpiresAt
	memSeen := s.runners[runnerID].LastSeen
	s.mu.Unlock()
	if !memExp.After(oldExp) {
		t.Fatalf("published heartbeat rolled the deadline back: %v (old %v)", memExp, oldExp)
	}
	if !memSeen.After(oldSeen) {
		t.Fatalf("published heartbeat rolled LastSeen back: %v (old %v)", memSeen, oldSeen)
	}
	fsRetentionAssertDegraded(t, s)

	snap, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	disk := snap.Jobs[task.Job.ID].LeaseExpiresAt
	if disk == nil || !disk.Equal(memExp) {
		t.Fatalf("memory deadline %v != published disk deadline %v", memExp, disk)
	}

	// A reconciled retry still extends from the published deadline.
	if err := s.persistLocked(); err != nil {
		t.Fatalf("reconcile persist: %v", err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token",
		string(leaseBodyFor(t, runnerID, task.LeaseToken, task.LeaseGeneration, nil))); w.Code != http.StatusOK {
		t.Fatalf("retried heartbeat = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// TestCheckRunMirrorDirSyncFailureRetainsMapping pins the check-run mirror
// writer: a dir-sync fault leaves the new mapping visible, so memory must keep
// it (a rollback would let the retry POST a duplicate check), readiness is
// degraded for the data directory, and the restart reads the mapping.
func TestCheckRunMirrorDirSyncFailureRetainsMapping(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	const key = "run-1|build"
	const id = "check-1"

	restore := failDirSync(t)
	err = s.putCheckRunID(context.Background(), key, id)
	restore()

	if err == nil || !fsutil.Renamed(err) {
		t.Fatalf("check-run mirror dir-sync fault = %v, want a Renamed error", err)
	}
	s.mu.Lock()
	got := s.checkRuns.m[key]
	s.mu.Unlock()
	if got != id {
		t.Fatalf("published check-run mapping rolled back: %q, want %q", got, id)
	}
	b, rerr := os.ReadFile(filepath.Join(dir, "check-runs.json"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !bytes.Contains(b, []byte(id)) {
		t.Fatalf("check-runs.json does not carry the published mapping: %s", b)
	}
	fsRetentionAssertDegraded(t, s)

	restarted, lerr := loadCheckRunIDs(dir)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if restarted[key] != id {
		t.Fatalf("restart check-run mapping = %q, want %q", restarted[key], id)
	}

	// A later successful publish of the same mapping must not remove it.
	if err := s.putCheckRunID(context.Background(), key, id); err != nil {
		t.Fatalf("reconcile putCheckRunID: %v", err)
	}
	restarted, lerr = loadCheckRunIDs(dir)
	if lerr != nil || restarted[key] != id {
		t.Fatalf("later persist reverted the mapping: %q, %v", restarted[key], lerr)
	}
}

// TestDeploymentFinishDirSyncFailureRetainsMarker pins the deployment-finish
// effect: a dir-sync fault leaves the finished marker published, so memory
// must retain it (disk==memory), readiness is degraded, the restart sees it,
// and a later persist does not un-finish it.
func TestDeploymentFinishDirSyncFailureRetainsMarker(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	fin := time.Now().UTC().Add(-time.Minute)
	j := model.Job{ID: "job-dep", RunID: "run-dep", Environment: "staging", Status: model.StatusSuccess, FinishedAt: &fin}
	s.mu.Lock()
	s.deployments[j.ID] = model.Deployment{ID: "dep-1", JobID: j.ID, RunID: j.RunID, Environment: "staging", Status: model.StatusRunning}
	s.mu.Unlock()
	if err := s.persistLocked(); err != nil {
		t.Fatal(err)
	}

	restore := failDirSync(t)
	err = s.effectDeploymentFinish(context.Background(), j)
	restore()
	if err == nil || !fsutil.Renamed(err) {
		t.Fatalf("deployment-finish dir-sync fault = %v, want a Renamed error", err)
	}

	s.mu.Lock()
	mem := s.deployments[j.ID]
	s.mu.Unlock()
	if mem.FinishedAt == nil || mem.Status != model.StatusSuccess {
		t.Fatalf("published deployment-finish marker rolled back: %+v", mem)
	}
	fsRetentionAssertStateJSONContains(t, dir, `"finished_at"`)
	fsRetentionAssertDegraded(t, s)

	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	restarted := s2.deployments[j.ID]
	s2.mu.Unlock()
	if restarted.FinishedAt == nil {
		t.Fatalf("restart did not see the published deployment-finish marker: %+v", restarted)
	}

	if err := s.persistLocked(); err != nil {
		t.Fatalf("reconcile persist: %v", err)
	}
	fsRetentionAssertStateJSONContains(t, dir, `"finished_at"`)
}

// TestScheduleUpsertDirSyncFailureRetainsSchedule pins the schedules journal:
// a dir-sync fault leaves the new schedule published, so memory must retain it
// (not roll it back to "not created"), the handler answers 503, the restart
// sees it, and a later journal write does not erase it.
func TestScheduleUpsertDirSyncFailureRetainsSchedule(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"repository":"https://example.com/o/r.git","spec":` + jsonString(scheduleSpec) + `}`

	restore := failDirSync(t)
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body)
	restore()

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("schedule create under a dir-sync fault = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "state not durable\n" {
		t.Fatalf("published schedule refusal body = %q, want %q", got, "state not durable\n")
	}
	s.mu.Lock()
	if len(s.schedules) != 1 {
		n := len(s.schedules)
		s.mu.Unlock()
		t.Fatalf("published schedule create rolled back: %d schedules", n)
	}
	var scID string
	for id := range s.schedules {
		scID = id
	}
	s.mu.Unlock()
	b, rerr := os.ReadFile(filepath.Join(dir, schedulesFile))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !bytes.Contains(b, []byte(scID)) {
		t.Fatalf("schedules.json does not carry the published schedule: %s", b)
	}
	fsRetentionAssertDegraded(t, s)

	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	_, present := s2.schedules[scID]
	s2.mu.Unlock()
	if !present {
		t.Fatal("restart did not see the published schedule")
	}

	if err := s.persistSchedulesLocked(); err != nil {
		t.Fatalf("reconcile persistSchedulesLocked: %v", err)
	}
	s2, err = NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	_, present = s2.schedules[scID]
	s2.mu.Unlock()
	if !present {
		t.Fatal("later journal write reverted the published schedule")
	}
}

// TestSecretReceiptDirSyncFailureRetainsReceipt pins the secret receipt
// writer: a dir-sync fault leaves the receipt published, so memory must retain
// it (never a replay window the disk denies), the handler answers 503 without
// an envelope, readiness is degraded, and a later persist keeps it.
func TestSecretReceiptDirSyncFailureRetainsReceipt(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
	_, pubB64 := ephemeralKey(t)

	restore := failDirSync(t)
	w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	restore()

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("secret issue under a dir-sync fault = %d, want 503: %s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("ciphertext")) {
		t.Fatalf("published receipt failure leaked an envelope: %s", w.Body.String())
	}
	key := secretReceiptKey(jobID, gen, "tok")
	s.mu.Lock()
	retained := s.secretReceipts[key]
	s.mu.Unlock()
	if !retained {
		t.Fatal("published secret receipt was rolled back in memory")
	}
	b, rerr := os.ReadFile(filepath.Join(dir, secretReceiptsFile))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !bytes.Contains(b, []byte(key)) {
		t.Fatalf("secrets-receipts.json does not carry the published receipt: %s", b)
	}
	fsRetentionAssertDegraded(t, s)

	if err := s.persistSecretReceiptsLocked(); err != nil {
		t.Fatalf("reconcile persistSecretReceiptsLocked: %v", err)
	}
	s2 := New("secret")
	if err := s2.loadSecretReceipts(dir); err != nil {
		t.Fatal(err)
	}
	if !s2.secretReceipts[key] {
		t.Fatal("restart/later persist lost the published secret receipt")
	}
}

// TestProfileUpsertDirSyncFailureRetainsProfile pins the runner-profile
// upsert: a dir-sync fault leaves the profile published, so the handler
// answers 503 (not 500), memory retains it, readiness is degraded, the
// restart sees it, and a later persist does not erase it.
func TestProfileUpsertDirSyncFailureRetainsProfile(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	const profileID = "p-dir-sync"
	body := `{"id":"` + profileID + `","labels":["container"],"max_capacity":1}`

	restore := failDirSync(t)
	w := doJSON(t, s, http.MethodPost, "/api/v1/runner-profiles", "admin-tok", body)
	restore()

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("profile upsert under a dir-sync fault = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "state not durable\n" {
		t.Fatalf("published profile refusal body = %q, want %q", got, "state not durable\n")
	}
	s.mu.Lock()
	_, retained := s.profiles[profileID]
	s.mu.Unlock()
	if !retained {
		t.Fatal("published profile was rolled back in memory")
	}
	fsRetentionAssertStateJSONContains(t, dir, profileID)
	fsRetentionAssertDegraded(t, s)

	s2, err := NewPersistent("token", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	_, present := s2.profiles[profileID]
	s2.mu.Unlock()
	if !present {
		t.Fatal("restart did not see the published profile")
	}

	if err := s.persistLocked(); err != nil {
		t.Fatalf("reconcile persist: %v", err)
	}
	fsRetentionAssertStateJSONContains(t, dir, profileID)
}

// TestPreRenameCompletionPersistStillRollsBack guards the complementary half
// of the contract: a plain (non-atomic / pre-rename) persist failure must keep
// the historical wholesale rollback, so the phase-aware change can never turn
// a definitely-not-published failure into retained state.
func TestPreRenameCompletionPersistStillRollsBack(t *testing.T) {
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
	runnerID, task := registerUsageRunner(t, s)

	s.persistFailForTest = errors.New("synthetic pre-rename snapshot write failure")
	w := completeTask(t, s, task, runnerID, "success")
	s.persistFailForTest = nil
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("pre-rename completion = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "completion state not durable\n" {
		t.Fatalf("pre-rename completion body = %q, want %q", got, "completion state not durable\n")
	}
	s.mu.Lock()
	job := s.jobs[task.Job.ID]
	receipts := len(s.completions)
	s.mu.Unlock()
	if job.Status != model.StatusRunning || job.UsageRecorded || receipts != 0 {
		t.Fatalf("pre-rename failure was not rolled back: job=%+v receipts=%d", job, receipts)
	}
}
