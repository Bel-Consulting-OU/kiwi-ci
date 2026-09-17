package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const requiredArtifactPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        paths:
          - out/
        required: true
    steps:
      - run: echo hi
`

const optionalArtifactPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        paths:
          - out/
    steps:
      - run: echo hi
`

const concurrencyPipeline = `version: 1
concurrency:
  group: grp
  cancel_in_progress: true
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo hi
`

// ---------------------------------------------------------------------------
// P0-8 atomic enqueue
// ---------------------------------------------------------------------------

func TestEnqueueDBDuplicateDeliveryReturnsOriginalRun(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	meta := `"metadata":{"github_delivery":"del-1"}`
	body := `{"repo_url":"https://github.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","pipeline":` + jsonString(smokePipeline) + `,` + meta + `}`
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("first submit = %d: %s", w.Code, w.Body.String())
	}
	var first model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	// The forge retry replays the same delivery: the original run must be
	// returned and NO second run may be enqueued.
	w = doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("replayed submit = %d: %s", w.Code, w.Body.String())
	}
	var second model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("duplicate delivery returned run %s, want original %s", second.ID, first.ID)
	}
	f.mu.Lock()
	runCount := len(f.insertRunCalls)
	f.mu.Unlock()
	if runCount != 1 {
		t.Fatalf("runs enqueued = %d, want exactly 1", runCount)
	}
}

func TestEnqueueDBSupersessionCancelsAtomically(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	body := `{"repo_url":"https://github.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","pipeline":` + jsonString(concurrencyPipeline) + `}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body); w.Code != http.StatusAccepted {
		t.Fatalf("first submit = %d: %s", w.Code, w.Body.String())
	}
	// A second run in the same concurrency group cancels the first run's
	// queued job inside the enqueue transaction.
	var second model.Run
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("second submit = %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var cancelled model.Job
	found := false
	for _, j := range f.jobs {
		if j.RunID != second.ID && j.Status == model.StatusCancelled {
			cancelled = j
			found = true
		}
	}
	if !found {
		t.Fatal("superseded job was not cancelled")
	}
	if cancelled.Error != "superseded by run "+second.ID {
		t.Fatalf("superseded error = %q", cancelled.Error)
	}
}

func TestEnqueueDBPartialFailureLeavesZeroRows(t *testing.T) {
	f := newDBFakeStore()
	f.enqueueFailOnce = true
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	body := `{"repo_url":"https://example.com/r","ref":"refs/heads/main","sha":"abc","pipeline":` + jsonString(smokePipeline) + `}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body); w.Code != http.StatusBadRequest {
		t.Fatalf("failing submit = %d, want 400: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.runs) != 0 || len(f.jobs) != 0 {
		t.Fatalf("failed enqueue leaked rows: %d runs, %d jobs", len(f.runs), len(f.jobs))
	}
}

func TestEnqueueDBQuotaExceededRefused(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.QuotaLimits.RepoQueueDepth = 1
	body := `{"repo_url":"https://example.com/r","ref":"refs/heads/main","sha":"abc","pipeline":` + jsonString(smokePipeline) + `}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body); w.Code != http.StatusAccepted {
		t.Fatalf("first submit = %d: %s", w.Code, w.Body.String())
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-quota submit = %d, want 429: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["reason"] != "REPO_QUOTA" {
		t.Fatalf("reason = %q", resp["reason"])
	}
}

// ---------------------------------------------------------------------------
// Quota race + budget fail-closed
// ---------------------------------------------------------------------------

func TestEnqueueDBBudgetUnavailableFailClosed(t *testing.T) {
	f := newDBFakeStore()
	f.usageErr = errors.New("usage store down")
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	body := `{"repo_url":"https://example.com/r","ref":"refs/heads/main","sha":"abc","pipeline":` + jsonString(smokePipeline) + `}`
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("budget-unavailable submit = %d, want 503: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Kiwi-Quota") != queueReasonBudgetStateUnavailable {
		t.Fatalf("X-Kiwi-Quota = %q", w.Header().Get("X-Kiwi-Quota"))
	}
	f.mu.Lock()
	runCount := len(f.runs)
	f.mu.Unlock()
	if runCount != 0 {
		t.Fatalf("budget-unavailable enqueue stored %d runs", runCount)
	}
	// QuotaFailOpen=true allows the enqueue through.
	s.QuotaFailOpen = true
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body); w.Code != http.StatusAccepted {
		t.Fatalf("fail-open submit = %d: %s", w.Code, w.Body.String())
	}
}

func TestNextDBBudgetUnavailableFailClosed(t *testing.T) {
	f := newDBFakeStore()
	f.usageErr = errors.New("usage store down")
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runners["runner1"] = model.Runner{ID: "runner1", Name: "r1", Capacity: 1}
	f.jobs["job1"] = model.Job{ID: "job1", RunID: "run1", Key: "build", Status: model.StatusQueued}
	f.runs["run1"] = model.Run{ID: "run1", Status: model.StatusQueued}
	f.mu.Unlock()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner1/next", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("budget-unavailable next = %d, want 503: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Kiwi-Quota") != queueReasonBudgetStateUnavailable {
		t.Fatalf("X-Kiwi-Quota = %q", w.Header().Get("X-Kiwi-Quota"))
	}
	// The waiting job is annotated with the reason.
	f.mu.Lock()
	reason := f.jobs["job1"].QueueReason
	f.mu.Unlock()
	if reason != queueReasonBudgetStateUnavailable {
		t.Fatalf("queue reason = %q", reason)
	}
	// QuotaFailOpen=true allows the lease.
	s.QuotaFailOpen = true
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner1/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("fail-open next = %d: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Required artifacts
// ---------------------------------------------------------------------------

func TestCompleteRequiresDeclaredArtifacts(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, requiredArtifactPipeline)
	// Success without the required artifact fails closed BEFORE the job
	// becomes terminal: the completion is refused (422) and the job stays
	// running — not terminal — so the runner can upload the artifact and
	// retry, mirroring the DB-mode semantics.
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	j := s.jobs[task.Job.ID]
	run := s.runs[j.RunID]
	s.mu.Unlock()
	if j.Status != model.StatusRunning {
		t.Fatalf("job status = %s, want running (completion refused)", j.Status)
	}
	if run.Status == model.StatusSuccess || run.Status == model.StatusFailure {
		t.Fatalf("run status = %s, want not terminal", run.Status)
	}
	// Upload the required artifact and retry: the completion succeeds.
	hdrs := leaseHeaders(task, runnerID)
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "payload", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("retried complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	j = s.jobs[task.Job.ID]
	run = s.runs[j.RunID]
	s.mu.Unlock()
	if j.Status != model.StatusSuccess {
		t.Fatalf("job status after retry = %s, want success", j.Status)
	}
	if run.Status != model.StatusSuccess {
		t.Fatalf("run status after retry = %s, want success", run.Status)
	}
}

func TestCompleteDBRequiresDeclaredArtifacts(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: requiredArtifactPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	// Success without the required artifact fails closed INSIDE the
	// completion transaction: the completion is refused (422) and the job
	// stays running — not terminal — so the runner can upload the artifact
	// and retry.
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	j := f.jobs[task.Job.ID]
	run := f.runs[j.RunID]
	f.mu.Unlock()
	if j.Status != model.StatusRunning {
		t.Fatalf("job status = %s, want running (completion rolled back)", j.Status)
	}
	if run.Status == model.StatusSuccess || run.Status == model.StatusFailure {
		t.Fatalf("run status = %s, want not terminal", run.Status)
	}
	// The refusal is audited.
	f.mu.Lock()
	audited := false
	for _, e := range f.audit {
		if e.Action == "job.required_artifact_missing" {
			audited = true
		}
	}
	f.mu.Unlock()
	if !audited {
		t.Fatal("missing-artifact completion was not audited")
	}
	// Upload the required artifact and retry: the completion succeeds.
	if err := f.InsertArtifact(context.Background(), model.ArtifactRecord{
		ID: strings.Repeat("a", 32), RunID: j.RunID, JobID: j.ID, Name: "bin",
		Size: 3, SHA256: "abc", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("retried complete = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	j = f.jobs[task.Job.ID]
	f.mu.Unlock()
	if j.Status != model.StatusSuccess {
		t.Fatalf("job status after retry = %s, want success", j.Status)
	}
}

func TestCompleteOptionalArtifactMissingStillSucceeds(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, optionalArtifactPipeline)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	j := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if j.Status != model.StatusSuccess {
		t.Fatalf("job status = %s, want success for a non-required missing artifact", j.Status)
	}
}

// ---------------------------------------------------------------------------
// Downstream reservation flow
// ---------------------------------------------------------------------------

func TestDownstreamConcurrentFlushOneChild(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: downstreamPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	item := downstreamPendingItem(t, s)
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	// Two concurrent flushers dispatch the SAME intent: exactly one wins
	// the reservation and launches one child.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.dispatchOutbox(context.Background(), item)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
	}
	f.mu.Lock()
	childCount := 0
	for _, r := range f.runs {
		if r.RepoFullName == "acme/child" {
			childCount++
		}
	}
	link, ok := f.downstreamLinks[task.Job.ID+"\x00acme/child\x00refs/heads/main"]
	f.mu.Unlock()
	if childCount != 1 {
		t.Fatalf("child runs = %d, want exactly 1", childCount)
	}
	if !ok || link.ChildRunID == "" {
		t.Fatalf("link = %+v, want launched", link)
	}
}

func TestDownstreamReservedLinkRecoveredByMaintain(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: downstreamPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	item := downstreamPendingItem(t, s)
	// Simulate a crash between reserve and enqueue: the link is reserved
	// two hours ago with no child.
	old := time.Now().UTC().Add(-2 * time.Hour)
	f.mu.Lock()
	key := task.Job.ID + "\x00acme/child\x00refs/heads/main"
	link, ok := f.downstreamLinks[key]
	if !ok {
		link = storage.DownstreamLink{ParentJobID: task.Job.ID, TargetRepo: "acme/child", TargetRef: "refs/heads/main", LaunchToken: "tok", CreatedAt: old}
	}
	link.Reserved = true
	link.ReservedAt = &old
	f.downstreamLinks[key] = link
	f.mu.Unlock()
	// The Maintain recovery pass expires the stale reservation...
	s.recoverDownstreamReservations(context.Background(), time.Now().UTC())
	f.mu.Lock()
	link = f.downstreamLinks[key]
	f.mu.Unlock()
	if link.Reserved {
		t.Fatal("stale reservation was not expired")
	}
	// ...so the replayed dispatch can reserve and launch the child.
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	if err := s.dispatchOutbox(context.Background(), item); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	f.mu.Lock()
	childCount := 0
	for _, r := range f.runs {
		if r.RepoFullName == "acme/child" {
			childCount++
		}
	}
	f.mu.Unlock()
	if childCount != 1 {
		t.Fatalf("child runs after recovery = %d, want 1", childCount)
	}
}

func TestDownstreamForgeIdentityPersisted(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.SetForgeBaseURL("forgejo", "https://forgejo.internal.example")
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	// The parent repository lives on a self-hosted Forgejo host.
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://forgejo.internal.example/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: downstreamPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	link, ok := f.downstreamLinks[task.Job.ID+"\x00acme/child\x00refs/heads/main"]
	f.mu.Unlock()
	if !ok {
		t.Fatal("link missing")
	}
	if link.TargetForge != "forgejo" || link.TargetBaseURL != "https://forgejo.internal.example" || link.TargetRepoID != "acme/child" {
		t.Fatalf("forge identity = %+v", link)
	}
	// The derived clone URL uses the persisted base URL, not a public host.
	if got := downstreamCloneURL(link.TargetForge, link.TargetBaseURL, link.TargetRepoID); got != "https://forgejo.internal.example/acme/child" {
		t.Fatalf("clone url = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Schedule occurrence atomicity
// ---------------------------------------------------------------------------

func TestScheduleFailingEnqueueRefiresNextTickDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// Anchored inside a minute: the +5s retry tick must not cross a minute
	// boundary and legitimately make the next nominal due.
	now := time.Now().UTC().Truncate(time.Minute).Add(30 * time.Second)
	sc := storage.Schedule{
		ID:         "sched1",
		Repository: "https://example.com/o/r.git",
		Spec:       scheduleSpec,
		Enabled:    true,
		CreatedAt:  now.Add(-1 * time.Minute),
	}
	if err := f.UpsertSchedule(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	if err := s.reloadSchedulesDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The first enqueue fails inside InsertCompiledRun: the occurrence
	// claim must roll back with it.
	f.enqueueFailOnce = true
	s.fireDueSchedules(context.Background(), now)
	f.mu.Lock()
	occ := len(f.occurrences["sched1"])
	runs := len(f.insertRunCalls)
	f.mu.Unlock()
	if occ != 0 || runs != 0 {
		t.Fatalf("failed firing left %d occurrences and %d runs", occ, runs)
	}
	// The next tick refires the SAME nominal successfully.
	s.fireDueSchedules(context.Background(), now.Add(5*time.Second))
	f.mu.Lock()
	occ = len(f.occurrences["sched1"])
	runs = len(f.insertRunCalls)
	f.mu.Unlock()
	if occ != 1 || runs != 1 {
		t.Fatalf("refire produced %d occurrences and %d runs, want 1/1", occ, runs)
	}
}

func TestScheduleFailingEnqueueRefiresNextTickMemory(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A clone-host policy that denies the schedule's repository makes the
	// enqueue fail after the occurrence would have been claimed.
	s.Policy = &policy.Config{AllowedCloneHosts: []string{"blocked.example"}}
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token",
		`{"repository":"https://example.com/o/r.git","spec":`+jsonString(scheduleSpec)+`}`)
	if w.Code != http.StatusOK {
		t.Fatalf("put schedule = %d: %s", w.Code, w.Body.String())
	}
	var sc storage.Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	// Anchor 30s into a minute so the +5s retry tick cannot cross a
	// minute boundary and legitimately make the NEXT nominal due (a
	// real-time flake seen on CI at HH:MM:58).
	now := time.Now().UTC().Truncate(time.Minute).Add(30 * time.Second)
	s.mu.Lock()
	sc.LastRun = timePtr(now.Add(-1 * time.Minute))
	s.schedules[sc.ID] = sc
	s.mu.Unlock()
	s.fireDueSchedules(context.Background(), now)
	s.mu.Lock()
	occ := len(s.occurrences[sc.ID])
	runCount := 0
	for _, r := range s.runs {
		if r.Event == "schedule" {
			runCount++
		}
	}
	s.mu.Unlock()
	if occ != 0 || runCount != 0 {
		t.Fatalf("failed firing left %d occurrences and %d runs", occ, runCount)
	}
	// Removing the denial lets the same nominal refire on the next tick
	// (the failed enqueue never advanced LastRun).
	s.Policy = &policy.Config{}
	s.fireDueSchedules(context.Background(), now.Add(5*time.Second))
	s.mu.Lock()
	runCount = 0
	for _, r := range s.runs {
		if r.Event == "schedule" {
			runCount++
		}
	}
	occ = len(s.occurrences[sc.ID])
	s.mu.Unlock()
	if runCount != 1 || occ != 1 {
		t.Fatalf("refire produced %d runs and %d occurrences, want 1/1", runCount, occ)
	}
}

// ---------------------------------------------------------------------------
// Dynamic generation
// ---------------------------------------------------------------------------

func TestDynamicDependencyIDsNeverEmpty(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	// A fragment whose dependency edges reference keys in an order the map
	// iteration cannot guarantee (child-b depends on child-a; child-c on
	// both) is the regression fixture for the empty-dependency-ID bug.
	frag := `{"jobs":{"child-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","needs":["child-a"],"steps":[{"run":"echo b"}]},"child-c":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","needs":["child-a","child-b"],"steps":[{"run":"echo c"}]},"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo a"}]}},"deps":{"child-b":["child-a"],"child-c":["child-a","child-b"]}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", fragmentBody(t, frag), leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("generated = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.ID == task.Job.ID {
			continue
		}
		for _, dep := range j.Needs {
			if dep == "" {
				t.Fatalf("job %s carries an empty dependency ID (needs=%v)", j.Key, j.Needs)
			}
		}
	}
}

func TestDynamicFragmentBeyondCapRejectedInTransaction(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {GenerateChildGraph: boolPtr(true)}}}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: generatePipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	// Fill the run to the max-jobs-per-run cap with dummy jobs.
	f.mu.Lock()
	for i := 0; i < maxJobsPerRun-1; i++ {
		id := fmt.Sprintf("dummy%040d", i)
		f.jobs[id] = model.Job{ID: id, RunID: task.Job.RunID, Status: model.StatusQueued}
	}
	f.mu.Unlock()
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", fragmentBody(t, frag), leaseHeaders(task, runnerID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("over-cap fragment = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "jobs") {
		t.Fatalf("rejection should mention the job cap: %s", w.Body.String())
	}
	// The transactional rejection left no fragment jobs behind.
	f.mu.Lock()
	stored := 0
	for id, j := range f.jobs {
		if j.DynamicDepth == 1 {
			stored++
			_ = id
		}
	}
	f.mu.Unlock()
	if stored != 0 {
		t.Fatalf("rejected fragment stored %d jobs", stored)
	}
}

// ---------------------------------------------------------------------------
// Shared CAS cache
// ---------------------------------------------------------------------------

func TestCacheCASRoundTripTwoReplicas(t *testing.T) {
	// Two server instances share one CAS filesystem and one DB store: an
	// entry PUT through replica A is served to replica B byte-identical
	// with a matching digest header.
	sharedCAS := cas.New(blob.NewFS(t.TempDir()))
	f := newDBFakeStore()
	s1, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s1.SetBlobStore(sharedCAS.Blobs)
	if err := s1.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s2.SetBlobStore(sharedCAS.Blobs)
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	raw := "cache-lease-token"
	exp := time.Now().UTC().Add(time.Hour)
	f.mu.Lock()
	f.runs["run-c"] = model.Run{ID: "run-c", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning}
	job := model.Job{ID: "job-a", RunID: "run-c", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a",
		Status: model.StatusRunning, Trusted: true, LeaseRunnerID: "runner-a", LeaseGeneration: 5, LeaseExpiresAt: &exp}
	job.LeaseTokenHash = hashLeaseToken(s1.leaseKey, raw)
	f.jobs["job-a"] = job
	f.runners["runner-a"] = model.Runner{ID: "runner-a", Name: "runner-a", Capacity: 1}
	f.mu.Unlock()
	hdrs := map[string]string{"X-Kiwi-Runner-ID": "runner-a", "X-Kiwi-Lease-Token": raw, "X-Kiwi-Lease-Generation": "5"}
	key := strings.Repeat("a", 64)
	payload := "shared-cache-payload"
	if w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "token", payload, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("cache put (A) = %d: %s", w.Code, w.Body.String())
	}
	// Replica B validates the lease with its OWN lease key: re-hash the
	// stored token the way the runner would when talking to B.
	f.mu.Lock()
	job = f.jobs["job-a"]
	job.LeaseTokenHash = hashLeaseToken(s2.leaseKey, raw)
	f.jobs["job-a"] = job
	f.mu.Unlock()
	// The replicas share the cluster cache-signing key (the production
	// wiring loads it from the cluster key store): pin B's signer to A's.
	s2.cacheSigner = s1.ensureCacheSigner()
	// Replica B resolves the manifest row and streams from the SAME cas.
	w := doJSONHeaders(t, s2, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "token", "", hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("cache get (B) = %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != payload {
		t.Fatalf("cache payload (B) = %q", w.Body.String())
	}
	digest := w.Header().Get("X-Kiwi-Cache-SHA256")
	if len(digest) != 64 {
		t.Fatalf("X-Kiwi-Cache-SHA256 = %q", digest)
	}
	sum := sha256Hex([]byte(payload))
	if digest != sum {
		t.Fatalf("digest header %q does not match content digest %q", digest, sum)
	}
	// The manifest envelope on B verifies against the shared signing key
	// and carries the producer provenance.
	repo, trust := cacheNamespace(job)
	f.mu.Lock()
	rec, ok := f.cacheMans[repo+"\x00"+trust+"\x00"+key]
	f.mu.Unlock()
	if !ok {
		t.Fatal("manifest row missing")
	}
	if _, err := cache.VerifyManifest(rec.Envelope, s2.ensureCacheSigner().Public); err != nil {
		t.Fatalf("verify manifest on B: %v", err)
	}
	if rec.ProducerJob != "job-a" || rec.ProducerRun != "run-c" {
		t.Fatalf("producer provenance = %s/%s", rec.ProducerRun, rec.ProducerJob)
	}
}

// ---------------------------------------------------------------------------
// HA sidecars
// ---------------------------------------------------------------------------

func TestSidecarDBModeCASRoundTrip(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	sbomPipeline := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        sbom: cyclonedx-json
    steps:
      - run: echo hi
`
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: sbomPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	hdrs := leaseHeaders(task, runnerID)
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin.sbom", "token", sbom, hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("sbom upload = %d: %s", w.Code, w.Body.String())
	}
	// The SBOM bytes live in CAS under their digest.
	sbomDigest := sha256Hex([]byte(sbom))
	if _, _, err := s.CAS.Open(context.Background(), sbomDigest); err != nil {
		t.Fatalf("sbom bytes not in cas: %v", err)
	}
	// The artifact upload passes the attestation gate from CAS and records
	// cas: digest references; no node-local sidecar files are used.
	w = doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "payload", hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec.SBOMPath, "cas:") || rec.SBOMSHA256 != sbomDigest {
		t.Fatalf("sbom references = %q/%q, want cas: digest", rec.SBOMPath, rec.SBOMSHA256)
	}
	if !strings.HasPrefix(rec.ProvenancePath, "cas:") || rec.ProvenanceSHA256 == "" {
		t.Fatalf("provenance references = %q/%q, want cas: digest", rec.ProvenancePath, rec.ProvenanceSHA256)
	}
	// The provenance endpoint resolves the envelope through CAS by digest.
	w = doJSON(t, s, http.MethodGet, "/api/v1/artifacts/"+rec.ID+"/provenance", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("provenance download = %d: %s", w.Code, w.Body.String())
	}
	if !json.Valid(w.Body.Bytes()) {
		t.Fatalf("provenance envelope is not JSON: %s", w.Body.String())
	}
	if w.Header().Get("X-Kiwi-Content-SHA256") != rec.ProvenanceSHA256 {
		t.Fatalf("provenance digest header = %q", w.Header().Get("X-Kiwi-Content-SHA256"))
	}
}

func TestSidecarFSModeLegacyFilesStillWork(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	hdrs := leaseHeaders(task, runnerID)
	up := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "payload", hdrs)
	if up.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", up.Code, up.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(up.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	// Legacy local sidecar files: provenance and artifact bytes resolve
	// from disk.
	if strings.HasPrefix(rec.ProvenancePath, "cas:") || rec.ProvenancePath == "" {
		t.Fatalf("fs-mode provenance path = %q, want a local file", rec.ProvenancePath)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/"+rec.ID+"/provenance", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("fs provenance download = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/"+rec.ID, "token", ""); w.Code != http.StatusOK || w.Body.String() != "payload" {
		t.Fatalf("fs artifact download = %d: %q", w.Code, w.Body.String())
	}
}

var _ = bytes.NewReader
var _ = forge.OutboxKindDownstream
