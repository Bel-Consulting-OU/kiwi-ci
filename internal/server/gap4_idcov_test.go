package server

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// idcovReceiptScriptStore scripts HasCompletionReceipt per call so the
// fast-path miss and the post-error hit can be exercised in one request.
type idcovReceiptScriptStore struct {
	*dbFakeStore
	mu          sync.Mutex
	calls       int
	fn          func(n int) (model.CompletionReceipt, bool, error)
	completeErr error
	muGet       sync.Mutex
	getCalls    int
	getFn       func(n int) (model.Job, error)
}

func (s *idcovReceiptScriptStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	s.muGet.Lock()
	s.getCalls++
	n := s.getCalls
	fn := s.getFn
	s.muGet.Unlock()
	if fn != nil {
		j, err := fn(n)
		if err != nil || j.ID != "" {
			return j, err
		}
	}
	return s.dbFakeStore.GetJob(ctx, id)
}

func (s *idcovReceiptScriptStore) CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt) error {
	if s.completeErr != nil {
		return s.completeErr
	}
	return s.dbFakeStore.CompleteJob(ctx, jobID, generation, runnerID, status, errMsg, outputs, receipt)
}

func (s *idcovReceiptScriptStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	s.mu.Lock()
	s.calls++
	n := s.calls
	fn := s.fn
	s.mu.Unlock()
	if fn != nil {
		return fn(n)
	}
	return s.dbFakeStore.HasCompletionReceipt(ctx, jobID, generation, runnerID)
}

// TestIDCovNextDBRunnerLookupErrors covers the runner-lookup branches of
// nextDB with the budget gate bypassed.
func TestIDCovNextDBRunnerLookupErrors(t *testing.T) {
	f := newDBFakeStore()
	fault := &idcovFaultStore{dbFakeStore: f}
	s := New("secret")
	if err := s.SwitchToDB(fault); err != nil {
		t.Fatal(err)
	}
	s.QuotaFailOpen = true
	f.setLeader(true)
	// Unknown runner: 404.
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/ghost/next", map[string]any{}, "secret", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown runner = %d, want 404: %s", w.Code, w.Body.String())
	}
	// Store failure: 500.
	fault.getRunnerErr = errors.New("runner read failed")
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/r1/next", map[string]any{}, "secret", nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("runner read failure = %d, want 500: %s", w.Code, w.Body.String())
	}
	// Budget state failure with fail-open: the runner lookup still runs.
	f.setLeader(false)
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/r1/next", map[string]any{}, "secret", nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("fail-open budget = %d, want 500 from the runner read", w.Code)
	}
}

// TestIDCovApproveDBForbidden covers the durable approval role gate.
func TestIDCovApproveDBForbidden(t *testing.T) {
	f := newDBFakeStore()
	f.mu.Lock()
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-a", Key: "deploy", Status: model.StatusWaitingApproval, ApprovalRequired: true}
	f.mu.Unlock()
	s := storeServer(t, "", map[string]auth.Principal{
		"read-token": {Subject: "reader", Roles: []auth.Role{auth.RoleRead}},
	})
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "read-token")
	if w := c.do(http.MethodPost, "/api/v1/jobs/job-a/approve", map[string]any{}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("db approve without the role = %d, want 403", w.Code)
	}
}

// TestIDCovMetricsMemoryState covers the in-memory state gauge rendering
// with runs, jobs, queue reasons and runners.
func TestIDCovMetricsMemoryState(t *testing.T) {
	s := New("admin")
	s.mu.Lock()
	s.runs["run-1"] = model.Run{ID: "run-1", Status: model.StatusRunning}
	s.runs["run-2"] = model.Run{ID: "run-2", Status: model.StatusSuccess}
	s.jobs["job-1"] = model.Job{ID: "job-1", Status: model.StatusQueued, QueueReason: "no matching runner"}
	s.runners["r1"] = model.Runner{ID: "r1", Capacity: 0, ActiveJobs: []string{"job-1"}}
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodGet, "/metrics", "admin", "")
	if w.Code != http.StatusOK {
		t.Fatalf("metrics = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`kiwi_runs{status="running"} 1`,
		"kiwi_jobs_queue_reason",
		"kiwi_runner_slots 1",
		"kiwi_runner_slots_busy 1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics body missing %q:\n%s", want, body)
		}
	}
}

// TestIDCovCompleteEnqueueEffectFailures covers the outbox and downstream
// intent failures after a memory-mode completion.
func TestIDCovCompleteEnqueueEffectFailures(t *testing.T) {
	t.Run("outbox append failure", func(t *testing.T) {
		s, err := NewPersistent("token", "token", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.enqueue(SubmitRun{
			RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
			Ref: "refs/heads/main", SHA: "abc", Event: "push",
			Pipeline: "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n",
			Trusted:  true,
		}); err != nil {
			t.Fatal(err)
		}
		runnerID, task := leaseRunJob(t, s)
		bad := newDBFakeStore()
		bad.outboxAppendErr = errors.New("outbox append failed")
		s.outbox.AttachDB(bad)
		w := completeTask(t, s, task, runnerID, "success")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("complete with a broken outbox = %d, want 500: %s", w.Code, w.Body.String())
		}
	})

	t.Run("downstream intent failure", func(t *testing.T) {
		s, err := NewPersistent("token", "token", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
		if _, err := s.enqueue(SubmitRun{
			RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
			Ref: "refs/heads/main", SHA: "abc", Event: "push",
			Pipeline: downstreamPipeline, Trusted: true,
		}); err != nil {
			t.Fatal(err)
		}
		runnerID, task := leaseRunJob(t, s)
		// The effect enqueue succeeds (fs outbox); the downstream link
		// insert fails through the injected store, which still serves the
		// leased job so the shared lease gate passes.
		base := newDBFakeStore()
		exp := task.LeaseExpiresAt
		base.mu.Lock()
		base.jobs[task.Job.ID] = model.Job{ID: task.Job.ID, RunID: task.Job.RunID, Key: task.Job.Key, RepoID: task.Job.RepoID, RepoFullName: task.Job.RepoFullName, Status: model.StatusRunning, LeaseRunnerID: runnerID, LeaseTokenHash: hashLeaseToken(s.leaseKey, task.LeaseToken), LeaseGeneration: task.LeaseGeneration, LeaseExpiresAt: &exp}
		base.runs[task.Job.RunID] = model.Run{ID: task.Job.RunID, RepoID: task.Job.RepoID, RepoFullName: task.Job.RepoFullName, Status: model.StatusRunning}
		base.mu.Unlock()
		s.DB = &idcovDownstreamErrStore{dbFakeStore: base}
		w := completeTask(t, s, task, runnerID, "success")
		if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "downstream") {
			t.Fatalf("complete with a failing downstream insert = %d: %s", w.Code, w.Body.String())
		}
	})
}

// idcovDownstreamErrStore fails downstream link inserts.
type idcovDownstreamErrStore struct {
	*dbFakeStore
}

func (idcovDownstreamErrStore) InsertDownstreamLink(context.Context, storage.DownstreamLink) error {
	return errors.New("downstream link insert failed")
}

// TestIDCovCompleteMemoryReceiptReconcileFailure covers the replayed
// completion whose reconciliation fails.
func TestIDCovCompleteMemoryReceiptReconcileFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	idcovSeedMemoryJob(t, s, "job-rc", "run-rc", "runner-a", "good-token", nil)
	// A stale lease (the request token does not hash to the stored digest)
	// with a matching receipt reaches the replay branch.
	s.mu.Lock()
	stored := s.jobs["job-rc"]
	stored.LeaseTokenHash = hashLeaseToken(s.leaseKey, "other-token")
	s.jobs["job-rc"] = stored
	hash := completionResultHash(model.StatusFailure, "", nil)
	s.completions[completionReceiptKey("job-rc", 1, "runner-a")] = model.CompletionReceipt{JobID: "job-rc", Generation: 1, RunnerID: "runner-a", ResultHash: hash}
	s.mu.Unlock()
	// Break the store so the reconciliation's run aggregate fails.
	blocker := filepath.Join(dir, "blocker")
	writeTestFile(t, blocker, []byte("x"))
	s.store.Root = blocker
	body := `{"runner_id":"runner-a","lease_token":"good-token","lease_generation":1,"status":"failure"}`
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-rc/complete", []byte(body), "token", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("reconcile failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// TestIDCovCompleteDBStaleReconcileFailure covers the reconcile failure in
// the receipt replay that follows a stale lease.
func TestIDCovCompleteDBStaleReconcileFailure(t *testing.T) {
	f := newDBFakeStore()
	hash := completionResultHash(model.StatusFailure, "", nil)
	store := &idcovReceiptScriptStore{dbFakeStore: f}
	// The fast-path receipt check misses; the post-stale check hits.
	store.fn = func(n int) (model.CompletionReceipt, bool, error) {
		if n == 1 {
			return model.CompletionReceipt{}, false, nil
		}
		return model.CompletionReceipt{JobID: "job-sr", Generation: 1, RunnerID: "runner-a", ResultHash: hash}, true, nil
	}
	// The reconciliation's job read fails.
	store.getFn = func(n int) (model.Job, error) {
		if n >= 2 {
			return model.Job{}, errors.New("reconcile read failed")
		}
		return model.Job{}, nil
	}
	s := New("secret")
	if err := s.SwitchToDB(store); err != nil {
		t.Fatal(err)
	}
	const token = "stale-token"
	// Seed a running job whose stored hash does not match the request token.
	idcovSeedDBRunningJob(t, s, f, "job-sr", "run-sr", token)
	f.mu.Lock()
	j := f.jobs["job-sr"]
	j.LeaseTokenHash = hashLeaseToken(s.leaseKey, "different")
	f.jobs["job-sr"] = j
	f.mu.Unlock()
	body := `{"runner_id":"runner-a","lease_token":"` + token + `","lease_generation":1,"status":"failure"}`
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-sr/complete", []byte(body), "secret", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("stale replay reconcile failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// TestIDCovCompleteDBReceiptAfterError covers the replay recognition that
// happens only after the completion transaction reports an error.
func TestIDCovCompleteDBReceiptAfterError(t *testing.T) {
	f := newDBFakeStore()
	hash := completionResultHash(model.StatusFailure, "", nil)
	store := &idcovReceiptScriptStore{dbFakeStore: f}
	store.fn = func(n int) (model.CompletionReceipt, bool, error) {
		if n == 1 {
			return model.CompletionReceipt{}, false, nil // fast path misses
		}
		return model.CompletionReceipt{JobID: "job-r", Generation: 1, RunnerID: "runner-a", ResultHash: hash}, true, nil
	}
	store.completeErr = errors.New("completion raced")
	s := New("secret")
	if err := s.SwitchToDB(store); err != nil {
		t.Fatal(err)
	}
	idcovSeedDBRunningJob(t, s, f, "job-r", "run-r", "tok")
	body := `{"runner_id":"runner-a","lease_token":"tok","lease_generation":1,"status":"failure"}`
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-r/complete", []byte(body), "secret", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("post-error replay = %d, want 204: %s", w.Code, w.Body.String())
	}
}
