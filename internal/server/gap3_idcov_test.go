package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// idcovScriptedStore lets tests script the Nth GetJob call and override the
// scheduler-facing calls, which is how the second-lookup branches of the
// heartbeat/completion paths become deterministic.
type idcovScriptedStore struct {
	*dbFakeStore
	mu           sync.Mutex
	getCalls     int
	getFn        func(n int) (model.Job, error)
	completeErr  error
	heartbeatErr error
}

func (f *idcovScriptedStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	f.mu.Lock()
	f.getCalls++
	n := f.getCalls
	fn := f.getFn
	f.mu.Unlock()
	if fn != nil {
		j, err := fn(n)
		if err != nil || j.ID != "" {
			return j, err
		}
	}
	return f.dbFakeStore.GetJob(ctx, id)
}

func (f *idcovScriptedStore) CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt) error {
	if f.completeErr != nil {
		return f.completeErr
	}
	return f.dbFakeStore.CompleteJob(ctx, jobID, generation, runnerID, status, errMsg, outputs, receipt)
}

func (f *idcovScriptedStore) HeartbeatLease(ctx context.Context, jobID string, runnerID string, generation int64, expiresAt time.Time) error {
	if f.heartbeatErr != nil {
		return f.heartbeatErr
	}
	return f.dbFakeStore.HeartbeatLease(ctx, jobID, runnerID, generation, expiresAt)
}

// idcovSeedDBRunningJob inserts a running leased job and its run.
func idcovSeedDBRunningJob(t *testing.T, s *Server, f *dbFakeStore, jobID, runID, token string) {
	t.Helper()
	exp := time.Now().UTC().Add(time.Minute)
	f.mu.Lock()
	f.runs[runID] = model.Run{ID: runID, RepoID: "github.com/kiwi/repo", RepoFullName: "kiwi/repo", Repo: "https://github.com/kiwi/repo.git", Ref: "refs/heads/main", Status: model.StatusRunning}
	f.jobs[jobID] = model.Job{
		ID: jobID, RunID: runID, Key: "build",
		RepoID: "github.com/kiwi/repo", RepoURL: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo",
		Status: model.StatusRunning, LeaseRunnerID: "runner-a", LeaseTokenHash: hashLeaseToken(s.leaseKey, token),
		LeaseGeneration: 1, LeaseExpiresAt: &exp,
	}
	f.mu.Unlock()
}

// TestIDCovMetricsHandlerAndDBRendering covers the dedicated metrics handler
// and every DB-mode rendering branch.
func TestIDCovMetricsHandlerAndDBRendering(t *testing.T) {
	s := New("t")
	w := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "kiwi_runs") {
		t.Fatalf("MetricsHandler = %d: %s", w.Code, w.Body.String())
	}

	f := newDBFakeStore()
	f.mu.Lock()
	f.runs["run-open"] = model.Run{ID: "run-open", Status: model.StatusRunning}
	f.runs["run-done"] = model.Run{ID: "run-done", Status: model.StatusSuccess}
	f.jobs["job-1"] = model.Job{ID: "job-1", RunID: "run-open", Status: model.StatusRunning}
	f.runners["r1"] = model.Runner{ID: "r1", Capacity: 0, ActiveJobs: []string{"job-1"}}
	f.mu.Unlock()
	sd := New("admin")
	if err := sd.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, sd, http.MethodGet, "/metrics", "admin", "")
	if w.Code != http.StatusOK {
		t.Fatalf("db metrics = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `kiwi_runs{status="running"} 1`) || !strings.Contains(body, "kiwi_runner_saturation") {
		t.Fatalf("db metrics body incomplete: %s", body)
	}
	// The DB state gauges read the store aggregates: a failing aggregate is
	// logged and skips ONLY its family (the healthy families and the process
	// registry keep rendering) — never a wrong zero.
	fault := &idcovFaultStore{dbFakeStore: f}
	f.metricJobStatusErr = errors.New("jobs down")
	f.metricRunnerSlotsErr = errors.New("runners down")
	sd.DB = fault
	w = doJSON(t, sd, http.MethodGet, "/metrics", "admin", "")
	body = w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `kiwi_runs{status="running"} 1`) {
		t.Fatalf("degraded db metrics = %d: %s", w.Code, body)
	}
	if strings.Contains(body, "# HELP kiwi_jobs Number") || strings.Contains(body, `kiwi_jobs{status=`) || strings.Contains(body, "kiwi_runners ") {
		t.Fatalf("failed db metric families rendered: %s", body)
	}
	// A failing run aggregate skips the runs family too; the runner family
	// (healthy again) still renders its real values, not zeros.
	f.metricJobStatusErr = nil
	f.metricRunnerSlotsErr = nil
	f.metricRunStatusErr = errors.New("runs down")
	w = doJSON(t, sd, http.MethodGet, "/metrics", "admin", "")
	body = w.Body.String()
	if w.Code != http.StatusOK || strings.Contains(body, "# HELP kiwi_runs Number") || strings.Contains(body, `kiwi_runs{status=`) {
		t.Fatalf("failed run family rendered = %d: %s", w.Code, body)
	}
	if !strings.Contains(body, "kiwi_runners 1") || !strings.Contains(body, `kiwi_jobs{status="running"} 1`) {
		t.Fatalf("healthy db families missing after a run aggregate failure: %s", body)
	}
}

// TestIDCovPureHelpers covers the remaining small helpers.
func TestIDCovPureHelpers(t *testing.T) {
	if !environmentBranchAllowed("refs/heads/main", []string{"", " main ", "release/*"}) {
		t.Fatal("exact branch pattern not honored")
	}
	if !environmentBranchAllowed("refs/heads/release/1", []string{"release/*"}) {
		t.Fatal("glob branch pattern not honored")
	}
	if !environmentBranchAllowed("refs/tags/v1", []string{"refs/tags/v1"}) {
		t.Fatal("full ref pattern not honored")
	}
	if environmentBranchAllowed("refs/heads/main", []string{"dev", "release/*"}) {
		t.Fatal("unmatched branch allowed")
	}

	jobs := map[string]model.Job{
		"a": {ID: "a", Environment: "prod", EnvironmentConcurrency: 1, Status: model.StatusRunning},
		"b": {ID: "b", Environment: "prod", Status: model.StatusRunning},
	}
	if !environmentAtCapacityScoped(model.Job{ID: "b", Environment: "prod", EnvironmentConcurrency: 1}, jobs) {
		t.Fatal("at-capacity environment not detected")
	}
	if environmentAtCapacityScoped(model.Job{ID: "b", Environment: "", EnvironmentConcurrency: 1}, jobs) {
		t.Fatal("empty environment reported at capacity")
	}
	if environmentAtCapacityScoped(model.Job{ID: "b", Environment: "prod", EnvironmentConcurrency: 0}, jobs) {
		t.Fatal("unlimited environment reported at capacity")
	}

	if satAddF(1, maxFloat) < maxFloat {
		t.Fatal("saturating add did not clamp")
	}
	if satAddF(1, 2) != 3 {
		t.Fatal("saturating add wrong")
	}
	if got := appendUnique([]string{"a", "b"}, "b"); len(got) != 2 {
		t.Fatalf("appendUnique duplicated: %v", got)
	}
	if got := appendUnique([]string{"a"}, "b"); len(got) != 2 || got[1] != "b" {
		t.Fatalf("appendUnique = %v", got)
	}
	if got := removeString([]string{"a", "b", "a"}, "a"); len(got) != 1 || got[0] != "b" {
		t.Fatalf("removeString = %v", got)
	}
	if cloneStrings(nil) != nil || cloneStrings([]string{"x"})[0] != "x" {
		t.Fatal("cloneStrings wrong")
	}
	if (&Server{}).leaseDuration() != defaultLeaseDuration {
		t.Fatal("default lease duration wrong")
	}
	if got := (&Server{LeaseDuration: time.Minute}).leaseDuration(); got != time.Minute {
		t.Fatalf("configured lease duration = %v", got)
	}
}

const maxFloat = 1.79769313486231570814527423731704356798070e+308

// TestIDCovMaintainMemoryTick runs one real housekeeping tick (the ticker is
// fixed at five seconds) and then cancels the loop.
func TestIDCovMaintainMemoryTick(t *testing.T) {
	s := New("t")
	s.mu.Lock()
	s.runs["run-m"] = model.Run{ID: "run-m", Status: model.StatusQueued}
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Maintain(ctx)
		close(done)
	}()
	time.Sleep(5600 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Maintain did not stop after cancellation")
	}
}

// TestIDCovMaintainDBRecoveryErrors covers the post-promotion and leader-tick
// recovery failures.
func TestIDCovMaintainDBRecoveryErrors(t *testing.T) {
	f := newDBFakeStore()
	fault := &idcovFaultStore{dbFakeStore: f}
	s := New("t")
	if err := s.SwitchToDB(fault); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// Promotion with a failing recovery logs and keeps leadership.
	f.setLeader(true)
	fault.listRunsErr = errors.New("recovery down")
	s.mu.Lock()
	s.leader = false
	s.mu.Unlock()
	s.maintainDB(context.Background(), now)
	s.mu.Lock()
	leader := s.leader
	s.mu.Unlock()
	if !leader {
		t.Fatal("promotion failed")
	}
	// The leader tick tolerates the recovery failure too.
	s.maintainDB(context.Background(), now)
	fault.listRunsErr = nil
	s.maintainDB(context.Background(), now)
}

// TestIDCovHeartbeatDBScriptedBranches covers the second-lookup and
// scheduler-error branches of heartbeatDB.
func TestIDCovHeartbeatDBScriptedBranches(t *testing.T) {
	type tc struct {
		name     string
		script   func(n int, base model.Job) (model.Job, error)
		hbErr    error
		wantCode int
		wantBody string
	}
	cases := []tc{
		{
			name:     "second lookup missing",
			script:   func(n int, base model.Job) (model.Job, error) { return model.Job{}, storage.ErrNotFound },
			wantCode: http.StatusNotFound,
		},
		{
			name:     "second lookup fails",
			script:   func(n int, base model.Job) (model.Job, error) { return model.Job{}, errors.New("read failed") },
			wantCode: http.StatusInternalServerError,
		},
		{
			name: "second lookup cancelled",
			script: func(n int, base model.Job) (model.Job, error) {
				base.Status = model.StatusCancelled
				return base, nil
			},
			wantCode: http.StatusOK,
			wantBody: `"cancel":true`,
		},
		{
			name: "second lookup stale generation",
			script: func(n int, base model.Job) (model.Job, error) {
				base.LeaseGeneration++
				return base, nil
			},
			wantCode: http.StatusConflict,
		},
		{
			name:     "scheduler conflict",
			hbErr:    storage.ErrLeaseConflict,
			wantCode: http.StatusConflict,
		},
		{
			name:     "scheduler failure",
			hbErr:    errors.New("heartbeat down"),
			wantCode: http.StatusInternalServerError,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDBFakeStore()
			store := &idcovScriptedStore{dbFakeStore: f, heartbeatErr: c.hbErr}
			s := New("secret")
			if err := s.SwitchToDB(store); err != nil {
				t.Fatal(err)
			}
			const token = "hb-token"
			idcovSeedDBRunningJob(t, s, f, "job-hb", "run-hb", token)
			if c.script != nil {
				f.mu.Lock()
				base := f.jobs["job-hb"]
				f.mu.Unlock()
				store.getFn = func(n int) (model.Job, error) {
					if n == 1 {
						return base, nil
					}
					return c.script(n, base)
				}
			}
			w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-hb/heartbeat",
				Heartbeat{RunnerID: "runner-a", LeaseToken: token, LeaseGeneration: 1}, "secret", nil)
			if w.Code != c.wantCode {
				t.Fatalf("status = %d, want %d: %s", w.Code, c.wantCode, w.Body.String())
			}
			if c.wantBody != "" && !strings.Contains(w.Body.String(), c.wantBody) {
				t.Fatalf("body = %s, want %q", w.Body.String(), c.wantBody)
			}
		})
	}
}

// TestIDCovCompleteDBBranches covers the durable completion branches: the
// identity gate, receipt read failures, idempotent replays, invalid
// status/output normalization and the post-transaction reconciliation.
func TestIDCovCompleteDBBranches(t *testing.T) {
	const token = "complete-token"
	statusBody := `{"runner_id":"runner-a","lease_token":"` + token + `","lease_generation":1,"status":"bogus"}`

	t.Run("receipt read failure", func(t *testing.T) {
		f := newDBFakeStore()
		fault := &idcovFaultStore{dbFakeStore: f, hasReceiptErr: errors.New("receipt read failed")}
		s := New("secret")
		if err := s.SwitchToDB(fault); err != nil {
			t.Fatal(err)
		}
		idcovSeedDBRunningJob(t, s, f, "job-c", "run-c", token)
		w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-c/complete", []byte(statusBody), "secret", nil)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
		}
	})

	t.Run("invalid status normalizes to failure", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("secret")
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		idcovSeedDBRunningJob(t, s, f, "job-c", "run-c", token)
		w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-c/complete", []byte(statusBody), "secret", nil)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204: %s", w.Code, w.Body.String())
		}
		f.mu.Lock()
		got := f.jobs["job-c"]
		f.mu.Unlock()
		if got.Status != model.StatusFailure {
			t.Fatalf("stored status = %q, want failure", got.Status)
		}
	})

	t.Run("invalid outputs normalize to failure", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("secret")
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		idcovSeedDBRunningJob(t, s, f, "job-o", "run-o", token)
		body := `{"runner_id":"runner-a","lease_token":"` + token + `","lease_generation":1,"status":"success","outputs":{"k":"` + strings.Repeat("v", (64<<10)+1) + `"}}`
		w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-o/complete", []byte(body), "secret", nil)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204: %s", w.Code, w.Body.String())
		}
		f.mu.Lock()
		got := f.jobs["job-o"]
		f.mu.Unlock()
		if got.Status != model.StatusFailure || got.Error != "runner returned invalid or oversized job outputs" {
			t.Fatalf("invalid outputs result = %q / %q", got.Status, got.Error)
		}
	})

	t.Run("missing job is 404", func(t *testing.T) {
		f := newDBFakeStore()
		store := &idcovScriptedStore{dbFakeStore: f, completeErr: storage.ErrNotFound}
		s := New("secret")
		if err := s.SwitchToDB(store); err != nil {
			t.Fatal(err)
		}
		idcovSeedDBRunningJob(t, s, f, "job-404", "run-404", token)
		w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-404/complete", []byte(statusBody), "secret", nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
		}
	})

	t.Run("stale completion is a conflict", func(t *testing.T) {
		f := newDBFakeStore()
		store := &idcovScriptedStore{dbFakeStore: f, completeErr: errors.New("generation mismatch")}
		s := New("secret")
		if err := s.SwitchToDB(store); err != nil {
			t.Fatal(err)
		}
		idcovSeedDBRunningJob(t, s, f, "job-s", "run-s", token)
		w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-s/complete", []byte(statusBody), "secret", nil)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
		}
	})

	t.Run("failed completion with a matching receipt replays", func(t *testing.T) {
		f := newDBFakeStore()
		store := &idcovScriptedStore{dbFakeStore: f, completeErr: errors.New("completion raced")}
		s := New("secret")
		if err := s.SwitchToDB(store); err != nil {
			t.Fatal(err)
		}
		idcovSeedDBRunningJob(t, s, f, "job-r", "run-r", token)
		hash := completionResultHash(model.StatusFailure, "", nil)
		f.mu.Lock()
		f.receipts[completionReceiptKey("job-r", 1, "runner-a")] = model.CompletionReceipt{JobID: "job-r", Generation: 1, RunnerID: "runner-a", ResultHash: hash}
		f.mu.Unlock()
		body := `{"runner_id":"runner-a","lease_token":"` + token + `","lease_generation":1,"status":"failure"}`
		w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-r/complete", []byte(body), "secret", nil)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204: %s", w.Code, w.Body.String())
		}
	})

	t.Run("stale lease with a matching receipt replays", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("secret")
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		// The stored job carries a different token hash, so the lease gate
		// reports it stale; the durable receipt still acks the replay.
		exp := time.Now().Add(time.Minute)
		f.mu.Lock()
		f.runs["run-rep"] = model.Run{ID: "run-rep", RepoID: "github.com/kiwi/repo", RepoFullName: "kiwi/repo", Status: model.StatusRunning}
		f.jobs["job-rep"] = model.Job{ID: "job-rep", RunID: "run-rep", Key: "build", RepoID: "github.com/kiwi/repo", Status: model.StatusRunning, LeaseRunnerID: "runner-a", LeaseTokenHash: hashLeaseToken(s.leaseKey, "other"), LeaseGeneration: 1, LeaseExpiresAt: &exp}
		hash := completionResultHash(model.StatusFailure, "", nil)
		f.receipts[completionReceiptKey("job-rep", 1, "runner-a")] = model.CompletionReceipt{JobID: "job-rep", Generation: 1, RunnerID: "runner-a", ResultHash: hash}
		f.mu.Unlock()
		body := `{"runner_id":"runner-a","lease_token":"` + token + `","lease_generation":1,"status":"failure"}`
		w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-rep/complete", []byte(body), "secret", nil)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204: %s", w.Code, w.Body.String())
		}
	})

	t.Run("reconcile failure fails the completion", func(t *testing.T) {
		f := newDBFakeStore()
		store := &idcovScriptedStore{dbFakeStore: f}
		s := New("secret")
		if err := s.SwitchToDB(store); err != nil {
			t.Fatal(err)
		}
		idcovSeedDBRunningJob(t, s, f, "job-rc", "run-rc", token)
		store.getFn = func(n int) (model.Job, error) {
			if n >= 2 {
				return model.Job{}, errors.New("reconcile read failed")
			}
			return model.Job{}, nil
		}
		w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-rc/complete", []byte(statusBody), "secret", nil)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
		}
		_ = store
	})
}

// TestIDCovCompleteDBIdentityGate covers the transport-identity refusal that
// runs before the receipt fast path.
func TestIDCovCompleteDBIdentityGate(t *testing.T) {
	ca, err := runnerpki.NewCA("gap3 ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	s := New("")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.RunnerCA = ca
	if err := s.ProvisionRunnerTokensDB(context.Background(), map[string]string{"runner-a": auth.TokenDigest("tok-a")}); err != nil {
		t.Fatal(err)
	}
	_, certB := pkiSignRunner(t, ca, "runner-b")
	body := `{"runner_id":"runner-b","lease_token":"t","lease_generation":1,"status":"failure"}`
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-x/complete", []byte(body), "tok-a", certB)
	if w.Code != http.StatusForbidden {
		t.Fatalf("identity mismatch = %d, want 403: %s", w.Code, w.Body.String())
	}
}
