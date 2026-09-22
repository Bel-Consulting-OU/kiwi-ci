package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/quotas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// idcovFaultStore injects failures into the store methods the runner
// lifecycle endpoints use while delegating everything else to the fake.
type idcovFaultStore struct {
	*dbFakeStore
	getRunErr     error
	listRunsErr   error
	listJobsErr   error
	readLogsErr   error
	appendLogErr  error
	getJobErr     error
	getRunnerErr  error
	upsertRunErr  error
	updateJobErr  error
	listRunnerErr error
	hasReceiptErr error
	revokeErr     error
	listAuditErr  error
	// disableAtomicErr makes the atomic disable transaction fail (the S6-B
	// fail-closed injection point; the old upsert/revoke split no longer
	// carries the authority for admins).
	disableAtomicErr error
}

func (f *idcovFaultStore) DisableRunnerAndRevokeCert(ctx context.Context, runnerID, certSerial, actor string) (int, error) {
	if f.disableAtomicErr != nil {
		return 0, f.disableAtomicErr
	}
	return f.dbFakeStore.DisableRunnerAndRevokeCert(ctx, runnerID, certSerial, actor)
}

func (f *idcovFaultStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	if f.getRunErr != nil {
		return model.Run{}, f.getRunErr
	}
	return f.dbFakeStore.GetRun(ctx, id)
}

func (f *idcovFaultStore) ListRuns(ctx context.Context, limit int) ([]model.Run, error) {
	if f.listRunsErr != nil {
		return nil, f.listRunsErr
	}
	return f.dbFakeStore.ListRuns(ctx, limit)
}

// ListRunsPageForAuthorizedRepos carries the injected run-read failure into
// the authorized paged path the collection handler actually uses.
func (f *idcovFaultStore) ListRunsPageForAuthorizedRepos(ctx context.Context, allowedRepoIDs []string, afterCreatedAt time.Time, afterID string, limit int) (storage.RunPage, error) {
	if f.listRunsErr != nil {
		return storage.RunPage{}, f.listRunsErr
	}
	return f.dbFakeStore.ListRunsPageForAuthorizedRepos(ctx, allowedRepoIDs, afterCreatedAt, afterID, limit)
}

// ListRunsPage keeps the injected failure on the legacy unfiltered capability
// too, so any direct use of it in a test stays fail-closed while the handler
// itself must never take this path.
func (f *idcovFaultStore) ListRunsPage(ctx context.Context, afterCreatedAt time.Time, afterID string, limit int) (storage.RunPage, error) {
	if f.listRunsErr != nil {
		return storage.RunPage{}, f.listRunsErr
	}
	return f.dbFakeStore.ListRunsPage(ctx, afterCreatedAt, afterID, limit)
}

func (f *idcovFaultStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	if f.listJobsErr != nil {
		return nil, f.listJobsErr
	}
	return f.dbFakeStore.ListJobsByRun(ctx, runID)
}

func (f *idcovFaultStore) ReadLogs(ctx context.Context, runID string, after int64, limit int) ([]model.LogEntry, error) {
	if f.readLogsErr != nil {
		return nil, f.readLogsErr
	}
	return f.dbFakeStore.ReadLogs(ctx, runID, after, limit)
}

func (f *idcovFaultStore) AppendLog(ctx context.Context, e model.LogEntry) error {
	if f.appendLogErr != nil {
		return f.appendLogErr
	}
	return f.dbFakeStore.AppendLog(ctx, e)
}

func (f *idcovFaultStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	if f.getJobErr != nil {
		return model.Job{}, f.getJobErr
	}
	return f.dbFakeStore.GetJob(ctx, id)
}

func (f *idcovFaultStore) GetRunner(ctx context.Context, id string) (model.Runner, error) {
	if f.getRunnerErr != nil {
		return model.Runner{}, f.getRunnerErr
	}
	return f.dbFakeStore.GetRunner(ctx, id)
}

func (f *idcovFaultStore) UpsertRunner(ctx context.Context, ri model.Runner) error {
	if f.upsertRunErr != nil {
		return f.upsertRunErr
	}
	return f.dbFakeStore.UpsertRunner(ctx, ri)
}

func (f *idcovFaultStore) UpdateJob(ctx context.Context, j model.Job) error {
	if f.updateJobErr != nil {
		return f.updateJobErr
	}
	return f.dbFakeStore.UpdateJob(ctx, j)
}

func (f *idcovFaultStore) ReadAudit(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	if f.listAuditErr != nil {
		return nil, f.listAuditErr
	}
	return f.dbFakeStore.ReadAudit(ctx, limit)
}

// RevokeRunnerLeases injects a transactional kill-switch failure: the
// scheduler consumes storage.RecoveryStore directly and never falls back to
// ListJobsByRunner.
func (f *idcovFaultStore) RevokeRunnerLeases(ctx context.Context, runnerID, reason string) ([]string, error) {
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	return f.dbFakeStore.RevokeRunnerLeases(ctx, runnerID, reason)
}

func (f *idcovFaultStore) ListRunners(ctx context.Context) ([]model.Runner, error) {
	if f.listRunnerErr != nil {
		return nil, f.listRunnerErr
	}
	return f.dbFakeStore.ListRunners(ctx)
}

func (f *idcovFaultStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	if f.hasReceiptErr != nil {
		return model.CompletionReceipt{}, false, f.hasReceiptErr
	}
	return f.dbFakeStore.HasCompletionReceipt(ctx, jobID, generation, runnerID)
}

// idcovSeedMemoryJob inserts a run and a running job holding a valid lease
// directly into the in-memory maps.
func idcovSeedMemoryJob(t *testing.T, s *Server, jobID, runID, runnerID, token string, mutate func(*model.Job)) {
	t.Helper()
	exp := time.Now().UTC().Add(time.Minute)
	j := model.Job{
		ID: jobID, RunID: runID, Key: "build",
		RepoURL: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo",
		Status: model.StatusRunning, Trusted: true,
		LeaseRunnerID: runnerID, LeaseTokenHash: hashLeaseToken(s.leaseKey, token),
		LeaseGeneration: 1, LeaseExpiresAt: &exp,
	}
	if mutate != nil {
		mutate(&j)
	}
	s.mu.Lock()
	s.runs[runID] = model.Run{ID: runID, Repo: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo", RepoID: "github.com/kiwi/repo", Ref: "refs/heads/main", Status: model.StatusRunning, CreatedAt: time.Now().UTC()}
	s.jobs[jobID] = j
	s.mu.Unlock()
}

// idcovSeedQueuedJob inserts a queued job for leasing tests.
func idcovSeedQueuedJob(t *testing.T, s *Server, jobID, runID string, mutate func(*model.Job)) {
	t.Helper()
	j := model.Job{
		ID: jobID, RunID: runID, Key: "build",
		RepoURL: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo",
		Status: model.StatusQueued, CreatedAt: time.Now().UTC(),
	}
	if mutate != nil {
		mutate(&j)
	}
	s.mu.Lock()
	s.runs[runID] = model.Run{ID: runID, Repo: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo", RepoID: "github.com/kiwi/repo", Status: model.StatusQueued}
	s.jobs[jobID] = j
	s.mu.Unlock()
}

// TestIDCovAuthLegacyOpenMode covers the "nothing configured" fallthrough
// for both RBAC and admin tiers.
func TestIDCovAuthLegacyOpenMode(t *testing.T) {
	s := New("")
	if s.AdminToken != "" || !s.AuthStore.Empty() {
		t.Fatal("fixture is not in open mode")
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs", "", ""); w.Code != http.StatusOK {
		t.Fatalf("open-mode RBAC route = %d, want 200", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/metrics", "", ""); w.Code != http.StatusOK {
		t.Fatalf("open-mode admin route = %d, want 200", w.Code)
	}
	// With an admin token configured the same routes require it.
	s2 := New("admin")
	if w := doJSON(t, s2, http.MethodGet, "/metrics", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("admin route without token = %d, want 401", w.Code)
	}
}

// TestIDCovLoggerNilFallbacks covers the standard-logger fallbacks.
func TestIDCovLoggerNilFallbacks(t *testing.T) {
	s := New("t")
	s.Logger = nil
	s.logf("idcov %d", 1)
	s.logInfo("idcov info", "k", "v")
	s.logError("idcov error", "k", "v")
}

// TestIDCovRunnerTierMTLSOnlyWithoutBearer covers the mTLS-only runner gate:
// per-runner tokens are configured but the request authenticates with a
// certificate alone.
func TestIDCovRunnerTierMTLSOnlyWithoutBearer(t *testing.T) {
	ca, err := runnerpki.NewCA("idcov ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("shared")
	s.RunnerCA = ca
	s.RequireRunnerClientCerts = true
	s.LoadRunnerTokens(map[string]string{"other": auth.TokenDigest("other-token")})
	_, cert := pkiSignRunner(t, ca, "runner-mtls")
	body := map[string]any{"name": "rm", "capacity": 1, "protocol_min": 3, "protocol_max": 3}
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register", body, "", cert); w.Code != http.StatusOK {
		t.Fatalf("certificate-only register = %d: %s", w.Code, w.Body.String())
	}
}

// TestIDCovGetLogsEndpoints covers every storage mode of GET /runs/{id}/logs.
func TestIDCovGetLogsEndpoints(t *testing.T) {
	// Memory server without a store: an empty log list.
	s := New("admin")
	s.mu.Lock()
	s.runs["run-1"] = model.Run{ID: "run-1", Status: model.StatusRunning}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-1/logs", "admin", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "[]") {
		t.Fatalf("memory logs = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/ghost/logs", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown run logs = %d, want 404", w.Code)
	}

	// Persistent memory server: the log store is consulted.
	dir := t.TempDir()
	sp, err := NewPersistent("admin", "admin", dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.store.AppendLog(model.LogEntry{Seq: 1, RunID: "run-2", JobID: "job-2", Line: "hello", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	sp.mu.Lock()
	sp.runs["run-2"] = model.Run{ID: "run-2", Status: model.StatusRunning}
	sp.mu.Unlock()
	w := doJSON(t, sp, http.MethodGet, "/api/v1/runs/run-2/logs?after=0&limit=10", "admin", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "hello") {
		t.Fatalf("store logs = %d: %s", w.Code, w.Body.String())
	}

	// DB mode: the store read path and its failure branch.
	f := newDBFakeStore()
	sd := New("admin")
	if err := sd.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runs["run-3"] = model.Run{ID: "run-3", Status: model.StatusRunning}
	f.mu.Unlock()
	if w := doJSON(t, sd, http.MethodGet, "/api/v1/runs/run-3/logs", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("db logs = %d: %s", w.Code, w.Body.String())
	}
	fault := &idcovFaultStore{dbFakeStore: f, readLogsErr: errors.New("logs down")}
	sd.DB = fault
	if w := doJSON(t, sd, http.MethodGet, "/api/v1/runs/run-3/logs", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing db logs = %d, want 500", w.Code)
	}

	// A repo-only read principal restricted to another repository is refused.
	restricted := storeServer(t, "", map[string]auth.Principal{
		"read-token": {Subject: "reader", Repositories: map[string]auth.RepositoryPermission{"github.com/other/repo": {Read: true}}},
	})
	restricted.mu.Lock()
	restricted.runs["run-4"] = model.Run{ID: "run-4", RepoID: "github.com/kiwi/repo", Repo: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo", Status: model.StatusRunning}
	restricted.mu.Unlock()
	c := newTestClient(t, restricted.Handler(), "read-token")
	if w := c.do(http.MethodGet, "/api/v1/runs/run-4/logs", nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("scoped-out logs = %d, want 403", w.Code)
	}
}

// TestIDCovListJobsSortAndDB covers the job listing sort and DB branches.
func TestIDCovListJobsSortAndDB(t *testing.T) {
	s := New("admin")
	idcovSeedQueuedJob(t, s, "job-low", "run-sort", func(j *model.Job) { j.Priority = 1; j.CreatedAt = time.Now().UTC() })
	idcovSeedQueuedJob(t, s, "job-high", "run-sort", func(j *model.Job) { j.Priority = 9; j.CreatedAt = time.Now().UTC().Add(time.Second) })
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-sort/jobs", "admin", "")
	if w.Code != http.StatusOK {
		t.Fatalf("jobs = %d: %s", w.Code, w.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0]["id"] != "job-high" {
		t.Fatalf("jobs not priority-sorted: %v", out)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/ghost/jobs", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown run jobs = %d, want 404", w.Code)
	}

	// DB mode: found, missing and store failure.
	f := newDBFakeStore()
	sd := New("admin")
	if err := sd.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runs["run-db"] = model.Run{ID: "run-db", Status: model.StatusRunning}
	f.jobs["job-db"] = model.Job{ID: "job-db", RunID: "run-db", Key: "build", Status: model.StatusQueued}
	f.mu.Unlock()
	if w := doJSON(t, sd, http.MethodGet, "/api/v1/runs/run-db/jobs", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("db jobs = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, sd, http.MethodGet, "/api/v1/runs/ghost/jobs", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("db unknown run jobs = %d, want 404", w.Code)
	}
	fault := &idcovFaultStore{dbFakeStore: f, listJobsErr: errors.New("jobs down")}
	sd.DB = fault
	if w := doJSON(t, sd, http.MethodGet, "/api/v1/runs/run-db/jobs", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing db jobs = %d, want 500", w.Code)
	}
}

// TestIDCovListRunsScopedAndDBError covers the DB-mode list path, its scope
// filter and its failure branch.
func TestIDCovListRunsScopedAndDBError(t *testing.T) {
	f := newDBFakeStore()
	f.mu.Lock()
	f.runs["run-a"] = model.Run{ID: "run-a", RepoID: "github.com/kiwi/repo", RepoFullName: "kiwi/repo", Status: model.StatusRunning}
	f.runs["run-b"] = model.Run{ID: "run-b", RepoID: "github.com/other/repo", RepoFullName: "other/repo", Status: model.StatusRunning}
	f.mu.Unlock()

	s := storeServer(t, "", map[string]auth.Principal{
		"read-token": {Subject: "reader", Repositories: map[string]auth.RepositoryPermission{"github.com/kiwi/repo": {Read: true}}},
	})
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "read-token")
	w := c.do(http.MethodGet, "/api/v1/runs", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("scoped list = %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "run-b") || !strings.Contains(w.Body.String(), "run-a") {
		t.Fatalf("scope filter wrong: %s", w.Body.String())
	}

	fault := &idcovFaultStore{dbFakeStore: f, listRunsErr: errors.New("runs down")}
	s.DB = fault
	if w := c.do(http.MethodGet, "/api/v1/runs", nil, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing list = %d, want 500", w.Code)
	}
}

// TestIDCovNextUnregisteredAndCapacityClamp covers the unregistered refusal
// and the legacy capacity clamp.
func TestIDCovNextUnregisteredAndCapacityClamp(t *testing.T) {
	s := New("secret")
	h := s.Handler()
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/ghost/next", map[string]any{}, "secret", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unregistered next = %d, want 404", w.Code)
	}
	// Capacity 0 in dev mode is clamped to 1 so legacy runners keep working.
	s.mu.Lock()
	s.runners["r-zero"] = model.Runner{ID: "r-zero", Name: "rz", Capacity: 0}
	s.mu.Unlock()
	idcovSeedQueuedJob(t, s, "job-clamp", "run-clamp", nil)
	w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/r-zero/next", map[string]any{}, "secret", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("capacity-clamped next = %d: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.Job.ID != "job-clamp" || task.LeaseToken == "" {
		t.Fatalf("task = %+v", task)
	}
}

// TestIDCovNextQueueDeadlineSkip covers the expired queue-deadline skip.
func TestIDCovNextQueueDeadlineSkip(t *testing.T) {
	s := New("secret")
	s.mu.Lock()
	s.runners["r-q"] = model.Runner{ID: "r-q", Name: "rq", Capacity: 1}
	s.mu.Unlock()
	past := time.Now().UTC().Add(-time.Hour)
	idcovSeedQueuedJob(t, s, "job-expired", "run-expired", func(j *model.Job) { j.QueueDeadline = &past })
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/r-q/next", map[string]any{}, "secret", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expired deadline next = %d, want 204: %s", w.Code, w.Body.String())
	}
}

// TestIDCovNextQuotaLimitsSkip covers the repo and team concurrency skips at
// lease time.
func TestIDCovNextQuotaLimitsSkip(t *testing.T) {
	cases := []struct {
		name  string
		limit quotas.Limits
	}{
		{"repo", quotas.Limits{RepoConcurrency: 1}},
		{"team", quotas.Limits{TeamConcurrency: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New("secret")
			s.QuotaLimits = tc.limit
			s.mu.Lock()
			s.runners["r-quota"] = model.Runner{ID: "r-quota", Name: "rquota", Capacity: 2}
			s.mu.Unlock()
			idcovSeedMemoryJob(t, s, "job-running", "run-quota", "other-runner", "tok", nil)
			idcovSeedQueuedJob(t, s, "job-queued", "run-quota", nil)
			w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/r-quota/next", map[string]any{}, "secret", nil)
			if w.Code != http.StatusNoContent {
				t.Fatalf("quota-limited next = %d, want 204: %s", w.Code, w.Body.String())
			}
		})
	}
}

// TestIDCovNextPriorityOrder covers the priority-then-FIFO candidate sort.
func TestIDCovNextPriorityOrder(t *testing.T) {
	s := New("secret")
	s.mu.Lock()
	s.runners["r-pri"] = model.Runner{ID: "r-pri", Name: "rpri", Capacity: 1}
	s.mu.Unlock()
	idcovSeedQueuedJob(t, s, "job-low", "run-pri", func(j *model.Job) { j.Priority = 1 })
	idcovSeedQueuedJob(t, s, "job-high", "run-pri", func(j *model.Job) { j.Priority = 5 })
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/r-pri/next", map[string]any{}, "secret", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("priority next = %d: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.Job.ID != "job-high" {
		t.Fatalf("leased %q, want the high-priority job", task.Job.ID)
	}
}

// TestIDCovHeartbeatCancelledAndBadJSON covers the cancelled-lease reply and
// the decode guard.
func TestIDCovHeartbeatCancelledAndBadJSON(t *testing.T) {
	s := New("secret")
	h := s.Handler()
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/j1/heartbeat", []byte("{"), "secret", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad heartbeat body = %d, want 400", w.Code)
	}
	// Cancelled job: the lease is dead but the runner is told to stop.
	idcovSeedMemoryJob(t, s, "job-cancel", "run-cancel", "runner-c", "tok-c", func(j *model.Job) {
		j.Status = model.StatusCancelled
	})
	w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/job-cancel/heartbeat",
		Heartbeat{RunnerID: "runner-c", LeaseToken: "tok-c", LeaseGeneration: 1}, "secret", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"cancel":true`) {
		t.Fatalf("cancelled heartbeat = %d: %s", w.Code, w.Body.String())
	}
	// Unknown job is a 404 from the shared lease gate.
	w = pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/ghost/heartbeat",
		Heartbeat{RunnerID: "runner-c", LeaseToken: "tok-c", LeaseGeneration: 1}, "secret", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown heartbeat = %d, want 404", w.Code)
	}
}

// TestIDCovHeartbeatDBBranches covers the durable heartbeat branches.
func TestIDCovHeartbeatDBBranches(t *testing.T) {
	f := newDBFakeStore()
	s := New("secret")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	// Unknown job.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/ghost/heartbeat",
		Heartbeat{RunnerID: "r", LeaseToken: "t", LeaseGeneration: 1}, "secret", nil); w.Code != http.StatusNotFound {
		t.Fatalf("db unknown heartbeat = %d, want 404", w.Code)
	}
	// Cancelled job.
	exp := time.Now().Add(time.Minute)
	f.mu.Lock()
	f.jobs["job-c"] = model.Job{ID: "job-c", RunID: "run-c", Key: "build", Status: model.StatusCancelled, LeaseRunnerID: "r", LeaseTokenHash: hashLeaseToken(s.leaseKey, "t"), LeaseGeneration: 1, LeaseExpiresAt: &exp}
	f.mu.Unlock()
	w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/job-c/heartbeat",
		Heartbeat{RunnerID: "r", LeaseToken: "t", LeaseGeneration: 1}, "secret", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"cancel":true`) {
		t.Fatalf("db cancelled heartbeat = %d: %s", w.Code, w.Body.String())
	}
	// Stale lease on a running job.
	f.mu.Lock()
	f.jobs["job-s"] = model.Job{ID: "job-s", RunID: "run-c", Key: "build", Status: model.StatusRunning, LeaseRunnerID: "r", LeaseTokenHash: hashLeaseToken(s.leaseKey, "t"), LeaseGeneration: 1, LeaseExpiresAt: &exp}
	f.mu.Unlock()
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/job-s/heartbeat",
		Heartbeat{RunnerID: "r", LeaseToken: "wrong", LeaseGeneration: 1}, "secret", nil); w.Code != http.StatusConflict {
		t.Fatalf("db stale heartbeat = %d, want 409", w.Code)
	}
	// Successful extension.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/job-s/heartbeat",
		Heartbeat{RunnerID: "r", LeaseToken: "t", LeaseGeneration: 1}, "secret", nil); w.Code != http.StatusOK {
		t.Fatalf("db heartbeat = %d: %s", w.Code, w.Body.String())
	}
}

// TestIDCovLogEndpointBranches covers the log endpoint's validation and
// store-failure branches.
func TestIDCovLogEndpointBranches(t *testing.T) {
	s := New("secret")
	h := s.Handler()
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/j1/log", []byte("{"), "secret", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad log body = %d, want 400", w.Code)
	}
	// Oversized step name.
	big := LogLine{RunnerID: "r", LeaseToken: "t", LeaseGeneration: 1, Step: strings.Repeat("s", 129), Line: "x"}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/j1/log", big, "secret", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized step = %d, want 400", w.Code)
	}
	// Oversized line.
	big = LogLine{RunnerID: "r", LeaseToken: "t", LeaseGeneration: 1, Line: strings.Repeat("x", (1<<20)+1)}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/j1/log", big, "secret", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized line = %d, want 400", w.Code)
	}
	// Oversized job key.
	big = LogLine{RunnerID: "r", LeaseToken: "t", LeaseGeneration: 1, JobKey: strings.Repeat("k", 513), Line: "x"}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/j1/log", big, "secret", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized job key = %d, want 400", w.Code)
	}

	// A persistent server whose store root is a broken path fails closed.
	dir := t.TempDir()
	sp, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	idcovSeedMemoryJob(t, sp, "job-log", "run-log", "runner-l", "tok-l", nil)
	blocker := filepath.Join(dir, "blocker")
	writeTestFile(t, blocker, []byte("x"))
	sp.store.Root = blocker
	in := LogLine{RunnerID: "runner-l", LeaseToken: "tok-l", LeaseGeneration: 1, Step: "s", Line: "hello"}
	w := pkiRequest(t, sp.Handler(), http.MethodPost, "/api/v1/jobs/job-log/log", in, "secret", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("broken store log = %d, want 500", w.Code)
	}
}

// TestIDCovLogDBSuccessAndFailure covers the DB log append branches.
func TestIDCovLogDBSuccessAndFailure(t *testing.T) {
	f := newDBFakeStore()
	s := New("secret")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Minute)
	f.mu.Lock()
	f.jobs["job-dbl"] = model.Job{ID: "job-dbl", RunID: "run-dbl", Key: "build", Status: model.StatusRunning, LeaseRunnerID: "r", LeaseTokenHash: hashLeaseToken(s.leaseKey, "t"), LeaseGeneration: 1, LeaseExpiresAt: &exp}
	f.mu.Unlock()
	in := LogLine{RunnerID: "r", LeaseToken: "t", LeaseGeneration: 1, Step: "s", Line: "hello"}
	h := s.Handler()
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/job-dbl/log", in, "secret", nil); w.Code != http.StatusNoContent {
		t.Fatalf("db log = %d, want 204: %s", w.Code, w.Body.String())
	}
	fault := &idcovFaultStore{dbFakeStore: f, appendLogErr: errors.New("append down")}
	s.DB = fault
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/job-dbl/log", in, "secret", nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing db log = %d, want 500", w.Code)
	}
}

// TestIDCovCompleteMemoryEdges covers the completion normalization, size
// guard and idempotent receipt replay.
func TestIDCovCompleteMemoryEdges(t *testing.T) {
	s := New("secret")
	h := s.Handler()
	// Oversized error message.
	big := Complete{RunnerID: "r", LeaseToken: "t", LeaseGeneration: 1, Status: model.StatusSuccess, Error: strings.Repeat("e", (64<<10)+1)}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/j1/complete", big, "secret", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized error = %d, want 400", w.Code)
	}
	// Bad JSON.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/j1/complete", []byte("{"), "secret", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad complete body = %d, want 400", w.Code)
	}

	// Unknown status normalizes to failure; the job is not running so the
	// durable path is exercised through a seeded lease.
	idcovSeedMemoryJob(t, s, "job-c1", "run-c1", "r1", "tok1", nil)
	in := Complete{RunnerID: "r1", LeaseToken: "tok1", LeaseGeneration: 1, Status: model.Status("bogus")}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/job-c1/complete", in, "secret", nil); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	got := s.jobs["job-c1"]
	s.mu.Unlock()
	if got.Status != model.StatusFailure {
		t.Fatalf("unknown status stored as %q, want failure", got.Status)
	}
	// The idempotent replay of the same completion is acknowledged.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/job-c1/complete", in, "secret", nil); w.Code != http.StatusNoContent {
		t.Fatalf("replayed complete = %d: %s", w.Code, w.Body.String())
	}
	// A different result for the same generation is a stale-lease conflict.
	other := Complete{RunnerID: "r1", LeaseToken: "tok1", LeaseGeneration: 1, Status: model.StatusSuccess}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/job-c1/complete", other, "secret", nil); w.Code != http.StatusConflict {
		t.Fatalf("conflicting replay = %d, want 409", w.Code)
	}

	// Invalid outputs (over the value bound) fail the job with the
	// descriptive error instead of storing the payload.
	idcovSeedMemoryJob(t, s, "job-c2", "run-c2", "r2", "tok2", nil)
	huge := Complete{RunnerID: "r2", LeaseToken: "tok2", LeaseGeneration: 1, Status: model.StatusSuccess, Outputs: map[string]string{"k": strings.Repeat("v", (64<<10)+1)}}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/job-c2/complete", huge, "secret", nil); w.Code != http.StatusNoContent {
		t.Fatalf("invalid outputs complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	got = s.jobs["job-c2"]
	s.mu.Unlock()
	if got.Status != model.StatusFailure || got.Error != "runner returned invalid or oversized job outputs" {
		t.Fatalf("invalid outputs result = %q / %q", got.Status, got.Error)
	}
}

// TestIDCovRunnerAdminDBBranches covers drain/enable/disable in DB mode and
// their failure branches.
func TestIDCovRunnerAdminDBBranches(t *testing.T) {
	f := newDBFakeStore()
	s := New("admin")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// Missing runner: drain and enable are 404.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/ghost/drain", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("drain unknown = %d, want 404", w.Code)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/ghost/enable", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("enable unknown = %d, want 404", w.Code)
	}
	// Store read failures are 500.
	fault := &idcovFaultStore{dbFakeStore: f, getRunnerErr: errors.New("runner read failed")}
	s.DB = fault
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/drain", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("drain read failure = %d, want 500", w.Code)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/enable", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("enable read failure = %d, want 500", w.Code)
	}
	fault.getRunnerErr = nil
	f.mu.Lock()
	f.runners["r1"] = model.Runner{ID: "r1", Name: "r1", Capacity: 1}
	f.mu.Unlock()
	// Upsert failures are 500.
	fault.upsertRunErr = errors.New("runner write failed")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/drain", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("drain write failure = %d, want 500", w.Code)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/enable", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("enable write failure = %d, want 500", w.Code)
	}
	fault.upsertRunErr = nil
	// Success paths.
	f.mu.Lock()
	f.runners["r1"] = model.Runner{ID: "r1", Name: "r1", Capacity: 1}
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/drain", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("drain = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/enable", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
}

// TestIDCovRunnerDisableDBKillSwitch covers the disable kill switch.
func TestIDCovRunnerDisableDBKillSwitch(t *testing.T) {
	f := newDBFakeStore()
	s := New("admin")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runners["r1"] = model.Runner{ID: "r1", Name: "r1", Capacity: 1, CertSerial: "abc"}
	f.jobs["job-k"] = model.Job{ID: "job-k", RunID: "run-k", Key: "build", Status: model.StatusRunning, LeaseRunnerID: "r1", LeaseGeneration: 1}
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/disable", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("disable = %d: %s", w.Code, w.Body.String())
	}
}

// TestIDCovListServingRunnersBranches covers the serving projection in both
// storage modes, the repo filter and the failure branch.
func TestIDCovListServingRunnersBranches(t *testing.T) {
	s := New("admin")
	s.mu.Lock()
	s.runners["r-serv"] = model.Runner{ID: "r-serv", Name: "rs", Capacity: 1, ActiveJobs: []string{"job-s1", "job-missing"}, LastSeen: time.Now().UTC()}
	s.jobs["job-s1"] = model.Job{ID: "job-s1", RunID: "run-s1", Key: "build", Status: model.StatusRunning, RepoID: "github.com/kiwi/repo"}
	s.runs["run-s1"] = model.Run{ID: "run-s1", RepoID: "github.com/kiwi/repo", RepoFullName: "kiwi/repo", Status: model.StatusRunning}
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodGet, "/api/v1/runners/serving", "admin", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "job-s1") {
		t.Fatalf("serving = %d: %s", w.Code, w.Body.String())
	}
	// The repo filter excludes non-matching jobs, leaving an empty list.
	w = doJSON(t, s, http.MethodGet, "/api/v1/runners/serving?repo=other/repo", "admin", "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "job-s1") {
		t.Fatalf("repo-filtered serving = %d: %s", w.Code, w.Body.String())
	}

	// DB mode and its failure branch.
	f := newDBFakeStore()
	sd := New("admin")
	if err := sd.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runners["r-serv"] = model.Runner{ID: "r-serv", Name: "rs", Capacity: 1, ActiveJobs: []string{"job-s1"}}
	f.jobs["job-s1"] = model.Job{ID: "job-s1", RunID: "run-s1", Key: "build", Status: model.StatusRunning, RepoID: "github.com/kiwi/repo"}
	f.runs["run-s1"] = model.Run{ID: "run-s1", RepoID: "github.com/kiwi/repo", RepoFullName: "kiwi/repo", Status: model.StatusRunning}
	f.mu.Unlock()
	if w := doJSON(t, sd, http.MethodGet, "/api/v1/runners/serving", "admin", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "job-s1") {
		t.Fatalf("db serving = %d: %s", w.Code, w.Body.String())
	}
	fault := &idcovFaultStore{dbFakeStore: f, listRunnerErr: errors.New("runners down")}
	sd.DB = fault
	if w := doJSON(t, sd, http.MethodGet, "/api/v1/runners/serving", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing serving = %d, want 500", w.Code)
	}
}

// TestIDCovApproveJobBranches covers the memory and DB approval decisions.
func TestIDCovApproveJobBranches(t *testing.T) {
	s := New("admin")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/ghost/approve", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("approve unknown = %d, want 404", w.Code)
	}
	// A job that does not require approval.
	s.mu.Lock()
	s.jobs["job-plain"] = model.Job{ID: "job-plain", RunID: "run-p", Key: "build", Status: model.StatusQueued}
	s.runs["run-p"] = model.Run{ID: "run-p", Status: model.StatusQueued}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-plain/approve", "admin", ""); w.Code != http.StatusConflict {
		t.Fatalf("approve non-gated = %d, want 409", w.Code)
	}
	// A terminal approval-gated job.
	s.mu.Lock()
	s.jobs["job-done"] = model.Job{ID: "job-done", RunID: "run-p", Key: "build", Status: model.StatusSuccess, ApprovalRequired: true}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-done/approve", "admin", ""); w.Code != http.StatusConflict {
		t.Fatalf("approve terminal = %d, want 409", w.Code)
	}
	// Waiting-approval job: approval moves it to queued and records the
	// actor and wait metric.
	waiting := time.Now().Add(-time.Second)
	s.mu.Lock()
	s.jobs["job-wait"] = model.Job{ID: "job-wait", RunID: "run-p", Key: "deploy", Status: model.StatusWaitingApproval, ApprovalRequired: true, Environment: "prod", WaitingSince: &waiting}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-wait/approve", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("approve = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	got := s.jobs["job-wait"]
	s.mu.Unlock()
	if got.Status != model.StatusQueued || got.ApprovedBy == "" || got.WaitingSince != nil {
		t.Fatalf("approved job = %+v", got)
	}

	// DB mode: missing, store failure, non-gated, terminal and success.
	f := newDBFakeStore()
	sd := New("admin")
	if err := sd.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, sd, http.MethodPost, "/api/v1/jobs/ghost/approve", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("db approve unknown = %d, want 404", w.Code)
	}
	f.mu.Lock()
	f.jobs["job-plain"] = model.Job{ID: "job-plain", RunID: "run-p", Key: "build", Status: model.StatusQueued}
	f.jobs["job-wait"] = model.Job{ID: "job-wait", RunID: "run-p", Key: "deploy", Status: model.StatusWaitingApproval, ApprovalRequired: true, Environment: "prod"}
	f.jobs["job-done"] = model.Job{ID: "job-done", RunID: "run-p", Key: "build", Status: model.StatusSuccess, ApprovalRequired: true}
	f.mu.Unlock()
	if w := doJSON(t, sd, http.MethodPost, "/api/v1/jobs/job-plain/approve", "admin", ""); w.Code != http.StatusConflict {
		t.Fatalf("db approve non-gated = %d, want 409", w.Code)
	}
	if w := doJSON(t, sd, http.MethodPost, "/api/v1/jobs/job-done/approve", "admin", ""); w.Code != http.StatusConflict {
		t.Fatalf("db approve terminal = %d, want 409", w.Code)
	}
	if w := doJSON(t, sd, http.MethodPost, "/api/v1/jobs/job-wait/approve", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("db approve = %d: %s", w.Code, w.Body.String())
	}
	fault := &idcovFaultStore{dbFakeStore: f, getJobErr: errors.New("job down")}
	sd.DB = fault
	if w := doJSON(t, sd, http.MethodPost, "/api/v1/jobs/job-wait/approve", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db approve read failure = %d, want 500", w.Code)
	}
	fault.getJobErr = nil
	fault.updateJobErr = errors.New("write down")
	if w := doJSON(t, sd, http.MethodPost, "/api/v1/jobs/job-wait/approve", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db approve write failure = %d, want 500", w.Code)
	}
}
