package server

import (
	"context"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// dbFakeStore is a compact behavioral storage.Store for DB-mode server
// tests: a statuses map plus receipts, with recorded scheduler-facing calls.
type dbFakeStore struct {
	mu        sync.Mutex
	runs      map[string]model.Run
	jobs      map[string]model.Job
	runners   map[string]model.Runner
	receipts  map[string]model.CompletionReceipt
	audit     []model.AuditEvent
	logs      []model.LogEntry
	artifacts []model.ArtifactRecord
	reports   []model.TestReport

	leaderOK  bool
	leaderErr error
	schemaErr error

	insertRunCalls  []model.Run
	insertJobCalls  []model.Job
	acquireCalls    []acquireArgs
	heartbeatCalls  []heartbeatArgs
	completeCalls   []completeArgs
	cancelRunCalls  []cancelRunArgs
	updateJobCalls  []model.Job
	appendAuditErrs int
}

type acquireArgs struct {
	JobID      string
	RunnerID   string
	TokenHash  []byte
	Generation int64
	ExpiresAt  time.Time
}

type heartbeatArgs struct {
	JobID      string
	RunnerID   string
	Generation int64
	ExpiresAt  time.Time
}

type completeArgs struct {
	JobID      string
	Generation int64
	RunnerID   string
	Status     model.Status
	Receipt    model.CompletionReceipt
}

type cancelRunArgs struct {
	RunID  string
	Reason string
}

var _ storage.Store = (*dbFakeStore)(nil)

func newDBFakeStore() *dbFakeStore {
	return &dbFakeStore{
		runs:     map[string]model.Run{},
		jobs:     map[string]model.Job{},
		runners:  map[string]model.Runner{},
		receipts: map[string]model.CompletionReceipt{},
		leaderOK: true,
	}
}

func (f *dbFakeStore) Close() error { return nil }

func (f *dbFakeStore) InsertRun(ctx context.Context, run model.Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.insertRunCalls = append(f.insertRunCalls, run)
	f.runs[run.ID] = run
	return nil
}

func (f *dbFakeStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runs[id]
	if !ok {
		return model.Run{}, storage.ErrNotFound
	}
	return r, nil
}

func (f *dbFakeStore) UpdateRunStatus(ctx context.Context, id string, status model.Status, startedAt, finishedAt *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runs[id]
	if !ok {
		return storage.ErrNotFound
	}
	r.Status = status
	if startedAt != nil {
		r.StartedAt = startedAt
	}
	if finishedAt != nil {
		r.FinishedAt = finishedAt
	}
	f.runs[id] = r
	return nil
}

func (f *dbFakeStore) ListRuns(ctx context.Context, limit int) ([]model.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]model.Run, 0, len(f.runs))
	for _, r := range f.runs {
		out = append(out, r)
	}
	return out, nil
}

func (f *dbFakeStore) InsertJob(ctx context.Context, job model.Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.insertJobCalls = append(f.insertJobCalls, job)
	f.jobs[job.ID] = job
	return nil
}

func (f *dbFakeStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[id]
	if !ok {
		return model.Job{}, storage.ErrNotFound
	}
	return j, nil
}

func (f *dbFakeStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.Job{}
	for _, j := range f.jobs {
		if j.RunID == runID {
			out = append(out, j)
		}
	}
	return out, nil
}

func (f *dbFakeStore) ListJobsByEnvironment(ctx context.Context, repoURL, environment string) ([]model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.Job{}
	for _, j := range f.jobs {
		if j.Environment == environment && j.RepoURL == repoURL {
			out = append(out, j)
		}
	}
	return out, nil
}

func (f *dbFakeStore) ListQueuedJobs(ctx context.Context) ([]model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.Job{}
	for _, j := range f.jobs {
		if j.Status == model.StatusQueued {
			out = append(out, j)
		}
	}
	return out, nil
}

func (f *dbFakeStore) UpdateJob(ctx context.Context, job model.Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateJobCalls = append(f.updateJobCalls, job)
	f.jobs[job.ID] = job
	return nil
}

func (f *dbFakeStore) AcquireLease(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquireCalls = append(f.acquireCalls, acquireArgs{jobID, runnerID, tokenHash, generation, expiresAt})
	j, ok := f.jobs[jobID]
	if !ok {
		return model.Job{}, storage.ErrNotFound
	}
	if j.Status != model.StatusQueued {
		return model.Job{}, storage.ErrLeaseConflict
	}
	j.Status = model.StatusRunning
	j.Attempts++
	j.LeaseRunnerID = runnerID
	j.LeaseTokenHash = tokenHash
	j.LeaseGeneration = generation
	j.LeaseExpiresAt = &expiresAt
	f.jobs[jobID] = j
	return j, nil
}

func (f *dbFakeStore) HeartbeatLease(ctx context.Context, jobID string, runnerID string, generation int64, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeatCalls = append(f.heartbeatCalls, heartbeatArgs{jobID, runnerID, generation, expiresAt})
	j, ok := f.jobs[jobID]
	if !ok {
		return storage.ErrNotFound
	}
	if j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID || j.LeaseGeneration != generation {
		return storage.ErrLeaseConflict
	}
	j.LeaseExpiresAt = &expiresAt
	f.jobs[jobID] = j
	return nil
}

func (f *dbFakeStore) CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completeCalls = append(f.completeCalls, completeArgs{jobID, generation, runnerID, status, receipt})
	j, ok := f.jobs[jobID]
	if !ok {
		return storage.ErrNotFound
	}
	key := jobID + "|" + itoa(generation) + "|" + runnerID
	if j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID || j.LeaseGeneration != generation {
		if _, dup := f.receipts[key]; dup {
			return nil
		}
		return storage.ErrGenerationMismatch
	}
	j.Status = status
	j.Error = errMsg
	j.Outputs = outputs
	now := time.Now().UTC()
	j.FinishedAt = &now
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	f.jobs[jobID] = j
	f.receipts[key] = receipt
	return nil
}

func (f *dbFakeStore) CancelRunJobs(ctx context.Context, runID string, reason string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelRunCalls = append(f.cancelRunCalls, cancelRunArgs{runID, reason})
	now := time.Now().UTC()
	ids := []string{}
	for id, j := range f.jobs {
		if j.RunID != runID || j.Status.Terminal() {
			continue
		}
		j.Status = model.StatusCancelled
		j.Error = reason
		j.FinishedAt = &now
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		f.jobs[id] = j
		ids = append(ids, id)
	}
	if r, ok := f.runs[runID]; ok && !r.Status.Terminal() {
		r.Status = model.StatusCancelled
		r.FinishedAt = &now
		f.runs[runID] = r
	}
	return ids, nil
}

func (f *dbFakeStore) UpsertRunner(ctx context.Context, runner model.Runner) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runners[runner.ID] = runner
	return nil
}

func (f *dbFakeStore) GetRunner(ctx context.Context, id string) (model.Runner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runners[id]
	if !ok {
		return model.Runner{}, storage.ErrNotFound
	}
	return r, nil
}

func (f *dbFakeStore) ListRunners(ctx context.Context) ([]model.Runner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]model.Runner, 0, len(f.runners))
	for _, r := range f.runners {
		out = append(out, r)
	}
	return out, nil
}

func (f *dbFakeStore) ReleaseRunnerJob(ctx context.Context, runnerID, jobID string, status model.Status) error {
	return nil
}

func (f *dbFakeStore) InsertArtifact(ctx context.Context, a model.ArtifactRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.artifacts = append(f.artifacts, a)
	return nil
}

func (f *dbFakeStore) ListArtifacts(ctx context.Context, runID string) ([]model.ArtifactRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.ArtifactRecord{}
	for _, a := range f.artifacts {
		if a.RunID == runID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *dbFakeStore) InsertTestReport(ctx context.Context, rep model.TestReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, rep)
	return nil
}

func (f *dbFakeStore) ListTestReports(ctx context.Context, runID string) ([]model.TestReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.TestReport{}
	for _, rep := range f.reports {
		if rep.RunID == runID {
			out = append(out, rep)
		}
	}
	return out, nil
}

func (f *dbFakeStore) ListTestReportsAll(ctx context.Context) ([]model.TestReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.TestReport(nil), f.reports...), nil
}

func (f *dbFakeStore) AppendLog(ctx context.Context, e model.LogEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs = append(f.logs, e)
	return nil
}

func (f *dbFakeStore) ReadLogs(ctx context.Context, runID string, after int64, limit int) ([]model.LogEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.LogEntry{}
	for _, e := range f.logs {
		if e.RunID == runID && e.Seq > after {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *dbFakeStore) AppendAudit(ctx context.Context, e model.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audit = append(f.audit, e)
	return nil
}

func (f *dbFakeStore) ReadAudit(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.AuditEvent(nil), f.audit...), nil
}

func (f *dbFakeStore) InsertCompletionReceipt(ctx context.Context, r model.CompletionReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.receipts[r.JobID+"|"+itoa(r.Generation)+"|"+r.RunnerID] = r
	return nil
}

func (f *dbFakeStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.receipts[jobID+"|"+itoa(generation)+"|"+runnerID]
	return r, ok, nil
}

func (f *dbFakeStore) UpsertDelivery(ctx context.Context, forge, deliveryID string, runID string, payloadDigest string) error {
	return nil
}

func (f *dbFakeStore) FindDelivery(ctx context.Context, forge, deliveryID string) (string, bool, error) {
	return "", false, nil
}

func (f *dbFakeStore) TryAcquireLeadership(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.leaderErr != nil {
		return false, f.leaderErr
	}
	return f.leaderOK, nil
}

func (f *dbFakeStore) ReleaseLeadership(ctx context.Context, key string) error { return nil }

func (f *dbFakeStore) Migrate(ctx context.Context) error { return nil }

func (f *dbFakeStore) SchemaVersion(ctx context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.schemaErr != nil {
		return 0, f.schemaErr
	}
	return 1, nil
}

func (f *dbFakeStore) setLeader(ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leaderOK = ok
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
