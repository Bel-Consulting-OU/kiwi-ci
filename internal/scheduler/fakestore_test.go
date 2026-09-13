package scheduler

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/kiwici/kiwi/internal/model"
	"github.com/kiwici/kiwi/internal/storage"
)

// fakeStore is a behavioral in-memory storage.Store for scheduler and server
// DB-mode tests. It records every scheduler-facing call so tests can assert
// delegation, and implements a functional subset (statuses map + receipts).
type fakeStore struct {
	mu        sync.Mutex
	runs      map[string]model.Run
	jobs      map[string]model.Job
	runners   map[string]model.Runner
	receipts  map[string]model.CompletionReceipt
	audit     []model.AuditEvent
	logs      []model.LogEntry
	artifacts []model.ArtifactRecord
	reports   []model.TestReport

	leaderOK    bool
	leaderErr   error
	releaseKeys []string

	insertRunCalls     []model.Run
	insertJobCalls     []model.Job
	acquireCalls       []acquireCall
	heartbeatCalls     []heartbeatCall
	completeCalls      []completeCall
	cancelRunCalls     []cancelRunCall
	updateJobCalls     []model.Job
	releaseRunnerCalls []releaseRunnerCall
}

type acquireCall struct {
	JobID      string
	RunnerID   string
	TokenHash  []byte
	Generation int64
	ExpiresAt  time.Time
}

type heartbeatCall struct {
	JobID      string
	RunnerID   string
	Generation int64
	ExpiresAt  time.Time
}

type completeCall struct {
	JobID      string
	Generation int64
	RunnerID   string
	Status     model.Status
	ErrMsg     string
	Outputs    map[string]string
	Receipt    model.CompletionReceipt
}

type cancelRunCall struct {
	RunID  string
	Reason string
}

type releaseRunnerCall struct {
	RunnerID string
	JobID    string
	Status   model.Status
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		runs:     map[string]model.Run{},
		jobs:     map[string]model.Job{},
		runners:  map[string]model.Runner{},
		receipts: map[string]model.CompletionReceipt{},
	}
}

var _ storage.Store = (*fakeStore)(nil)

func (f *fakeStore) Close() error { return nil }

func (f *fakeStore) InsertRun(ctx context.Context, run model.Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.insertRunCalls = append(f.insertRunCalls, run)
	f.runs[run.ID] = run
	return nil
}

func (f *fakeStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runs[id]
	if !ok {
		return model.Run{}, storage.ErrNotFound
	}
	return r, nil
}

func (f *fakeStore) UpdateRunStatus(ctx context.Context, id string, status model.Status, startedAt, finishedAt *time.Time) error {
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

func (f *fakeStore) ListRuns(ctx context.Context, limit int) ([]model.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]model.Run, 0, len(f.runs))
	for _, r := range f.runs {
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeStore) InsertJob(ctx context.Context, job model.Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.insertJobCalls = append(f.insertJobCalls, job)
	f.jobs[job.ID] = job
	return nil
}

func (f *fakeStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[id]
	if !ok {
		return model.Job{}, storage.ErrNotFound
	}
	return j, nil
}

func (f *fakeStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
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

func (f *fakeStore) ListQueuedJobs(ctx context.Context) ([]model.Job, error) {
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

func (f *fakeStore) UpdateJob(ctx context.Context, job model.Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateJobCalls = append(f.updateJobCalls, job)
	f.jobs[job.ID] = job
	return nil
}

func (f *fakeStore) AcquireLease(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquireCalls = append(f.acquireCalls, acquireCall{jobID, runnerID, tokenHash, generation, expiresAt})
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

func (f *fakeStore) HeartbeatLease(ctx context.Context, jobID string, runnerID string, generation int64, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeatCalls = append(f.heartbeatCalls, heartbeatCall{jobID, runnerID, generation, expiresAt})
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

func (f *fakeStore) CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completeCalls = append(f.completeCalls, completeCall{jobID, generation, runnerID, status, errMsg, outputs, receipt})
	j, ok := f.jobs[jobID]
	if !ok {
		return storage.ErrNotFound
	}
	key := receiptKey(jobID, generation, runnerID)
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

func (f *fakeStore) CancelRunJobs(ctx context.Context, runID string, reason string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelRunCalls = append(f.cancelRunCalls, cancelRunCall{runID, reason})
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

func (f *fakeStore) UpsertRunner(ctx context.Context, runner model.Runner) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runners[runner.ID] = runner
	return nil
}

func (f *fakeStore) GetRunner(ctx context.Context, id string) (model.Runner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runners[id]
	if !ok {
		return model.Runner{}, storage.ErrNotFound
	}
	return r, nil
}

func (f *fakeStore) ListRunners(ctx context.Context) ([]model.Runner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]model.Runner, 0, len(f.runners))
	for _, r := range f.runners {
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeStore) ReleaseRunnerJob(ctx context.Context, runnerID, jobID string, status model.Status) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseRunnerCalls = append(f.releaseRunnerCalls, releaseRunnerCall{runnerID, jobID, status})
	r, ok := f.runners[runnerID]
	if !ok {
		return storage.ErrNotFound
	}
	active := r.ActiveJobs[:0]
	for _, id := range r.ActiveJobs {
		if id != jobID {
			active = append(active, id)
		}
	}
	r.ActiveJobs = active
	f.runners[runnerID] = r
	return nil
}

func (f *fakeStore) InsertArtifact(ctx context.Context, a model.ArtifactRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.artifacts = append(f.artifacts, a)
	return nil
}

func (f *fakeStore) ListArtifacts(ctx context.Context, runID string) ([]model.ArtifactRecord, error) {
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

func (f *fakeStore) InsertTestReport(ctx context.Context, rep model.TestReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, rep)
	return nil
}

func (f *fakeStore) ListTestReports(ctx context.Context, runID string) ([]model.TestReport, error) {
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

func (f *fakeStore) ListTestReportsAll(ctx context.Context) ([]model.TestReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.TestReport(nil), f.reports...), nil
}

func (f *fakeStore) AppendLog(ctx context.Context, e model.LogEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs = append(f.logs, e)
	return nil
}

func (f *fakeStore) ReadLogs(ctx context.Context, runID string, after int64, limit int) ([]model.LogEntry, error) {
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

func (f *fakeStore) AppendAudit(ctx context.Context, e model.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audit = append(f.audit, e)
	return nil
}

func (f *fakeStore) ReadAudit(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.AuditEvent(nil), f.audit...), nil
}

func (f *fakeStore) InsertCompletionReceipt(ctx context.Context, r model.CompletionReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.receipts[receiptKey(r.JobID, r.Generation, r.RunnerID)] = r
	return nil
}

func (f *fakeStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.receipts[receiptKey(jobID, generation, runnerID)]
	return r, ok, nil
}

func (f *fakeStore) UpsertDelivery(ctx context.Context, forge, deliveryID string, runID string, payloadDigest string) error {
	return nil
}

func (f *fakeStore) FindDelivery(ctx context.Context, forge, deliveryID string) (string, bool, error) {
	return "", false, nil
}

func (f *fakeStore) TryAcquireLeadership(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.leaderErr != nil {
		return false, f.leaderErr
	}
	return f.leaderOK, nil
}

func (f *fakeStore) ReleaseLeadership(ctx context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseKeys = append(f.releaseKeys, key)
	return nil
}

func (f *fakeStore) Migrate(ctx context.Context) error { return nil }

func (f *fakeStore) SchemaVersion(ctx context.Context) (int, error) { return 1, nil }

// script helpers ------------------------------------------------------------

func (f *fakeStore) setLeader(ok bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leaderOK = ok
	f.leaderErr = err
}

func (f *fakeStore) putRun(r model.Run) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs[r.ID] = r
}

func (f *fakeStore) putJob(j model.Job) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs[j.ID] = j
}

func (f *fakeStore) putRunner(r model.Runner) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runners[r.ID] = r
}

func (f *fakeStore) job(id string) (model.Job, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[id]
	return j, ok
}

func (f *fakeStore) audits() []model.AuditEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.AuditEvent(nil), f.audit...)
}

func receiptKey(jobID string, generation int64, runnerID string) string {
	return jobID + "|" + strconv.FormatInt(generation, 10) + "|" + runnerID
}
