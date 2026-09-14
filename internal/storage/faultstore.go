package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// FaultyStore wraps a Store and injects an error into the Nth mutating call
// (1-based). Reads always pass through untouched. FailAfter <= 0 disables
// fault injection entirely. It exists so persistence fault-injection tests
// can prove that every mutation either commits completely or returns an
// error with no partial write, at every failure point of the call sequence.
type FaultyStore struct {
	Inner Store

	mu        sync.Mutex
	mutCalls  int
	FailAfter int
	Err       error
}

// fail returns the injected error on the FailAfter-th mutating call and nil
// otherwise. It must be called at the top of every mutating method, before
// any state on Inner is touched.
func (f *FaultyStore) fail() error {
	if f.FailAfter <= 0 || f.Err == nil {
		return nil
	}
	f.mutCalls++
	if f.mutCalls == f.FailAfter {
		return f.Err
	}
	return nil
}

// Mutations returns how many mutating calls have been attempted so far.
func (f *FaultyStore) Mutations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mutCalls
}

var _ Store = (*FaultyStore)(nil)

func (f *FaultyStore) Close() error { return f.Inner.Close() }

func (f *FaultyStore) InsertRun(ctx context.Context, run model.Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.InsertRun(ctx, run)
}

func (f *FaultyStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	return f.Inner.GetRun(ctx, id)
}

func (f *FaultyStore) UpdateRunStatus(ctx context.Context, id string, status model.Status, startedAt, finishedAt *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.UpdateRunStatus(ctx, id, status, startedAt, finishedAt)
}

func (f *FaultyStore) ListRuns(ctx context.Context, limit int) ([]model.Run, error) {
	return f.Inner.ListRuns(ctx, limit)
}

func (f *FaultyStore) InsertJob(ctx context.Context, job model.Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.InsertJob(ctx, job)
}

func (f *FaultyStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	return f.Inner.GetJob(ctx, id)
}

func (f *FaultyStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	return f.Inner.ListJobsByRun(ctx, runID)
}

func (f *FaultyStore) ListQueuedJobs(ctx context.Context) ([]model.Job, error) {
	return f.Inner.ListQueuedJobs(ctx)
}

func (f *FaultyStore) UpdateJob(ctx context.Context, job model.Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.UpdateJob(ctx, job)
}

func (f *FaultyStore) AcquireLease(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return model.Job{}, err
	}
	return f.Inner.AcquireLease(ctx, jobID, runnerID, tokenHash, generation, expiresAt)
}

func (f *FaultyStore) HeartbeatLease(ctx context.Context, jobID string, runnerID string, generation int64, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.HeartbeatLease(ctx, jobID, runnerID, generation, expiresAt)
}

func (f *FaultyStore) CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.CompleteJob(ctx, jobID, generation, runnerID, status, errMsg, outputs, receipt)
}

func (f *FaultyStore) CancelRunJobs(ctx context.Context, runID string, reason string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return nil, err
	}
	return f.Inner.CancelRunJobs(ctx, runID, reason)
}

func (f *FaultyStore) UpsertRunner(ctx context.Context, runner model.Runner) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.UpsertRunner(ctx, runner)
}

func (f *FaultyStore) GetRunner(ctx context.Context, id string) (model.Runner, error) {
	return f.Inner.GetRunner(ctx, id)
}

func (f *FaultyStore) ListRunners(ctx context.Context) ([]model.Runner, error) {
	return f.Inner.ListRunners(ctx)
}

func (f *FaultyStore) ReleaseRunnerJob(ctx context.Context, runnerID, jobID string, status model.Status) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.ReleaseRunnerJob(ctx, runnerID, jobID, status)
}

func (f *FaultyStore) InsertArtifact(ctx context.Context, a model.ArtifactRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.InsertArtifact(ctx, a)
}

func (f *FaultyStore) ListArtifacts(ctx context.Context, runID string) ([]model.ArtifactRecord, error) {
	return f.Inner.ListArtifacts(ctx, runID)
}

func (f *FaultyStore) InsertTestReport(ctx context.Context, rep model.TestReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.InsertTestReport(ctx, rep)
}

func (f *FaultyStore) ListTestReports(ctx context.Context, runID string) ([]model.TestReport, error) {
	return f.Inner.ListTestReports(ctx, runID)
}

func (f *FaultyStore) ListTestReportsAll(ctx context.Context) ([]model.TestReport, error) {
	return f.Inner.ListTestReportsAll(ctx)
}

func (f *FaultyStore) AppendLog(ctx context.Context, e model.LogEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.AppendLog(ctx, e)
}

func (f *FaultyStore) ReadLogs(ctx context.Context, runID string, after int64, limit int) ([]model.LogEntry, error) {
	return f.Inner.ReadLogs(ctx, runID, after, limit)
}

func (f *FaultyStore) AppendAudit(ctx context.Context, e model.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.AppendAudit(ctx, e)
}

func (f *FaultyStore) ReadAudit(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	return f.Inner.ReadAudit(ctx, limit)
}

func (f *FaultyStore) InsertCompletionReceipt(ctx context.Context, r model.CompletionReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.InsertCompletionReceipt(ctx, r)
}

func (f *FaultyStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	return f.Inner.HasCompletionReceipt(ctx, jobID, generation, runnerID)
}

func (f *FaultyStore) UpsertDelivery(ctx context.Context, forge, deliveryID string, runID string, payloadDigest string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.UpsertDelivery(ctx, forge, deliveryID, runID, payloadDigest)
}

func (f *FaultyStore) FindDelivery(ctx context.Context, forge, deliveryID string) (string, bool, error) {
	return f.Inner.FindDelivery(ctx, forge, deliveryID)
}

func (f *FaultyStore) TryAcquireLeadership(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return false, err
	}
	return f.Inner.TryAcquireLeadership(ctx, key, ttl)
}

func (f *FaultyStore) ReleaseLeadership(ctx context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.ReleaseLeadership(ctx, key)
}

func (f *FaultyStore) Migrate(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.Migrate(ctx)
}

func (f *FaultyStore) SchemaVersion(ctx context.Context) (int, error) {
	return f.Inner.SchemaVersion(ctx)
}

// memStore is a fully functional in-memory Store used as the fault-free
// baseline underneath FaultyStore in fault-injection tests.
type memStore struct {
	mu        sync.Mutex
	runs      map[string]model.Run
	jobs      map[string]model.Job
	runners   map[string]model.Runner
	receipts  map[string]model.CompletionReceipt
	audit     []model.AuditEvent
	logs      []model.LogEntry
	artifacts []model.ArtifactRecord
	reports   []model.TestReport
	deliveries map[string]string
}

func newMemStore() *memStore {
	return &memStore{
		runs:      map[string]model.Run{},
		jobs:      map[string]model.Job{},
		runners:   map[string]model.Runner{},
		receipts:  map[string]model.CompletionReceipt{},
		deliveries: map[string]string{},
	}
}

var _ Store = (*memStore)(nil)

func (m *memStore) Close() error { return nil }

func (m *memStore) InsertRun(ctx context.Context, run model.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[run.ID] = run
	return nil
}

func (m *memStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return model.Run{}, ErrNotFound
	}
	return r, nil
}

func (m *memStore) UpdateRunStatus(ctx context.Context, id string, status model.Status, startedAt, finishedAt *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return ErrNotFound
	}
	r.Status = status
	if startedAt != nil {
		r.StartedAt = startedAt
	}
	if finishedAt != nil {
		r.FinishedAt = finishedAt
	}
	m.runs[id] = r
	return nil
}

func (m *memStore) ListRuns(ctx context.Context, limit int) ([]model.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.Run, 0, len(m.runs))
	for _, r := range m.runs {
		out = append(out, r)
	}
	return out, nil
}

func (m *memStore) InsertJob(ctx context.Context, job model.Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[job.ID] = job
	return nil
}

func (m *memStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return model.Job{}, ErrNotFound
	}
	return j, nil
}

func (m *memStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.Job{}
	for _, j := range m.jobs {
		if j.RunID == runID {
			out = append(out, j)
		}
	}
	return out, nil
}

func (m *memStore) ListQueuedJobs(ctx context.Context) ([]model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.Job{}
	for _, j := range m.jobs {
		if j.Status == model.StatusQueued {
			out = append(out, j)
		}
	}
	return out, nil
}

func (m *memStore) UpdateJob(ctx context.Context, job model.Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[job.ID] = job
	return nil
}

func (m *memStore) AcquireLease(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[jobID]
	if !ok {
		return model.Job{}, ErrNotFound
	}
	if j.Status != model.StatusQueued {
		return model.Job{}, ErrLeaseConflict
	}
	j.Status = model.StatusRunning
	j.Attempts++
	j.LeaseRunnerID = runnerID
	j.LeaseTokenHash = tokenHash
	j.LeaseGeneration = generation
	j.LeaseExpiresAt = &expiresAt
	m.jobs[jobID] = j
	return j, nil
}

func (m *memStore) HeartbeatLease(ctx context.Context, jobID string, runnerID string, generation int64, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[jobID]
	if !ok {
		return ErrNotFound
	}
	if j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID || j.LeaseGeneration != generation {
		return ErrLeaseConflict
	}
	j.LeaseExpiresAt = &expiresAt
	m.jobs[jobID] = j
	return nil
}

func (m *memStore) CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[jobID]
	if !ok {
		return ErrNotFound
	}
	key := m.receiptKey(jobID, generation, runnerID)
	if j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID || j.LeaseGeneration != generation {
		if _, dup := m.receipts[key]; dup {
			return nil
		}
		return ErrGenerationMismatch
	}
	j.Status = status
	j.Error = errMsg
	j.Outputs = outputs
	now := time.Now().UTC()
	j.FinishedAt = &now
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	m.jobs[jobID] = j
	m.receipts[key] = receipt
	return nil
}

func (m *memStore) CancelRunJobs(ctx context.Context, runID string, reason string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	ids := []string{}
	for id, j := range m.jobs {
		if j.RunID != runID || j.Status.Terminal() {
			continue
		}
		j.Status = model.StatusCancelled
		j.Error = reason
		j.FinishedAt = &now
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		m.jobs[id] = j
		ids = append(ids, id)
	}
	if r, ok := m.runs[runID]; ok && !r.Status.Terminal() {
		r.Status = model.StatusCancelled
		r.FinishedAt = &now
		m.runs[runID] = r
	}
	return ids, nil
}

func (m *memStore) UpsertRunner(ctx context.Context, runner model.Runner) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runners[runner.ID] = runner
	return nil
}

func (m *memStore) GetRunner(ctx context.Context, id string) (model.Runner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runners[id]
	if !ok {
		return model.Runner{}, ErrNotFound
	}
	return r, nil
}

func (m *memStore) ListRunners(ctx context.Context) ([]model.Runner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.Runner, 0, len(m.runners))
	for _, r := range m.runners {
		out = append(out, r)
	}
	return out, nil
}

func (m *memStore) ReleaseRunnerJob(ctx context.Context, runnerID, jobID string, status model.Status) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runners[runnerID]
	if !ok {
		return ErrNotFound
	}
	active := r.ActiveJobs[:0]
	for _, id := range r.ActiveJobs {
		if id != jobID {
			active = append(active, id)
		}
	}
	r.ActiveJobs = active
	m.runners[runnerID] = r
	return nil
}

func (m *memStore) InsertArtifact(ctx context.Context, a model.ArtifactRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.artifacts = append(m.artifacts, a)
	return nil
}

func (m *memStore) ListArtifacts(ctx context.Context, runID string) ([]model.ArtifactRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.ArtifactRecord{}
	for _, a := range m.artifacts {
		if a.RunID == runID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *memStore) InsertTestReport(ctx context.Context, rep model.TestReport) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reports = append(m.reports, rep)
	return nil
}

func (m *memStore) ListTestReports(ctx context.Context, runID string) ([]model.TestReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.TestReport{}
	for _, rep := range m.reports {
		if rep.RunID == runID {
			out = append(out, rep)
		}
	}
	return out, nil
}

func (m *memStore) ListTestReportsAll(ctx context.Context) ([]model.TestReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]model.TestReport(nil), m.reports...), nil
}

func (m *memStore) AppendLog(ctx context.Context, e model.LogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, e)
	return nil
}

func (m *memStore) ReadLogs(ctx context.Context, runID string, after int64, limit int) ([]model.LogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.LogEntry{}
	for _, e := range m.logs {
		if e.RunID == runID && e.Seq > after {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memStore) AppendAudit(ctx context.Context, e model.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, e)
	return nil
}

func (m *memStore) ReadAudit(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]model.AuditEvent(nil), m.audit...), nil
}

func (m *memStore) InsertCompletionReceipt(ctx context.Context, r model.CompletionReceipt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.receipts[m.receiptKey(r.JobID, r.Generation, r.RunnerID)] = r
	return nil
}

func (m *memStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.receipts[m.receiptKey(jobID, generation, runnerID)]
	return r, ok, nil
}

func (m *memStore) UpsertDelivery(ctx context.Context, forge, deliveryID string, runID string, payloadDigest string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deliveries[forge+"/"+deliveryID] = runID + "/" + payloadDigest
	return nil
}

func (m *memStore) FindDelivery(ctx context.Context, forge, deliveryID string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.deliveries[forge+"/"+deliveryID]
	return v, ok, nil
}

func (m *memStore) TryAcquireLeadership(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return true, nil
}

func (m *memStore) ReleaseLeadership(ctx context.Context, key string) error { return nil }

func (m *memStore) Migrate(ctx context.Context) error { return nil }

func (m *memStore) SchemaVersion(ctx context.Context) (int, error) { return 1, nil }

func (m *memStore) receiptKey(jobID string, generation int64, runnerID string) string {
	return fmt.Sprintf("%s|%d|%s", jobID, generation, runnerID)
}
