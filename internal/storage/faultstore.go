package storage

import (
	"context"
	"fmt"
	"sort"
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

var (
	_ OutboxStore           = (*FaultyStore)(nil)
	_ ScheduleStore         = (*FaultyStore)(nil)
	_ DeploymentStore       = (*FaultyStore)(nil)
	_ SnapshotStore         = (*FaultyStore)(nil)
	_ ArtifactContractStore = (*FaultyStore)(nil)
	_ QueueReasonStore      = (*FaultyStore)(nil)
)

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

func (f *FaultyStore) ListJobsByEnvironment(ctx context.Context, repoURL, environment string) ([]model.Job, error) {
	return f.Inner.ListJobsByEnvironment(ctx, repoURL, environment)
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

// ---------------------------------------------------------------------------
// DB-mode extension stores. The Inner Store must also implement these
// interfaces (the fault-injection memStore does); the assertions panic
// loudly if a non-extended inner is ever used with the extension methods.
// ---------------------------------------------------------------------------

func (f *FaultyStore) OutboxAppend(ctx context.Context, e OutboxItem) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(OutboxStore).OutboxAppend(ctx, e)
}

func (f *FaultyStore) OutboxAck(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(OutboxStore).OutboxAck(ctx, id)
}

func (f *FaultyStore) OutboxPending(ctx context.Context) ([]OutboxItem, error) {
	return f.Inner.(OutboxStore).OutboxPending(ctx)
}

func (f *FaultyStore) UpsertSchedule(ctx context.Context, sc Schedule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(ScheduleStore).UpsertSchedule(ctx, sc)
}

func (f *FaultyStore) ListSchedules(ctx context.Context) ([]Schedule, error) {
	return f.Inner.(ScheduleStore).ListSchedules(ctx)
}

func (f *FaultyStore) ClaimScheduleOccurrence(ctx context.Context, scheduleID string, nominal time.Time, runID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return false, err
	}
	return f.Inner.(ScheduleStore).ClaimScheduleOccurrence(ctx, scheduleID, nominal, runID)
}

func (f *FaultyStore) ListOccurrences(ctx context.Context, scheduleID string) ([]Occurrence, error) {
	return f.Inner.(ScheduleStore).ListOccurrences(ctx, scheduleID)
}

func (f *FaultyStore) InsertDeployment(ctx context.Context, d model.Deployment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(DeploymentStore).InsertDeployment(ctx, d)
}

func (f *FaultyStore) ListDeploymentsByRun(ctx context.Context, runID string) ([]model.Deployment, error) {
	return f.Inner.(DeploymentStore).ListDeploymentsByRun(ctx, runID)
}

func (f *FaultyStore) UpdateDeploymentStatus(ctx context.Context, id string, status model.Status, finishedAt *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(DeploymentStore).UpdateDeploymentStatus(ctx, id, status, finishedAt)
}

func (f *FaultyStore) InsertSnapshotRecord(ctx context.Context, rec model.SnapshotRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(SnapshotStore).InsertSnapshotRecord(ctx, rec)
}

func (f *FaultyStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	return f.Inner.(SnapshotStore).ListSnapshotsByRun(ctx, runID)
}

func (f *FaultyStore) InsertJobContracts(ctx context.Context, jobID string, contracts map[string]ArtifactContract) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(ArtifactContractStore).InsertJobContracts(ctx, jobID, contracts)
}

func (f *FaultyStore) GetJobContracts(ctx context.Context, jobID string) (map[string]ArtifactContract, bool, error) {
	return f.Inner.(ArtifactContractStore).GetJobContracts(ctx, jobID)
}

func (f *FaultyStore) SetQueueReasons(ctx context.Context, reasons map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(QueueReasonStore).SetQueueReasons(ctx, reasons)
}

// memStore is a fully functional in-memory Store used as the fault-free
// baseline underneath FaultyStore in fault-injection tests.
type memStore struct {
	mu          sync.Mutex
	runs        map[string]model.Run
	jobs        map[string]model.Job
	runners     map[string]model.Runner
	receipts    map[string]model.CompletionReceipt
	audit       []model.AuditEvent
	logs        []model.LogEntry
	artifacts   []model.ArtifactRecord
	reports     []model.TestReport
	deliveries  map[string]string
	outbox      []OutboxItem
	schedules   map[string]Schedule
	occurrences map[string]map[time.Time]string
	deployments []model.Deployment
	snapshots   []model.SnapshotRecord
	contracts   map[string]map[string]ArtifactContract
}

func newMemStore() *memStore {
	return &memStore{
		runs:        map[string]model.Run{},
		jobs:        map[string]model.Job{},
		runners:     map[string]model.Runner{},
		receipts:    map[string]model.CompletionReceipt{},
		deliveries:  map[string]string{},
		schedules:   map[string]Schedule{},
		occurrences: map[string]map[time.Time]string{},
		contracts:   map[string]map[string]ArtifactContract{},
	}
}

var _ Store = (*memStore)(nil)

var (
	_ OutboxStore           = (*memStore)(nil)
	_ ScheduleStore         = (*memStore)(nil)
	_ DeploymentStore       = (*memStore)(nil)
	_ SnapshotStore         = (*memStore)(nil)
	_ ArtifactContractStore = (*memStore)(nil)
	_ QueueReasonStore      = (*memStore)(nil)
)

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

func (m *memStore) ListJobsByEnvironment(ctx context.Context, repoURL, environment string) ([]model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.Job{}
	for _, j := range m.jobs {
		if j.Environment == environment && j.RepoURL == repoURL {
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

// ---------------------------------------------------------------------------
// DB-mode extension stores (in-memory)
// ---------------------------------------------------------------------------

func (m *memStore) OutboxAppend(ctx context.Context, e OutboxItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outbox = append(m.outbox, e)
	return nil
}

func (m *memStore) OutboxAck(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.outbox[:0]
	for _, it := range m.outbox {
		if it.ID != id {
			out = append(out, it)
		}
	}
	m.outbox = out
	return nil
}

func (m *memStore) OutboxPending(ctx context.Context) ([]OutboxItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]OutboxItem(nil), m.outbox...), nil
}

func (m *memStore) UpsertSchedule(ctx context.Context, sc Schedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sc.CreatedAt.IsZero() {
		if prev, ok := m.schedules[sc.ID]; ok {
			sc.CreatedAt = prev.CreatedAt
		}
	}
	m.schedules[sc.ID] = sc
	return nil
}

func (m *memStore) ListSchedules(ctx context.Context) ([]Schedule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Schedule, 0, len(m.schedules))
	for _, sc := range m.schedules {
		out = append(out, sc)
	}
	return out, nil
}

func (m *memStore) ClaimScheduleOccurrence(ctx context.Context, scheduleID string, nominal time.Time, runID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byNominal, ok := m.occurrences[scheduleID]
	if !ok {
		byNominal = map[time.Time]string{}
		m.occurrences[scheduleID] = byNominal
	}
	if existing, ok := byNominal[nominal]; ok {
		return existing == runID, nil
	}
	byNominal[nominal] = runID
	return true, nil
}

func (m *memStore) ListOccurrences(ctx context.Context, scheduleID string) ([]Occurrence, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byNominal := m.occurrences[scheduleID]
	out := make([]Occurrence, 0, len(byNominal))
	for nominal, runID := range byNominal {
		out = append(out, Occurrence{ScheduleID: scheduleID, Nominal: nominal, RunID: runID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nominal.Before(out[j].Nominal) })
	return out, nil
}

func (m *memStore) InsertDeployment(ctx context.Context, d model.Deployment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deployments = append(m.deployments, d)
	return nil
}

func (m *memStore) ListDeploymentsByRun(ctx context.Context, runID string) ([]model.Deployment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.Deployment{}
	for _, d := range m.deployments {
		if d.RunID == runID {
			out = append(out, d)
		}
	}
	return out, nil
}

func (m *memStore) UpdateDeploymentStatus(ctx context.Context, id string, status model.Status, finishedAt *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, d := range m.deployments {
		if d.ID != id {
			continue
		}
		d.Status = status
		if finishedAt != nil {
			d.FinishedAt = finishedAt
		}
		m.deployments[i] = d
		return nil
	}
	return ErrNotFound
}

func (m *memStore) InsertSnapshotRecord(ctx context.Context, rec model.SnapshotRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshots = append(m.snapshots, rec)
	return nil
}

func (m *memStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.SnapshotRecord{}
	for _, rec := range m.snapshots {
		if rec.RunID == runID {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (m *memStore) InsertJobContracts(ctx context.Context, jobID string, contracts map[string]ArtifactContract) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[jobID]; !ok {
		return ErrNotFound
	}
	cp := make(map[string]ArtifactContract, len(contracts))
	for k, v := range contracts {
		cp[k] = v
	}
	m.contracts[jobID] = cp
	return nil
}

func (m *memStore) GetJobContracts(ctx context.Context, jobID string) (map[string]ArtifactContract, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.contracts[jobID]
	if !ok {
		return nil, false, nil
	}
	cp := make(map[string]ArtifactContract, len(c))
	for k, v := range c {
		cp[k] = v
	}
	return cp, true, nil
}

func (m *memStore) SetQueueReasons(ctx context.Context, reasons map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, reason := range reasons {
		if j, ok := m.jobs[id]; ok {
			j.QueueReason = reason
			m.jobs[id] = j
		}
	}
	return nil
}
