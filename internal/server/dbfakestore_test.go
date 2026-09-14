package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// dbFakeStore is a compact behavioral storage.Store for DB-mode server
// tests: a statuses map plus receipts, with recorded scheduler-facing calls.
// It also implements the storage extension interfaces (OutboxStore,
// ScheduleStore, DeploymentStore, SnapshotStore, ArtifactContractStore,
// QueueReasonStore) so DB-mode server tests exercise the durable paths.
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

	outboxItems      []storage.OutboxItem
	outboxAcked      []string
	schedules        map[string]storage.Schedule
	occurrences      map[string][]storage.Occurrence
	deployments      map[string]model.Deployment
	snapshots        []model.SnapshotRecord
	contracts        map[string]map[string]storage.ArtifactContract
	queueReasons     map[string]string
	queueReasonsErrs int
	downstreamLinks  map[string]storage.DownstreamLink

	leaderOK  bool
	leaderErr error
	schemaErr error

	insertRunCalls []model.Run
	insertJobCalls []model.Job
	acquireCalls   []acquireArgs
	heartbeatCalls []heartbeatArgs
	completeCalls  []completeArgs
	cancelRunCalls []cancelRunArgs
	updateJobCalls []model.Job
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
var _ storage.OutboxStore = (*dbFakeStore)(nil)
var _ storage.ScheduleStore = (*dbFakeStore)(nil)
var _ storage.DeploymentStore = (*dbFakeStore)(nil)
var _ storage.SnapshotStore = (*dbFakeStore)(nil)
var _ storage.ArtifactContractStore = (*dbFakeStore)(nil)
var _ storage.QueueReasonStore = (*dbFakeStore)(nil)
var _ storage.DynamicStore = (*dbFakeStore)(nil)
var _ storage.DownstreamStore = (*dbFakeStore)(nil)
var _ storage.UsageStore = (*dbFakeStore)(nil)
var _ storage.RunDownstreamStore = (*dbFakeStore)(nil)
var _ storage.ArtifactLookupStore = (*dbFakeStore)(nil)
var _ storage.RunnerJobStore = (*dbFakeStore)(nil)

func newDBFakeStore() *dbFakeStore {
	return &dbFakeStore{
		runs:            map[string]model.Run{},
		jobs:            map[string]model.Job{},
		runners:         map[string]model.Runner{},
		receipts:        map[string]model.CompletionReceipt{},
		schedules:       map[string]storage.Schedule{},
		occurrences:     map[string][]storage.Occurrence{},
		deployments:     map[string]model.Deployment{},
		contracts:       map[string]map[string]storage.ArtifactContract{},
		queueReasons:    map[string]string{},
		downstreamLinks: map[string]storage.DownstreamLink{},
		leaderOK:        true,
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

func (f *dbFakeStore) ListJobsByRunner(ctx context.Context, runnerID string) ([]model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.Job{}
	for _, j := range f.jobs {
		if j.Status == model.StatusRunning && j.LeaseRunnerID == runnerID {
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

// ---------------------------------------------------------------------------
// storage extension interfaces
// ---------------------------------------------------------------------------

func (f *dbFakeStore) OutboxAppend(ctx context.Context, e storage.OutboxItem) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outboxItems = append(f.outboxItems, e)
	return nil
}

func (f *dbFakeStore) OutboxAck(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outboxAcked = append(f.outboxAcked, id)
	kept := f.outboxItems[:0]
	for _, it := range f.outboxItems {
		if it.ID != id {
			kept = append(kept, it)
		}
	}
	f.outboxItems = kept
	return nil
}

func (f *dbFakeStore) OutboxPending(ctx context.Context) ([]storage.OutboxItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]storage.OutboxItem(nil), f.outboxItems...), nil
}

func (f *dbFakeStore) UpsertSchedule(ctx context.Context, sc storage.Schedule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.schedules[sc.ID] = sc
	return nil
}

func (f *dbFakeStore) ListSchedules(ctx context.Context) ([]storage.Schedule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]storage.Schedule, 0, len(f.schedules))
	for _, sc := range f.schedules {
		out = append(out, sc)
	}
	return out, nil
}

func (f *dbFakeStore) ClaimScheduleOccurrence(ctx context.Context, scheduleID string, nominal time.Time, runID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range f.occurrences[scheduleID] {
		if o.Nominal.Equal(nominal) {
			return o.RunID == runID, nil
		}
	}
	f.occurrences[scheduleID] = append(f.occurrences[scheduleID], storage.Occurrence{ScheduleID: scheduleID, Nominal: nominal, RunID: runID})
	return true, nil
}

func (f *dbFakeStore) ListOccurrences(ctx context.Context, scheduleID string) ([]storage.Occurrence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]storage.Occurrence(nil), f.occurrences[scheduleID]...), nil
}

func (f *dbFakeStore) InsertDeployment(ctx context.Context, d model.Deployment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deployments[d.ID] = d
	return nil
}

func (f *dbFakeStore) ListDeploymentsByRun(ctx context.Context, runID string) ([]model.Deployment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.Deployment{}
	for _, d := range f.deployments {
		if d.RunID == runID {
			out = append(out, d)
		}
	}
	return out, nil
}

func (f *dbFakeStore) UpdateDeploymentStatus(ctx context.Context, id string, status model.Status, finishedAt *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deployments[id]
	if !ok {
		return storage.ErrNotFound
	}
	d.Status = status
	if finishedAt != nil {
		d.FinishedAt = finishedAt
	}
	f.deployments[id] = d
	return nil
}

func (f *dbFakeStore) InsertSnapshotRecord(ctx context.Context, rec model.SnapshotRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshots = append(f.snapshots, rec)
	return nil
}

func (f *dbFakeStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.SnapshotRecord{}
	for _, rec := range f.snapshots {
		if rec.RunID == runID {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (f *dbFakeStore) InsertJobContracts(ctx context.Context, jobID string, contracts map[string]storage.ArtifactContract) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.contracts[jobID] = contracts
	return nil
}

func (f *dbFakeStore) GetJobContracts(ctx context.Context, jobID string) (map[string]storage.ArtifactContract, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.contracts[jobID]
	if !ok {
		return nil, false, nil
	}
	return m, true, nil
}

func (f *dbFakeStore) SetQueueReasons(ctx context.Context, reasons map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.queueReasonsErrs > 0 {
		f.queueReasonsErrs--
		return fmt.Errorf("queue reasons: injected failure")
	}
	for id, reason := range reasons {
		f.queueReasons[id] = reason
		if j, ok := f.jobs[id]; ok {
			j.QueueReason = reason
			f.jobs[id] = j
		}
	}
	return nil
}

func (f *dbFakeStore) queueReason(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queueReasons[id]
}

// ---------------------------------------------------------------------------
// extension stores: dynamic generation, downstream claims, usage, artifact
// lookup, run downstream tracking
// ---------------------------------------------------------------------------

func (f *dbFakeStore) InsertGeneratedJobs(ctx context.Context, parentJobID string, depth int, jobs map[string]model.Job, deps map[string][]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.jobs[parentJobID]; !ok {
		return storage.ErrNotFound
	}
	for id, j := range jobs {
		f.jobs[id] = j
	}
	return nil
}

func (f *dbFakeStore) InsertDownstreamLink(ctx context.Context, l storage.DownstreamLink) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := l.ParentJobID + "\x00" + l.TargetRepo + "\x00" + l.TargetRef
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	if _, ok := f.downstreamLinks[key]; ok {
		return nil
	}
	f.downstreamLinks[key] = l
	return nil
}

func (f *dbFakeStore) GetDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (storage.DownstreamLink, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.downstreamLinks[parentJobID+"\x00"+targetRepo+"\x00"+targetRef]
	return l, ok, nil
}

func (f *dbFakeStore) MarkDownstreamLaunched(ctx context.Context, parentJobID, targetRepo, targetRef, childRunID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := parentJobID + "\x00" + targetRepo + "\x00" + targetRef
	l, ok := f.downstreamLinks[key]
	if !ok || l.ChildRunID != "" {
		return nil
	}
	l.ChildRunID = childRunID
	f.downstreamLinks[key] = l
	return nil
}

func (f *dbFakeStore) RecentUsage(ctx context.Context, since time.Time) (float64, float64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var cost, energy float64
	for _, j := range f.jobs {
		if j.FinishedAt == nil || j.FinishedAt.Before(since) {
			continue
		}
		cost += j.Cost
		energy += j.EnergyWh
	}
	return cost, energy, nil
}

func (f *dbFakeStore) AppendDownstreamRun(ctx context.Context, runID, childRunID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runs[runID]
	if !ok {
		return storage.ErrNotFound
	}
	for _, id := range r.DownstreamRuns {
		if id == childRunID {
			return nil
		}
	}
	r.DownstreamRuns = append(r.DownstreamRuns, childRunID)
	f.runs[runID] = r
	return nil
}

func (f *dbFakeStore) ReopenRunForChildren(ctx context.Context, runID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runs[runID]
	if !ok {
		return storage.ErrNotFound
	}
	if r.Status != model.StatusSuccess {
		return nil
	}
	r.Status = model.StatusRunning
	r.FinishedAt = nil
	f.runs[runID] = r
	return nil
}

func (f *dbFakeStore) GetArtifact(ctx context.Context, id string) (model.ArtifactRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.artifacts {
		if a.ID == id {
			return a, nil
		}
	}
	return model.ArtifactRecord{}, storage.ErrNotFound
}
