package scheduler

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
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

	profiles     map[string]model.RunnerProfile
	certProfiles map[string]string

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

	// Transactional recovery/revocation calls: the scheduler must issue
	// exactly ONE of these per transition (never the retired multi-step
	// UpdateJob+ReleaseRunnerJob sequence).
	revokeCalls  []revokeCall
	recoverCalls []recoverCall
	expireCalls  []expireCall
	revokeErr    error
	recoverErr   error
	expireErr    error

	// quotaReservations backs the storage.QuotaCounterStore contract so the
	// queue-timeout/lease paths that maintain reserved counters can be
	// exercised in scheduler tests (clamped at zero, like every store).
	quotaReservations map[string][2]int

	// compiledCalls records every atomic enqueue request the scheduler
	// issues, so tests can assert the run/jobs/deps/supersede payload.
	compiledCalls []storage.InsertCompiledRunRequest
	// compiledFailAfterOps, when > 0, makes the next InsertCompiledRun fail
	// (one-shot) after staging that many operations (superseded
	// cancellations first, then enqueued jobs): a mid-enqueue storage fault
	// that must leave zero rows.
	compiledFailAfterOps int
	compiledFailErr      error
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

type revokeCall struct {
	RunnerID string
	Reason   string
}

type recoverCall struct {
	JobID      string
	Generation int64
}

type expireCall struct {
	JobID    string
	Deadline time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		runs:         map[string]model.Run{},
		jobs:         map[string]model.Job{},
		runners:      map[string]model.Runner{},
		receipts:     map[string]model.CompletionReceipt{},
		profiles:     map[string]model.RunnerProfile{},
		certProfiles: map[string]string{},
	}
}

var _ storage.Store = (*fakeStore)(nil)
var _ storage.ProfileStore = (*fakeStore)(nil)
var _ storage.QuotaCounterStore = (*fakeStore)(nil)
var _ storage.RunEnqueueStore = (*fakeStore)(nil)
var _ storage.RecoveryStore = (*fakeStore)(nil)

// InsertCompiledRun applies the atomic enqueue in memory: the run, its jobs
// (with the request's authoritative dependency edges), the supersede
// cancellations and their dependent/run recomputation commit together under
// f.mu, mirroring the SQL transaction. compiledFailAfterOps injects a
// one-shot failure after that many staged writes, so tests can prove a
// mid-enqueue fault leaves zero rows (run included).
func (f *fakeStore) InsertCompiledRun(ctx context.Context, req storage.InsertCompiledRunRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.compiledCalls = append(f.compiledCalls, req)
	if _, dup := f.runs[req.Run.ID]; dup {
		return fmt.Errorf("storage: run %s already exists", req.Run.ID)
	}
	now := time.Now().UTC()
	staged := 0
	bumpStaged := func() error {
		if f.compiledFailAfterOps <= 0 {
			return nil
		}
		staged++
		if staged < f.compiledFailAfterOps {
			return nil
		}
		err := f.compiledFailErr
		f.compiledFailAfterOps = 0
		f.compiledFailErr = nil
		if err == nil {
			err = fmt.Errorf("storage: injected enqueue failure")
		}
		return err
	}
	type cancelStage struct {
		id         string
		job        model.Job
		wasRunning bool
		runnerID   string
	}
	cancelIDs := append([]string(nil), req.CancelPrevious...)
	if req.Supersede != nil {
		cancelIDs = append(cancelIDs, f.supersededJobIDsLocked(req.Supersede, req.Run.ID)...)
	}
	cancelStages := make([]cancelStage, 0, len(cancelIDs))
	seen := map[string]bool{}
	for _, id := range cancelIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		j, ok := f.jobs[id]
		if !ok || j.Status.Terminal() {
			continue
		}
		wasRunning := j.Status == model.StatusRunning
		runnerID := j.LeaseRunnerID
		j.Status = model.StatusCancelled
		j.Error = "superseded by run " + req.Run.ID
		j.FinishedAt = &now
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		cancelStages = append(cancelStages, cancelStage{id: id, job: j, wasRunning: wasRunning, runnerID: runnerID})
		if err := bumpStaged(); err != nil {
			return err
		}
	}
	type jobStage struct {
		id  string
		job model.Job
	}
	jobStages := make([]jobStage, 0, len(req.Jobs))
	for id, j := range req.Jobs {
		if deps, ok := req.Deps[id]; ok {
			j.Needs = append([]string(nil), deps...)
		}
		jobStages = append(jobStages, jobStage{id: id, job: j})
		if err := bumpStaged(); err != nil {
			return err
		}
	}
	// Commit: the superseded cancellations land first, then their dependents
	// are re-evaluated and their runs cancelled, and only then is the new
	// run published — one indivisible step under f.mu.
	cancelled := map[string]bool{}
	cancelledRuns := map[string]bool{}
	for _, st := range cancelStages {
		f.jobs[st.id] = st.job
		cancelled[st.id] = true
		if st.job.RunID != "" {
			cancelledRuns[st.job.RunID] = true
		}
		f.audit = append(f.audit, model.AuditEvent{ID: st.id + "|audit", Action: "job.superseded", Actor: "scheduler", RunID: st.job.RunID, JobID: st.id, Message: "cancelled", CreatedAt: now})
		if st.wasRunning && st.runnerID != "" {
			f.releaseRunnerSlotLocked(st.runnerID, st.id)
		}
	}
	f.recomputeDependentsLocked(cancelled, now)
	for rid := range cancelledRuns {
		if r, ok := f.runs[rid]; ok && !r.Status.Terminal() {
			r.Status = model.StatusCancelled
			r.FinishedAt = &now
			f.runs[rid] = r
		}
	}
	f.insertRunCalls = append(f.insertRunCalls, req.Run)
	f.runs[req.Run.ID] = req.Run
	for _, st := range jobStages {
		f.jobs[st.id] = st.job
	}
	return nil
}

// supersededJobIDsLocked resolves a supersede policy against the currently
// committed runs (caller holds f.mu) by CANONICAL repository identity, like
// the real stores.
func (f *fakeStore) supersededJobIDsLocked(p *storage.SupersedePolicy, newRunID string) []string {
	repoID := strings.TrimSpace(p.RepoID)
	if repoID == "" || strings.TrimSpace(p.ConcurrencyGroup) == "" {
		return nil
	}
	out := []string{}
	for id, r := range f.runs {
		if id == newRunID || r.Status.Terminal() {
			continue
		}
		if storage.RepoIDForRun(r) != repoID || r.ConcurrencyGroup != p.ConcurrencyGroup {
			continue
		}
		for jid, j := range f.jobs {
			if j.RunID != id || j.Status.Terminal() {
				continue
			}
			out = append(out, jid)
		}
	}
	return out
}

// recomputeDependentsLocked re-evaluates queued/waiting jobs that need a
// cancelled job, blocking them when their condition does not allow the
// outcome (caller holds f.mu).
func (f *fakeStore) recomputeDependentsLocked(cancelled map[string]bool, now time.Time) {
	if len(cancelled) == 0 {
		return
	}
	for id, j := range f.jobs {
		if j.Status != model.StatusQueued && j.Status != model.StatusWaitingApproval {
			continue
		}
		needsCancelled := false
		for _, dep := range j.Needs {
			if cancelled[dep] {
				needsCancelled = true
				break
			}
		}
		if !needsCancelled {
			continue
		}
		ready, outcome := DependencyOutcome(j.Needs, nil, func(dep string) (model.Status, bool) {
			d, ok := f.jobs[dep]
			return d.Status, ok
		})
		if !ready {
			continue
		}
		j.DependencyStatus = outcome
		if outcome != model.StatusSuccess && !ConditionAllows(j.Condition, outcome) {
			j.Status = model.StatusBlocked
			j.Error = "dependency failed"
			j.FinishedAt = &now
		}
		f.jobs[id] = j
	}
}

// releaseRunnerSlotLocked splices one job ID out of a runner's active set and
// recomputes busy/current_job (caller holds f.mu).
func (f *fakeStore) releaseRunnerSlotLocked(runnerID, jobID string) {
	r, ok := f.runners[runnerID]
	if !ok {
		return
	}
	active := r.ActiveJobs[:0]
	for _, id := range r.ActiveJobs {
		if id != jobID {
			active = append(active, id)
		}
	}
	r.ActiveJobs = active
	if len(r.ActiveJobs) > 0 && r.CurrentJob == jobID {
		r.CurrentJob = r.ActiveJobs[0]
	}
	if len(r.ActiveJobs) == 0 {
		r.CurrentJob = ""
	}
	r.Busy = r.Capacity > 0 && len(r.ActiveJobs) >= r.Capacity
	f.runners[runnerID] = r
}

// fakeAdjustQuotaLocked shifts the fake's reserved counters (caller holds
// f.mu), mirroring the storage counter updates (clamped at zero).
func (f *fakeStore) fakeAdjustQuotaLocked(repoID string, runningDelta, queuedDelta int) {
	if f.quotaReservations == nil {
		f.quotaReservations = map[string][2]int{}
	}
	for _, key := range storage.QuotaKeys(repoID) {
		if key == "" {
			continue
		}
		c := f.quotaReservations[key]
		c[0] += runningDelta
		if c[0] < 0 {
			c[0] = 0
		}
		c[1] += queuedDelta
		if c[1] < 0 {
			c[1] = 0
		}
		f.quotaReservations[key] = c
	}
}

// recomputeRunLocked mirrors storage's run aggregation from the fake's job
// states (caller holds f.mu).
func (f *fakeStore) recomputeRunLocked(runID string, now time.Time) {
	r, ok := f.runs[runID]
	if !ok || r.Status == model.StatusCancelled {
		return
	}
	var total, terminal int
	var anyRunning, anyFailure, anyCancelled, anyWaiting bool
	var firstStart, lastFinish *time.Time
	for _, j := range f.jobs {
		if j.RunID != runID {
			continue
		}
		total++
		if j.StartedAt != nil && (firstStart == nil || j.StartedAt.Before(*firstStart)) {
			t := *j.StartedAt
			firstStart = &t
		}
		if j.Status.Terminal() {
			terminal++
			if j.FinishedAt != nil && (lastFinish == nil || j.FinishedAt.After(*lastFinish)) {
				t := *j.FinishedAt
				lastFinish = &t
			}
		}
		switch j.Status {
		case model.StatusRunning:
			anyRunning = true
		case model.StatusFailure, model.StatusBlocked:
			anyFailure = true
		case model.StatusCancelled:
			anyCancelled = true
		case model.StatusWaitingApproval:
			anyWaiting = true
		}
	}
	if total == 0 {
		return
	}
	switch {
	case terminal == total:
		switch {
		case anyFailure:
			r.Status = model.StatusFailure
		case anyCancelled:
			r.Status = model.StatusCancelled
		default:
			r.Status = model.StatusSuccess
		}
		r.FinishedAt = lastFinish
		if r.FinishedAt == nil {
			n := now.UTC()
			r.FinishedAt = &n
		}
	case anyRunning:
		r.Status = model.StatusRunning
	case anyWaiting:
		r.Status = model.StatusWaitingApproval
	default:
		r.Status = model.StatusQueued
	}
	if r.StartedAt == nil && firstStart != nil {
		r.StartedAt = firstStart
	}
	f.runs[runID] = r
}

// RevokeRunnerLeases is the transactional kill switch on the fake store: the
// whole runner-scoped transition commits under f.mu, mirroring the real
// RecoveryStore contract.
func (f *fakeStore) RevokeRunnerLeases(ctx context.Context, runnerID, reason string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls = append(f.revokeCalls, revokeCall{RunnerID: runnerID, Reason: reason})
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	now := time.Now().UTC()
	ids := []string{}
	for id, j := range f.jobs {
		if j.Status == model.StatusRunning && j.LeaseRunnerID == runnerID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	changed := map[string]bool{}
	runIDs := map[string]bool{}
	for _, id := range ids {
		j := f.jobs[id]
		requeue := j.Attempts <= j.MaxInfraRetries
		if requeue {
			j.Status = model.StatusQueued
			j.Error = reason + "; retrying"
		} else {
			j.Status = model.StatusCancelled
			j.Error = reason
			j.FinishedAt = &now
		}
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		f.jobs[id] = j
		if requeue {
			f.fakeAdjustQuotaLocked(storage.RepoIDForJob(j), -1, 1)
		} else {
			f.fakeAdjustQuotaLocked(storage.RepoIDForJob(j), -1, 0)
		}
		action := "job.runner_disabled_cancelled"
		if requeue {
			action = "job.runner_disabled_requeued"
		}
		f.audit = append(f.audit, model.AuditEvent{ID: id + "|" + action, Action: action, Actor: "admin", RunID: j.RunID, JobID: j.ID, Message: reason, CreatedAt: now})
		changed[id] = true
		if j.RunID != "" {
			runIDs[j.RunID] = true
		}
	}
	for _, id := range ids {
		f.releaseRunnerSlotLocked(runnerID, id)
		if r, ok := f.runners[runnerID]; ok {
			r.Failed++
			r.LastSeen = now
			f.runners[runnerID] = r
		}
	}
	f.recomputeDependentsLocked(changed, now)
	for runID := range runIDs {
		f.recomputeRunLocked(runID, now)
	}
	return ids, nil
}

// RecoverExpiredLease is the single expired-lease transition on the fake
// store, mirroring the real RecoveryStore contract.
func (f *fakeStore) RecoverExpiredLease(ctx context.Context, jobID string, expectedGeneration int64, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recoverCalls = append(f.recoverCalls, recoverCall{JobID: jobID, Generation: expectedGeneration})
	if f.recoverErr != nil {
		return f.recoverErr
	}
	j, ok := f.jobs[jobID]
	if !ok {
		return storage.ErrNotFound
	}
	if j.Status != model.StatusRunning || j.LeaseGeneration != expectedGeneration {
		return nil
	}
	if j.LeaseExpiresAt != nil && j.LeaseExpiresAt.After(now) {
		return nil
	}
	requeue := j.Attempts <= j.MaxInfraRetries
	if requeue {
		j.Status = model.StatusQueued
		j.Error = "runner lease expired; retrying"
	} else {
		j.Status = model.StatusFailure
		j.Error = "runner lease expired and infrastructure retry budget exhausted"
		j.FinishedAt = &now
	}
	runnerID := j.LeaseRunnerID
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	f.jobs[jobID] = j
	if requeue {
		f.fakeAdjustQuotaLocked(storage.RepoIDForJob(j), -1, 1)
	} else {
		f.fakeAdjustQuotaLocked(storage.RepoIDForJob(j), -1, 0)
	}
	if runnerID != "" {
		f.releaseRunnerSlotLocked(runnerID, jobID)
		if r, ok := f.runners[runnerID]; ok {
			r.Failed++
			r.LastSeen = now
			f.runners[runnerID] = r
		}
	}
	action := "job.lease_expired"
	msg := "job requeued after lost runner"
	if !requeue {
		action = "job.lost_runner"
		msg = j.Error
	}
	f.audit = append(f.audit, model.AuditEvent{ID: jobID + "|" + action, Action: action, Actor: "scheduler", RunID: j.RunID, JobID: j.ID, Message: msg, CreatedAt: now})
	f.recomputeDependentsLocked(map[string]bool{jobID: true}, now)
	f.recomputeRunLocked(j.RunID, now)
	return nil
}

// ExpireQueuedJob is the single queue-timeout transition on the fake store,
// mirroring the real RecoveryStore contract.
func (f *fakeStore) ExpireQueuedJob(ctx context.Context, jobID string, deadline time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expireCalls = append(f.expireCalls, expireCall{JobID: jobID, Deadline: deadline})
	if f.expireErr != nil {
		return f.expireErr
	}
	j, ok := f.jobs[jobID]
	if !ok {
		return storage.ErrNotFound
	}
	if j.Status != model.StatusQueued && j.Status != model.StatusWaitingApproval {
		return nil
	}
	now := time.Now().UTC()
	eff := storage.QueueDeadlineFor(j)
	if eff == nil || eff.After(deadline) || deadline.After(now) {
		return nil
	}
	j.Status = model.StatusCancelled
	j.Error = "queue timeout"
	j.FinishedAt = &now
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	f.jobs[jobID] = j
	f.fakeAdjustQuotaLocked(storage.RepoIDForJob(j), 0, -1)
	f.audit = append(f.audit, model.AuditEvent{ID: jobID + "|job.queue_timeout", Action: "job.queue_timeout", Actor: "scheduler", RunID: j.RunID, JobID: j.ID, Message: "job cancelled after queue deadline", CreatedAt: now})
	f.recomputeDependentsLocked(map[string]bool{jobID: true}, now)
	f.recomputeRunLocked(j.RunID, now)
	return nil
}

// AdjustQuotaCounter shifts the reserved counters for the key pair,
// clamping at zero exactly like the SQL/memStore counter updates.
func (f *fakeStore) AdjustQuotaCounter(ctx context.Context, repoKey, teamKey string, runningDelta, queuedDelta int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.quotaReservations == nil {
		f.quotaReservations = map[string][2]int{}
	}
	for _, key := range []string{repoKey, teamKey} {
		if key == "" {
			continue
		}
		c := f.quotaReservations[key]
		c[0] += runningDelta
		if c[0] < 0 {
			c[0] = 0
		}
		c[1] += queuedDelta
		if c[1] < 0 {
			c[1] = 0
		}
		f.quotaReservations[key] = c
	}
	return nil
}

// QuotaCounts reads the summed reserved counters for the key pair.
func (f *fakeStore) QuotaCounts(ctx context.Context, repoKey, teamKey string) (int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var running, queued int
	for _, key := range []string{repoKey, teamKey} {
		if key == "" {
			continue
		}
		c := f.quotaReservations[key]
		running += c[0]
		queued += c[1]
	}
	return running, queued, nil
}

// quotaQueued reports one key's reserved queued counter.
func (f *fakeStore) quotaQueued(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.quotaReservations[key][1]
}

// quotaRunning reports one key's reserved running counter.
func (f *fakeStore) quotaRunning(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.quotaReservations[key][0]
}

func (f *fakeStore) UpsertProfile(ctx context.Context, p model.RunnerProfile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.profiles[p.ID] = p
	return nil
}

func (f *fakeStore) GetProfile(ctx context.Context, id string) (model.RunnerProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.profiles[id]
	if !ok {
		return model.RunnerProfile{}, storage.ErrNotFound
	}
	return p, nil
}

func (f *fakeStore) ListProfiles(ctx context.Context) ([]model.RunnerProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]model.RunnerProfile, 0, len(f.profiles))
	for _, p := range f.profiles {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakeStore) BindCertProfile(ctx context.Context, serial, profileID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certProfiles[serial] = profileID
	return nil
}

func (f *fakeStore) ProfileForSerial(ctx context.Context, serial string) (model.RunnerProfile, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.certProfiles[serial]
	if !ok {
		return model.RunnerProfile{}, false, nil
	}
	p, ok := f.profiles[id]
	return p, ok, nil
}

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

// ListJobsByEnvironment mirrors the real store: jobs are matched on the
// CANONICAL repository identity (stored RepoID, legacy URL + full-name
// fallback), so HTTPS and SSH spellings of one repository share one key.
func (f *fakeStore) ListJobsByEnvironment(ctx context.Context, repoID, environment string) ([]model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.Job{}
	for _, j := range f.jobs {
		if j.Environment == environment && storage.RepoIDForJob(j) == repoID {
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
	now := time.Now().UTC()
	j.Status = model.StatusRunning
	j.Attempts++
	if j.StartedAt == nil {
		j.StartedAt = &now
	}
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
