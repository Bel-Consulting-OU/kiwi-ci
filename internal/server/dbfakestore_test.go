package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// dbFakeStore is a compact behavioral storage.Store for DB-mode server
// tests: a statuses map plus receipts, with recorded scheduler-facing calls.
// It also implements the storage extension interfaces (OutboxStore,
// ScheduleStore, DeploymentStore, SnapshotStore, ArtifactContractStore,
// QueueReasonStore) so DB-mode server tests exercise the durable paths.
type dbFakeStore struct {
	mu         sync.Mutex
	checkRuns  map[string]string
	logBatches map[string]string
	runs       map[string]model.Run
	jobs       map[string]model.Job
	runners    map[string]model.Runner
	receipts   map[string]model.CompletionReceipt
	audit      []model.AuditEvent
	logs       []model.LogEntry
	artifacts  []model.ArtifactRecord
	reports    []model.TestReport

	outboxItems  []storage.OutboxItem
	outboxAcked  []string
	outboxClaims map[string]fakeOutboxClaim
	// outboxMeta mirrors migration 0015's attempts/last_error/next_attempt_at/
	// dead_lettered_at retry state.
	outboxMeta map[string]fakeOutboxMeta
	// forgeState mirrors migration 0018's forge_check_state delivered
	// watermark per logical key.
	forgeState map[string]int64
	fragments  map[string]storage.GeneratedFragmentReceipt
	// outboxAppendErr/outboxAckErr inject durable-append/ack failures.
	outboxAppendErr error
	outboxAckErr    error
	// outboxVersionErr, when non-nil, makes OutboxEnqueueVersioned fail
	// (persistent forge-publication failure tests).
	outboxVersionErr error
	// outboxGuardErr, when non-nil, makes OutboxVersionGuard fail
	// (fail-closed dispatcher guard tests).
	outboxGuardErr   error
	schedules        map[string]storage.Schedule
	occurrences      map[string][]storage.Occurrence
	deployments      map[string]model.Deployment
	snapshots        []model.SnapshotRecord
	contracts        map[string]map[string]storage.ArtifactContract
	queueReasons     map[string]string
	queueReasonsErrs int
	downstreamLinks  map[string]storage.DownstreamLink
	deliveries       map[string]string
	quotas           map[string][2]int
	cacheMans        map[string]storage.CacheManifestRecord
	cacheManErr      error
	secretClaims     map[string]bool
	// pendingSidecars mirrors artifact_pending_sidecars (migration 0012):
	// durable pending SBOM/sigstore digests across replicas.
	pendingSidecars map[string]fakePendingSidecar
	// pendingErr, when non-nil, makes every pending-sidecar mutation fail.
	pendingErr error
	// sidecarAttachErr, when non-nil, makes SetArtifactSidecars fail
	// (fail-closed attachment tests).
	sidecarAttachErr error

	profiles     map[string]model.RunnerProfile
	certProfiles map[string]string
	runnerTokens map[string]string
	revocations  map[string]string
	grants       map[string]storage.EnrollGrantRecord

	// claimErr, when non-nil, makes ClaimSecretDelivery fail (fail-closed
	// secret delivery tests).
	claimErr error
	// contractsErr, when non-nil, makes CompleteJob's required-artifact
	// verification fail (completion rolls back, job stays running).
	contractsErr error
	// snapshotErr, when non-nil, makes InsertSnapshotRecord fail (P2-31
	// fail-closed snapshot upload tests).
	snapshotErr error
	// auditErr, when non-nil, makes AppendAudit fail (OIDC issuance
	// fail-closed tests).
	auditErr error
	// updateJobErr, when non-nil, makes UpdateJob fail. It models a store
	// failure while the completion-effect pass persists the usage marker, so
	// tests can exercise a crash window that lands BETWEEN effects.
	updateJobErr error
	// artifactInsertErr, when non-nil, makes InsertArtifactOnce fail (the
	// pending-sidecar consume ordering tests: a failed record insert must
	// leave the durable pending rows in place).
	artifactInsertErr error

	// casRefErr, when non-nil, makes every CAS-reference read path fail
	// (the CAS GC fail-closed tests).
	casRefErr error
	// casGCLeases records the held collector leases by key; casGCLeaseClaims
	// records every acquisition attempt; casGCLeaseErr injects a hard lease
	// failure.
	casGCLeases      map[string]bool
	casGCLeaseClaims []string
	casGCLeaseErr    error
	// leaderClaims records every advisory-lock key TryAcquireLeadership was
	// asked for, so tests can pin the CAS GC HA lease.
	leaderClaims []string

	// listRunsErr/getRunErr/getJobErr make the corresponding read fail with a
	// hard store error (not ErrNotFound), and the deployment knobs make the
	// deployment store fail: they drive fail-closed/500 paths.
	listRunsErr      error
	getRunErr        error
	getJobErr        error
	listJobsByRunErr error
	// countRunningErr, when non-nil, makes CountRunningJobs fail: the drain
	// count is then UNKNOWN and must never be read as zero/drained.
	countRunningErr     error
	deploymentInsertErr error
	listDeploymentsErr  error
	updateDeploymentErr error
	upsertDeliveryErr   error
	findDeliveryErr     error
	outboxPendingErr    error
	listSchedulesErr    error
	// advanceScheduleErr, when non-nil, makes AdvanceScheduleLastRun fail
	// (durable-advance failure-injection tests: the in-memory mirror must
	// stay untouched).
	advanceScheduleErr error
	cancelRunJobsErr   error
	// enqueueErr, when non-nil, is returned by InsertCompiledRun in place of
	// the in-memory enqueue.
	enqueueErr error

	leaderOK  bool
	leaderErr error
	schemaErr error

	// usageErr, when non-nil, makes RecentUsage fail (budget-state
	// fail-closed tests).
	usageErr error
	// enqueueFailOnce makes the next InsertCompiledRun fail (schedule
	// atomicity tests).
	enqueueFailOnce bool
	// enqueueFailDuringSupersede makes the next InsertCompiledRun fail while
	// the supersede cancellations are being staged (P1-7 supersession fault
	// injection): the whole enqueue must roll back, leaving the superseded
	// run untouched and the new run absent.
	enqueueFailDuringSupersede bool
	// atomicLeaseCapacity limits AcquireLeaseAtomic; <=0 means unlimited.
	atomicLeaseCapacity int
	// atomicLeaseErrs makes AcquireLeaseAtomic fail a number of times.
	atomicLeaseErrs int

	// logSeq is the identity-style log sequence counter: AppendLog ignores
	// the caller's Seq and assigns the next value, mirroring the
	// GENERATED ALWAYS AS IDENTITY column.
	logSeq int64
	// testHistoryVersion/testHistoryStats back the legacy TestHistoryStore
	// cache; testHistorySaveErr makes SaveTestHistory fail (legacy report
	// durability tests). historyAggregates/historyVersions back the
	// incremental TestHistoryAggregateStore contract (migration 0026), and
	// insertReportHistoryErr / loadRepoHistoryErr inject its failures.
	testHistoryVersion   int64
	testHistoryStats     []byte
	testHistorySaveErr   error
	testHistorySaveCalls int

	historyAggregates      map[string]map[string]storage.TestHistoryAggregate
	historyVersions        map[string]int64
	insertReportHistoryErr error
	loadRepoHistoryErr     error
	disableCertErr         error

	insertRunCalls []model.Run
	insertJobCalls []model.Job
	acquireCalls   []acquireArgs
	heartbeatCalls []heartbeatArgs
	completeCalls  []completeArgs
	cancelRunCalls []cancelRunArgs
	updateJobCalls []model.Job
	compiledCalls  []storage.InsertCompiledRunRequest
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
var _ storage.ForgeCheckStateStore = (*dbFakeStore)(nil)
var _ storage.ScheduleStore = (*dbFakeStore)(nil)
var _ storage.DeploymentStore = (*dbFakeStore)(nil)
var _ storage.SnapshotStore = (*dbFakeStore)(nil)
var _ storage.ArtifactContractStore = (*dbFakeStore)(nil)
var _ storage.QueueReasonStore = (*dbFakeStore)(nil)
var _ storage.DynamicStore = (*dbFakeStore)(nil)
var _ storage.DynamicStoreTx = (*dbFakeStore)(nil)
var _ storage.DownstreamStore = (*dbFakeStore)(nil)
var _ storage.UsageStore = (*dbFakeStore)(nil)
var _ storage.UsageOnceStore = (*dbFakeStore)(nil)
var _ storage.RunDownstreamStore = (*dbFakeStore)(nil)
var _ storage.ArtifactLookupStore = (*dbFakeStore)(nil)
var _ storage.RunnerJobStore = (*dbFakeStore)(nil)
var _ storage.RecoveryStore = (*dbFakeStore)(nil)
var _ storage.RunEnqueueStore = (*dbFakeStore)(nil)
var _ storage.AtomicLeaseStore = (*dbFakeStore)(nil)
var _ storage.QuotaCounterStore = (*dbFakeStore)(nil)
var _ storage.CacheManifestStore = (*dbFakeStore)(nil)
var _ storage.ArtifactSidecarStore = (*dbFakeStore)(nil)
var _ storage.SecretClaimStore = (*dbFakeStore)(nil)
var _ storage.SecretClaimReleaser = (*dbFakeStore)(nil)
var _ storage.ProfileStore = (*dbFakeStore)(nil)
var _ storage.RunnerTokenStore = (*dbFakeStore)(nil)
var _ storage.CertRevocationStore = (*dbFakeStore)(nil)
var _ storage.EnrollGrantStore = (*dbFakeStore)(nil)
var _ storage.TestHistoryStore = (*dbFakeStore)(nil)
var _ storage.TestHistoryAggregateStore = (*dbFakeStore)(nil)
var _ storage.RunnerDisableStore = (*dbFakeStore)(nil)
var _ storage.ArtifactIdempotentStore = (*dbFakeStore)(nil)
var _ storage.GeneratedFragmentStore = (*dbFakeStore)(nil)
var _ storage.CASReferenceStore = (*dbFakeStore)(nil)
var _ storage.CASGCLeaseStore = (*dbFakeStore)(nil)

// fakeCASGCLease is one held in-memory collector lease.
type fakeCASGCLease struct {
	store *dbFakeStore
	key   string
	once  sync.Once
}

func (l *fakeCASGCLease) Release(ctx context.Context) error {
	l.once.Do(func() {
		l.store.mu.Lock()
		delete(l.store.casGCLeases, l.key)
		l.store.mu.Unlock()
	})
	return nil
}

// TryAcquireCASGCLease implements storage.CASGCLeaseStore: the advisory
// lock is modeled as a per-key held flag and every attempt is recorded so
// tests can pin the HA lease. casGCLeaseErr injects a hard store failure.
func (f *dbFakeStore) TryAcquireCASGCLease(ctx context.Context, key string) (storage.CASGCLease, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.casGCLeaseClaims = append(f.casGCLeaseClaims, key)
	if f.casGCLeaseErr != nil {
		return nil, false, f.casGCLeaseErr
	}
	if f.casGCLeases == nil {
		f.casGCLeases = map[string]bool{}
	}
	if f.casGCLeases[key] {
		return nil, false, nil
	}
	f.casGCLeases[key] = true
	return &fakeCASGCLease{store: f, key: key}, true, nil
}

func newDBFakeStore() *dbFakeStore {
	return &dbFakeStore{
		runs:              map[string]model.Run{},
		jobs:              map[string]model.Job{},
		runners:           map[string]model.Runner{},
		receipts:          map[string]model.CompletionReceipt{},
		schedules:         map[string]storage.Schedule{},
		occurrences:       map[string][]storage.Occurrence{},
		deployments:       map[string]model.Deployment{},
		contracts:         map[string]map[string]storage.ArtifactContract{},
		queueReasons:      map[string]string{},
		downstreamLinks:   map[string]storage.DownstreamLink{},
		deliveries:        map[string]string{},
		quotas:            map[string][2]int{},
		cacheMans:         map[string]storage.CacheManifestRecord{},
		secretClaims:      map[string]bool{},
		pendingSidecars:   map[string]fakePendingSidecar{},
		outboxClaims:      map[string]fakeOutboxClaim{},
		outboxMeta:        map[string]fakeOutboxMeta{},
		forgeState:        map[string]int64{},
		fragments:         map[string]storage.GeneratedFragmentReceipt{},
		profiles:          map[string]model.RunnerProfile{},
		certProfiles:      map[string]string{},
		runnerTokens:      map[string]string{},
		revocations:       map[string]string{},
		grants:            map[string]storage.EnrollGrantRecord{},
		historyAggregates: map[string]map[string]storage.TestHistoryAggregate{},
		historyVersions:   map[string]int64{},
		leaderOK:          true,
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
	if f.getRunErr != nil {
		return model.Run{}, f.getRunErr
	}
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
	if f.listRunsErr != nil {
		return nil, f.listRunsErr
	}
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
	if f.getJobErr != nil {
		return model.Job{}, f.getJobErr
	}
	j, ok := f.jobs[id]
	if !ok {
		return model.Job{}, storage.ErrNotFound
	}
	return j, nil
}

func (f *dbFakeStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listJobsByRunErr != nil {
		return nil, f.listJobsByRunErr
	}
	out := []model.Job{}
	for _, j := range f.jobs {
		if j.RunID == runID {
			out = append(out, j)
		}
	}
	return out, nil
}

// CountRunningJobs mirrors memStore.CountRunningJobs: the in-flight count is
// the number of jobs holding a running lease, read atomically from the
// complete in-memory job map. countRunningErr injects the drain-count failure.
func (f *dbFakeStore) CountRunningJobs(ctx context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.countRunningErr != nil {
		return 0, f.countRunningErr
	}
	n := 0
	for _, j := range f.jobs {
		if j.Status == model.StatusRunning {
			n++
		}
	}
	return n, nil
}

func (f *dbFakeStore) ListJobsByEnvironment(ctx context.Context, repoID, environment string) ([]model.Job, error) {
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
	if f.updateJobErr != nil {
		return f.updateJobErr
	}
	f.updateJobCalls = append(f.updateJobCalls, job)
	f.jobs[job.ID] = job
	return nil
}

// RecordUsageOnce mirrors storage.UsageOnceStore: only the first caller per
// job wins, and the marker plus cost/energy commit together. It honors
// updateJobErr so the existing "job row write down" fault injection keeps
// covering the usage effect.
func (f *dbFakeStore) RecordUsageOnce(ctx context.Context, jobID string, cost, energyWh float64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateJobErr != nil {
		return false, f.updateJobErr
	}
	j, ok := f.jobs[jobID]
	if !ok || j.UsageRecorded {
		return false, nil
	}
	j.UsageRecorded = true
	j.Cost = cost
	j.EnergyWh = energyWh
	f.jobs[jobID] = j
	f.updateJobCalls = append(f.updateJobCalls, j)
	return true, nil
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
	if generation < 0 {
		return fmt.Errorf("storage: invalid lease generation %d", generation)
	}
	if receipt.JobID != jobID || receipt.Generation != generation || receipt.RunnerID != runnerID {
		return fmt.Errorf("storage: completion receipt identity mismatch")
	}
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
	// Required-artifact verification inside the completion: mirrors the
	// PostgresStore transaction. A successful completion must have an
	// artifact record for every Required contract; a missing artifact (or a
	// contract-store failure) fails closed and leaves the job running.
	if status == model.StatusSuccess {
		if f.contractsErr != nil {
			return f.contractsErr
		}
		for name, c := range f.contracts[jobID] {
			if !c.Required {
				continue
			}
			found := false
			for _, a := range f.artifacts {
				if a.JobID == jobID && a.Name == name {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%w: %s", storage.ErrRequiredArtifactMissing, name)
			}
		}
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
	// The completed job releases its reserved running quota slot in the same
	// critical section, mirroring completeRunnerTx/adjustQuotaTx.
	f.adjustQuotaLocked(storage.RepoIDForJob(j), -1, 0)
	// Release the completing runner's slot and counters in the same critical
	// section, mirroring the SQL completeRunnerTx (capacity 0 survives).
	if r, rok := f.runners[runnerID]; rok {
		if status == model.StatusSuccess {
			r.Completed++
		} else if status == model.StatusFailure {
			r.Failed++
		}
		r.LastSeen = now
		f.runners[runnerID] = r
		f.releaseRunnerSlotLocked(runnerID, jobID)
	}
	// Completion effect intents ride the completion, mirroring the SQL
	// contract: completion_reconcile (internal consistency, unbounded
	// retries) plus forge_delivery (external publication, bounded retries)
	// under their deterministic effect IDs.
	payload, perr := json.Marshal(storage.CompletionEffectsPayload{JobID: jobID, RunID: j.RunID})
	if perr != nil {
		return perr
	}
	for _, kind := range []string{storage.OutboxKindCompletionReconcile, storage.OutboxKindForgeDelivery} {
		f.outboxItems = append(f.outboxItems, storage.OutboxItem{
			ID:        storage.CompletionEffectID(jobID, generation, kind),
			Kind:      kind,
			Payload:   payload,
			CreatedAt: now,
		})
	}
	return nil
}

func (f *dbFakeStore) CancelRunJobs(ctx context.Context, runID string, reason string) ([]string, error) {
	if f.cancelRunJobsErr != nil {
		return nil, f.cancelRunJobsErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelRunCalls = append(f.cancelRunCalls, cancelRunArgs{runID, reason})
	now := time.Now().UTC()
	ids := []string{}
	for id, j := range f.jobs {
		if j.RunID != runID || j.Status.Terminal() {
			continue
		}
		wasRunning := j.Status == model.StatusRunning
		runnerID := j.LeaseRunnerID
		j.Status = model.StatusCancelled
		j.Error = reason
		j.FinishedAt = &now
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		f.jobs[id] = j
		// The cancelled job releases its reserved slot (running or queued),
		// mirroring the SQL CancelRunJobs transaction.
		if wasRunning {
			f.adjustQuotaLocked(storage.RepoIDForJob(j), -1, 0)
			// A cancelled running job releases its runner slot immediately.
			if runnerID != "" {
				f.releaseRunnerSlotLocked(runnerID, id)
			}
		} else {
			f.adjustQuotaLocked(storage.RepoIDForJob(j), 0, -1)
		}
		ids = append(ids, id)
	}
	if r, ok := f.runs[runID]; ok && !r.Status.Terminal() {
		r.Status = model.StatusCancelled
		r.FinishedAt = &now
		f.runs[runID] = r
	}
	return ids, nil
}

// adjustQuotaLocked shifts the reserved counters for the repository/team
// keys derived from the canonical RepoID (clamped at zero, missing rows
// tolerated), mirroring the SQL adjustQuotaTx key derivation. The caller
// holds f.mu.
func (f *dbFakeStore) adjustQuotaLocked(repoID string, runningDelta, queuedDelta int) {
	adjustQuotaMap(f.quotas, repoID, runningDelta, queuedDelta)
}

// ---------------------------------------------------------------------------
// storage.RecoveryStore: transactional lease recovery and revocation
// ---------------------------------------------------------------------------

// The three recovery transactions stage every effect — job rows and lease
// fields, runner active sets and counters, quota counters, dependent jobs,
// run aggregation and audit rows — on copies of the fake's maps, swapping
// them in only after the whole pass succeeded, mirroring the single durable
// transaction in memStore/PostgresStore.

// RevokeRunnerLeases mirrors memStore.RevokeRunnerLeases: every running lease
// held by runnerID is requeued (infrastructure retry budget still available)
// or terminal-cancelled with the reason, the lease is cleared, the runner
// slot and quota counters move, dependents and affected runs are recomputed,
// and one audit row per job is written. It returns the revoked job IDs.
func (f *dbFakeStore) RevokeRunnerLeases(ctx context.Context, runnerID, reason string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().UTC()
	ids := []string{}
	for id, j := range f.jobs {
		if j.Status == model.StatusRunning && j.LeaseRunnerID == runnerID {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return []string{}, nil
	}
	sort.Strings(ids)
	jobs := cloneJobMap(f.jobs)
	runners := cloneRunnerMap(f.runners)
	runs := cloneRunMap(f.runs)
	quotas := cloneQuotaMap(f.quotas)
	audit := append([]model.AuditEvent(nil), f.audit...)
	changed := map[string]bool{}
	runIDs := map[string]bool{}
	for _, id := range ids {
		j := jobs[id]
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
		jobs[id] = j
		if requeue {
			adjustQuotaMap(quotas, storage.RepoIDForJob(j), -1, 1)
		} else {
			adjustQuotaMap(quotas, storage.RepoIDForJob(j), -1, 0)
		}
		action := "job.runner_disabled_cancelled"
		if requeue {
			action = "job.runner_disabled_requeued"
		}
		audit = append(audit, recoveryAudit(j, action, "admin", reason, map[string]string{"job": j.Key, "runner": runnerID}, now))
		changed[id] = true
		if j.RunID != "" {
			runIDs[j.RunID] = true
		}
	}
	for _, id := range ids {
		releaseRunnerSlotMap(runners, runnerID, id)
		if r, ok := runners[runnerID]; ok {
			r.Failed++
			r.LastSeen = now
			runners[runnerID] = r
		}
	}
	recomputeDependentsMap(jobs, changed, now)
	for runID := range runIDs {
		recomputeRunMap(runs, jobs, runID)
	}
	f.jobs, f.runners, f.runs, f.quotas, f.audit = jobs, runners, runs, quotas, audit
	return ids, nil
}

// DisableRunnerAndRevokeCert mirrors the SQL RunnerDisableStore transaction:
// the runner's leases are revoked, the runner is disabled (revoked_at
// stamped), the certificate serial is revoked and the audit rows are written
// together, staged on clones so an injected failure leaves NO partial state.
// disableCertErr models the revoked-certificate write failing.
func (f *dbFakeStore) DisableRunnerAndRevokeCert(ctx context.Context, runnerID, certSerial, actor string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auditErr != nil {
		// The audit rows commit inside the store transaction, so an
		// unwritable audit fails the whole disable closed — exactly like the
		// SQL insert of the audit rows aborting the transaction.
		return 0, f.auditErr
	}
	if f.disableCertErr != nil {
		return 0, f.disableCertErr
	}
	if _, ok := f.runners[runnerID]; !ok {
		return 0, storage.ErrNotFound
	}
	now := time.Now().UTC()
	ids := []string{}
	for id, j := range f.jobs {
		if j.Status == model.StatusRunning && j.LeaseRunnerID == runnerID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	jobs := cloneJobMap(f.jobs)
	runners := cloneRunnerMap(f.runners)
	runs := cloneRunMap(f.runs)
	quotas := cloneQuotaMap(f.quotas)
	audit := append([]model.AuditEvent(nil), f.audit...)
	revocations := map[string]string{}
	for k, v := range f.revocations {
		revocations[k] = v
	}
	changed := map[string]bool{}
	runIDs := map[string]bool{}
	for _, id := range ids {
		j := jobs[id]
		requeue := j.Attempts <= j.MaxInfraRetries
		if requeue {
			j.Status = model.StatusQueued
			j.Error = "runner disabled; retrying"
		} else {
			j.Status = model.StatusCancelled
			j.Error = "runner disabled"
			j.FinishedAt = &now
		}
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		jobs[id] = j
		if requeue {
			adjustQuotaMap(quotas, storage.RepoIDForJob(j), -1, 1)
		} else {
			adjustQuotaMap(quotas, storage.RepoIDForJob(j), -1, 0)
		}
		action := "job.runner_disabled_cancelled"
		if requeue {
			action = "job.runner_disabled_requeued"
		}
		audit = append(audit, recoveryAudit(j, action, "admin", "runner disabled", map[string]string{"job": j.Key, "runner": runnerID}, now))
		changed[id] = true
		if j.RunID != "" {
			runIDs[j.RunID] = true
		}
	}
	for _, id := range ids {
		releaseRunnerSlotMap(runners, runnerID, id)
		if r, ok := runners[runnerID]; ok {
			r.Failed++
			r.LastSeen = now
			runners[runnerID] = r
		}
	}
	recomputeDependentsMap(jobs, changed, now)
	for runID := range runIDs {
		recomputeRunMap(runs, jobs, runID)
	}
	ri := runners[runnerID]
	ri.Disabled = true
	if certSerial != "" && ri.RevokedAt == nil {
		ri.RevokedAt = &now
	}
	runners[runnerID] = ri
	if certSerial != "" {
		revocations[certSerial] = runnerID
	}
	audit = append(audit, model.AuditEvent{ID: runnerID + "|runner.disable", Action: "runner.disable", Actor: actor, Message: "runner disabled", Metadata: map[string]string{"runner": runnerID}, CreatedAt: now})
	if certSerial != "" {
		audit = append(audit, model.AuditEvent{ID: runnerID + "|runner.cert_revoked", Action: "runner.cert_revoked", Actor: actor, Message: "runner certificate serial revoked", Metadata: map[string]string{"runner": runnerID, "serial": certSerial}, CreatedAt: now})
	}
	f.jobs, f.runners, f.runs, f.quotas, f.audit, f.revocations = jobs, runners, runs, quotas, audit, revocations
	return len(ids), nil
}

// RecoverExpiredLease mirrors memStore.RecoverExpiredLease: an expired
// running lease with the expected generation is requeued or terminally
// failed (budget exhausted); a mismatched generation, a non-running job or a
// still-live lease is a no-op.
func (f *dbFakeStore) RecoverExpiredLease(ctx context.Context, jobID string, expectedGeneration int64, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	jobs := cloneJobMap(f.jobs)
	runners := cloneRunnerMap(f.runners)
	runs := cloneRunMap(f.runs)
	quotas := cloneQuotaMap(f.quotas)
	audit := append([]model.AuditEvent(nil), f.audit...)
	requeue := j.Attempts <= j.MaxInfraRetries
	if requeue {
		j.Status = model.StatusQueued
		j.Error = "runner lease expired; retrying"
	} else {
		j.Status = model.StatusFailure
		j.Error = "runner lease expired and infrastructure retry budget exhausted"
		j.FinishedAt = &now
	}
	leaseRunnerID := j.LeaseRunnerID
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	jobs[jobID] = j
	if requeue {
		adjustQuotaMap(quotas, storage.RepoIDForJob(j), -1, 1)
	} else {
		adjustQuotaMap(quotas, storage.RepoIDForJob(j), -1, 0)
	}
	if leaseRunnerID != "" {
		releaseRunnerSlotMap(runners, leaseRunnerID, jobID)
		if r, ok := runners[leaseRunnerID]; ok {
			r.Failed++
			r.LastSeen = now
			runners[leaseRunnerID] = r
		}
	}
	action := "job.lease_expired"
	msg := "job requeued after lost runner"
	if !requeue {
		action = "job.lost_runner"
		msg = j.Error
	}
	audit = append(audit, recoveryAudit(j, action, "scheduler", msg, map[string]string{"job": j.Key}, now))
	recomputeDependentsMap(jobs, map[string]bool{jobID: true}, now)
	recomputeRunMap(runs, jobs, j.RunID)
	f.jobs, f.runners, f.runs, f.quotas, f.audit = jobs, runners, runs, quotas, audit
	return nil
}

// ExpireQueuedJob mirrors memStore.ExpireQueuedJob: a queued (or
// approval-waiting) job whose effective queue deadline is not after the
// observed deadline and whose observed deadline is not in the future is
// terminal-cancelled, its queued quota slot released, dependents and the run
// recomputed. Everything else is a no-op.
func (f *dbFakeStore) ExpireQueuedJob(ctx context.Context, jobID string, deadline time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	jobs := cloneJobMap(f.jobs)
	runs := cloneRunMap(f.runs)
	quotas := cloneQuotaMap(f.quotas)
	audit := append([]model.AuditEvent(nil), f.audit...)
	j.Status = model.StatusCancelled
	j.Error = "queue timeout"
	j.FinishedAt = &now
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	jobs[jobID] = j
	adjustQuotaMap(quotas, storage.RepoIDForJob(j), 0, -1)
	audit = append(audit, recoveryAudit(j, "job.queue_timeout", "scheduler", "job cancelled after queue deadline", map[string]string{"job": j.Key}, now))
	recomputeDependentsMap(jobs, map[string]bool{jobID: true}, now)
	recomputeRunMap(runs, jobs, j.RunID)
	f.jobs, f.runs, f.quotas, f.audit = jobs, runs, quotas, audit
	return nil
}

// cloneJobMap/cloneRunnerMap/cloneRunMap/cloneQuotaMap copy the fake's state
// for a staged recovery transaction (the memStore overlay clones).
func cloneJobMap(in map[string]model.Job) map[string]model.Job {
	out := make(map[string]model.Job, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRunnerMap(in map[string]model.Runner) map[string]model.Runner {
	out := make(map[string]model.Runner, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRunMap(in map[string]model.Run) map[string]model.Run {
	out := make(map[string]model.Run, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneQuotaMap(in map[string][2]int) map[string][2]int {
	out := make(map[string][2]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// adjustQuotaMap shifts counters on an overlay quota map, clamping at zero
// exactly like the SQL/memStore counter updates.
func adjustQuotaMap(quotas map[string][2]int, repoID string, runningDelta, queuedDelta int) {
	for _, key := range storage.QuotaKeys(repoID) {
		c := quotas[key]
		c[0] += runningDelta
		if c[0] < 0 {
			c[0] = 0
		}
		c[1] += queuedDelta
		if c[1] < 0 {
			c[1] = 0
		}
		quotas[key] = c
	}
}

// releaseRunnerSlotMap removes one job from an overlay runner's active set
// and recomputes busy/current_job, mirroring memStore.releaseRunnerSlotMap.
func releaseRunnerSlotMap(runners map[string]model.Runner, runnerID, jobID string) {
	r, ok := runners[runnerID]
	if !ok {
		return
	}
	active := make([]string, 0, len(r.ActiveJobs))
	for _, id := range r.ActiveJobs {
		if id != jobID {
			active = append(active, id)
		}
	}
	r.ActiveJobs = active
	if len(active) > 0 && r.CurrentJob == jobID {
		r.CurrentJob = active[0]
	}
	if len(active) == 0 {
		r.CurrentJob = ""
	}
	r.Busy = r.Capacity > 0 && len(active) >= r.Capacity
	runners[runnerID] = r
}

// recoveryAudit builds one audit event for a staged recovery transaction,
// mirroring storage.recoveryAudit.
func recoveryAudit(j model.Job, action, actor, msg string, meta map[string]string, now time.Time) model.AuditEvent {
	return model.AuditEvent{ID: j.ID + "|" + action, Action: action, Actor: actor, RunID: j.RunID, JobID: j.ID, Message: msg, Metadata: meta, CreatedAt: now}
}

// recomputeRunMap recomputes one run's aggregation from the overlay job map,
// mirroring memStore.recomputeRunMap/recomputeRunStatus.
func recomputeRunMap(runs map[string]model.Run, jobs map[string]model.Job, runID string) {
	run, ok := runs[runID]
	if !ok || run.Status == model.StatusCancelled {
		return
	}
	var total, terminal int
	var anyRunning, anyFailure, anyCancelled, anyWaiting bool
	var firstStart, lastFinish *time.Time
	for _, j := range jobs {
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
			run.Status = model.StatusFailure
		case anyCancelled:
			run.Status = model.StatusCancelled
		default:
			run.Status = model.StatusSuccess
		}
		run.FinishedAt = lastFinish
		if run.FinishedAt == nil {
			n := time.Now().UTC()
			run.FinishedAt = &n
		}
	case anyRunning:
		run.Status = model.StatusRunning
	case anyWaiting:
		run.Status = model.StatusWaitingApproval
	default:
		run.Status = model.StatusQueued
	}
	if run.StartedAt == nil && firstStart != nil {
		run.StartedAt = firstStart
	}
	runs[runID] = run
}

// releaseRunnerSlotLocked splices a job out of a runner's active set and
// recomputes busy/current_job; capacity 0 survives.
func (f *dbFakeStore) releaseRunnerSlotLocked(runnerID, jobID string) {
	r, ok := f.runners[runnerID]
	if !ok {
		return
	}
	r.ActiveJobs = removeStrings(r.ActiveJobs, jobID)
	r.CurrentJob = ""
	if len(r.ActiveJobs) > 0 {
		r.CurrentJob = r.ActiveJobs[0]
	}
	r.Busy = r.Capacity > 0 && len(r.ActiveJobs) >= r.Capacity
	f.runners[runnerID] = r
}

func removeStrings(in []string, v string) []string {
	out := in[:0]
	for _, x := range in {
		if x != v {
			out = append(out, x)
		}
	}
	return out
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
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runners[runnerID]
	if !ok {
		// The runner row is gone: the job's reserved quota slot is
		// repository-scoped and is released regardless.
		f.releaseJobQuotaLocked(jobID)
		return storage.ErrNotFound
	}
	if status == model.StatusSuccess {
		r.Completed++
	} else if status == model.StatusFailure {
		r.Failed++
	}
	r.LastSeen = time.Now().UTC()
	f.runners[runnerID] = r
	f.releaseRunnerSlotLocked(runnerID, jobID)
	f.releaseJobQuotaLocked(jobID)
	return nil
}

// releaseJobQuotaLocked returns a released job's reserved quota slot: the
// running slot always, plus a fresh queued slot when it was requeued. The
// caller holds f.mu.
func (f *dbFakeStore) releaseJobQuotaLocked(jobID string) {
	j, jok := f.jobs[jobID]
	if !jok {
		return
	}
	queuedDelta := 0
	if j.Status == model.StatusQueued {
		queuedDelta = 1
	}
	f.adjustQuotaLocked(storage.RepoIDForJob(j), -1, queuedDelta)
}

func (f *dbFakeStore) InsertArtifact(ctx context.Context, a model.ArtifactRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.artifacts = append(f.artifacts, a)
	return nil
}

// InsertArtifactOnce mirrors the artifacts (job_id, job_generation, name)
// unique index: the first insert wins, a same-digest conflict returns the
// stored record, a different-digest conflict returns
// storage.ErrArtifactDigestConflict.
func (f *dbFakeStore) InsertArtifactOnce(ctx context.Context, a model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.artifactInsertErr != nil {
		return model.ArtifactRecord{}, false, f.artifactInsertErr
	}
	if a.JobID != "" {
		for _, existing := range f.artifacts {
			if existing.JobID != a.JobID || existing.LeaseGeneration != a.LeaseGeneration || existing.Name != a.Name {
				continue
			}
			if existing.SHA256 != a.SHA256 {
				return existing, false, storage.ErrArtifactDigestConflict
			}
			return existing, false, nil
		}
	}
	f.artifacts = append(f.artifacts, a)
	return a, true, nil
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
	// Identity-sequence semantics: the store assigns the next sequence in
	// the append, ignoring any caller-supplied (wall-clock) value.
	f.logSeq++
	e.Seq = f.logSeq
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
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *dbFakeStore) AppendAudit(ctx context.Context, e model.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auditErr != nil {
		return f.auditErr
	}
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
	if f.upsertDeliveryErr != nil {
		return f.upsertDeliveryErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deliveries[forge+"/"+deliveryID] = runID
	return nil
}

func (f *dbFakeStore) FindDelivery(ctx context.Context, forge, deliveryID string) (string, bool, error) {
	if f.findDeliveryErr != nil {
		return "", false, f.findDeliveryErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.deliveries[forge+"/"+deliveryID]
	return v, ok, nil
}

func (f *dbFakeStore) TryAcquireLeadership(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leaderClaims = append(f.leaderClaims, key)
	if f.leaderErr != nil {
		return false, f.leaderErr
	}
	return f.leaderOK, nil
}

func (f *dbFakeStore) ReleaseLeadership(ctx context.Context, key string) error { return nil }

// ListAllArtifacts implements storage.CASReferenceStore: the full artifact
// table, mirroring the real read path.
func (f *dbFakeStore) ListAllArtifacts(ctx context.Context) ([]model.ArtifactRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.casRefErr != nil {
		return nil, f.casRefErr
	}
	return append([]model.ArtifactRecord{}, f.artifacts...), nil
}

// ListAllSnapshots implements storage.CASReferenceStore: the full snapshot
// table.
func (f *dbFakeStore) ListAllSnapshots(ctx context.Context) ([]model.SnapshotRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.casRefErr != nil {
		return nil, f.casRefErr
	}
	return append([]model.SnapshotRecord{}, f.snapshots...), nil
}

// ListAllCacheManifests implements storage.CASReferenceStore: every durable
// cache-manifest row.
func (f *dbFakeStore) ListAllCacheManifests(ctx context.Context) ([]storage.CacheManifestRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.casRefErr != nil {
		return nil, f.casRefErr
	}
	out := []storage.CacheManifestRecord{}
	for _, rec := range f.cacheMans {
		out = append(out, rec)
	}
	return out, nil
}

// ListAllPendingSidecarDigests implements storage.CASReferenceStore: the
// digest column of the durable pending-sidecar rows.
func (f *dbFakeStore) ListAllPendingSidecarDigests(ctx context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.casRefErr != nil {
		return nil, f.casRefErr
	}
	out := []string{}
	for _, row := range f.pendingSidecars {
		out = append(out, row.digest)
	}
	return out, nil
}

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
	if f.outboxAppendErr != nil {
		return f.outboxAppendErr
	}
	// Outbox IDs are the durable primary key: a REPLAY with identical content
	// converges on the existing row (nil), while a reused ID with different
	// kind/payload/identity is the same invariant conflict the SQL store
	// reports via its post-conflict re-read validation.
	for _, it := range f.outboxItems {
		if it.ID != e.ID {
			continue
		}
		if !fakeOutboxContentSame(it, e) {
			return fmt.Errorf("storage: outbox id %s reused with different content", e.ID)
		}
		return nil
	}
	f.outboxItems = append(f.outboxItems, e)
	return nil
}

// fakeOutboxContentSame mirrors the SQL OutboxAppend comparison (empty payload
// normalized to "{}", JSON compared semantically) through the shared server
// helper so the fake cannot drift from Enqueue's rule.
func fakeOutboxContentSame(a, b storage.OutboxItem) bool {
	return sameOutboxContent(
		forge.OutboxItem{Kind: a.Kind, Payload: a.Payload, LogicalKey: a.LogicalKey, StateVersion: a.StateVersion},
		forge.OutboxItem{Kind: b.Kind, Payload: b.Payload, LogicalKey: b.LogicalKey, StateVersion: b.StateVersion},
	)
}

func (f *dbFakeStore) OutboxAck(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outboxAckErr != nil {
		return f.outboxAckErr
	}
	f.outboxAcked = append(f.outboxAcked, id)
	kept := f.outboxItems[:0]
	for _, it := range f.outboxItems {
		if it.ID != id {
			kept = append(kept, it)
			continue
		}
		// Versioned ack advances the delivered watermark atomically with
		// the removal, mirroring the SQL CTE.
		if it.LogicalKey != "" && it.StateVersion > f.forgeState[it.LogicalKey] {
			f.forgeState[it.LogicalKey] = it.StateVersion
		}
	}
	f.outboxItems = kept
	delete(f.outboxClaims, id)
	delete(f.outboxMeta, id)
	return nil
}

// OutboxEnqueueVersioned mirrors the SQL versioned enqueue: check the
// delivered watermark, delete older pending versions, insert the new row.
func (f *dbFakeStore) OutboxEnqueueVersioned(ctx context.Context, e storage.OutboxItem) (storage.VersionedEnqueueOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outboxVersionErr != nil {
		return storage.VersionedEnqueued, f.outboxVersionErr
	}
	if e.LogicalKey == "" || e.StateVersion <= 0 {
		return storage.VersionedEnqueued, fmt.Errorf("storage: versioned outbox enqueue requires a logical key and a positive version")
	}
	if e.StateVersion <= f.forgeState[e.LogicalKey] {
		return storage.VersionedSuperseded, nil
	}
	// A newer pending version wins even when this enqueue arrives after it.
	for _, it := range f.outboxItems {
		if it.LogicalKey != e.LogicalKey || it.StateVersion <= e.StateVersion {
			continue
		}
		if meta, ok := f.outboxMeta[it.ID]; ok && !meta.deadAt.IsZero() {
			continue
		}
		return storage.VersionedSuperseded, nil
	}
	kept := f.outboxItems[:0]
	for _, it := range f.outboxItems {
		if it.LogicalKey == e.LogicalKey && it.StateVersion <= e.StateVersion {
			if meta, ok := f.outboxMeta[it.ID]; ok && !meta.deadAt.IsZero() {
				// Dead letters are terminal and operator-visible: never
				// silently deleted by a supersede.
				kept = append(kept, it)
				continue
			}
			delete(f.outboxClaims, it.ID)
			delete(f.outboxMeta, it.ID)
			continue
		}
		kept = append(kept, it)
	}
	f.outboxItems = kept
	for _, it := range f.outboxItems {
		if it.ID == e.ID {
			return storage.VersionedSuperseded, nil
		}
	}
	f.outboxItems = append(f.outboxItems, e)
	return storage.VersionedEnqueued, nil
}

// OutboxVersionGuard mirrors the SQL durable guard.
func (f *dbFakeStore) OutboxVersionGuard(ctx context.Context, id, logicalKey string, version int64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outboxGuardErr != nil {
		return false, f.outboxGuardErr
	}
	if logicalKey == "" || version <= 0 {
		return true, nil
	}
	alive := false
	newerPending := false
	for _, it := range f.outboxItems {
		if it.ID == id {
			alive = true
		}
		if it.LogicalKey != logicalKey || it.StateVersion <= version {
			continue
		}
		if meta, ok := f.outboxMeta[it.ID]; ok && !meta.deadAt.IsZero() {
			continue
		}
		newerPending = true
	}
	return alive && f.forgeState[logicalKey] < version && !newerPending, nil
}

func (f *dbFakeStore) AppendLogBatch(ctx context.Context, entries []model.LogEntry, r storage.LogBatchReceipt) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logBatches == nil {
		f.logBatches = map[string]string{}
	}
	key := r.JobID + "\x00" + strconv.FormatInt(r.Generation, 10) + "\x00" + r.BatchID
	digest := storage.LogBatchPayloadDigest(r, entries)
	if stored, ok := f.logBatches[key]; ok {
		// Same payload under the same identity is an idempotent duplicate;
		// a different payload is the conflict the SQL/fs stores report.
		if stored != digest {
			return false, storage.ErrLogBatchConflict
		}
		return false, nil
	}
	f.logBatches[key] = digest
	f.logs = append(f.logs, entries...)
	return true, nil
}

func (f *dbFakeStore) OutboxHas(ctx context.Context, id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, it := range f.outboxItems {
		if it.ID == id {
			return true, nil
		}
	}
	return false, nil
}

func (f *dbFakeStore) OutboxPending(ctx context.Context) ([]storage.OutboxItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outboxPendingErr != nil {
		return nil, f.outboxPendingErr
	}
	out := make([]storage.OutboxItem, 0, len(f.outboxItems))
	for _, it := range f.outboxItems {
		if meta, ok := f.outboxMeta[it.ID]; ok && !meta.deadAt.IsZero() {
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

// OutboxDue mirrors the SQL due-filtered active read: not dead-lettered AND
// next_attempt_at <= now(). ReplayDB and pruneDB mirror only these rows, so a
// backoff-delayed row is not resident and a dead letter is never replayed.
func (f *dbFakeStore) OutboxDue(ctx context.Context) ([]storage.OutboxItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outboxPendingErr != nil {
		return nil, f.outboxPendingErr
	}
	now := time.Now().UTC()
	out := make([]storage.OutboxItem, 0, len(f.outboxItems))
	for _, it := range f.outboxItems {
		if meta, ok := f.outboxMeta[it.ID]; ok {
			if !meta.deadAt.IsZero() {
				continue
			}
			if !meta.nextAt.IsZero() && meta.nextAt.After(now) {
				continue
			}
		}
		out = append(out, it)
	}
	return out, nil
}

// OutboxRetry mirrors the SQL retry/dead-letter transition: attempts grow,
// the error is retained, the claim is dropped, and the next attempt is
// deferred with bounded backoff. maxAttempts == 0 means NEVER dead-letter
// (completion_reconcile's unbounded convergence policy).
func (f *dbFakeStore) OutboxRetry(ctx context.Context, id string, dispatchErr error, maxAttempts int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	found := false
	for _, it := range f.outboxItems {
		if it.ID == id {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	msg := ""
	if dispatchErr != nil {
		msg = dispatchErr.Error()
	}
	meta := f.outboxMeta[id]
	backoff := time.Second
	for i := 0; i < meta.attempts && backoff < time.Minute; i++ {
		backoff *= 2
	}
	jitter := time.Duration(time.Now().UnixNano() % int64(backoff/4+1))
	meta.attempts++
	meta.lastError = msg
	delete(f.outboxClaims, id)
	if maxAttempts > 0 && meta.attempts >= maxAttempts {
		meta.deadAt = time.Now().UTC()
		meta.nextAt = time.Time{}
	} else {
		meta.nextAt = time.Now().UTC().Add(backoff + jitter)
	}
	f.outboxMeta[id] = meta
	return nil
}

// OutboxDeadLetters lists retired rows with their failure context.
func (f *dbFakeStore) OutboxDeadLetters(ctx context.Context) ([]storage.OutboxDeadLetter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []storage.OutboxDeadLetter{}
	for _, it := range f.outboxItems {
		meta, ok := f.outboxMeta[it.ID]
		if !ok || meta.deadAt.IsZero() {
			continue
		}
		out = append(out, storage.OutboxDeadLetter{
			ID: it.ID, Kind: it.Kind, Payload: it.Payload, CreatedAt: it.CreatedAt,
			Attempts: meta.attempts, LastError: meta.lastError, DeadLetteredAt: meta.deadAt,
			LogicalKey: it.LogicalKey, StateVersion: it.StateVersion,
		})
	}
	return out, nil
}

// OutboxRequeue re-arms one dead letter with a fresh retry budget.
func (f *dbFakeStore) OutboxRequeue(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	meta, ok := f.outboxMeta[id]
	if !ok || meta.deadAt.IsZero() {
		return storage.ErrNotFound
	}
	for _, it := range f.outboxItems {
		if it.ID == id {
			delete(f.outboxMeta, id)
			delete(f.outboxClaims, id)
			return nil
		}
	}
	return storage.ErrNotFound
}

// OutboxDelete removes one dead letter; live rows are never deleted.
func (f *dbFakeStore) OutboxDelete(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	meta, ok := f.outboxMeta[id]
	if !ok || meta.deadAt.IsZero() {
		return storage.ErrNotFound
	}
	kept := f.outboxItems[:0]
	removed := false
	for _, it := range f.outboxItems {
		if it.ID == id {
			removed = true
			continue
		}
		kept = append(kept, it)
	}
	if !removed {
		return storage.ErrNotFound
	}
	f.outboxItems = kept
	delete(f.outboxMeta, id)
	delete(f.outboxClaims, id)
	return nil
}

// OutboxMarkDelivered mirrors the SQL watermark stamp used for LEGACY
// pre-0018 forge rows whose own ack cannot advance the watermark.
func (f *dbFakeStore) OutboxMarkDelivered(ctx context.Context, logicalKey string, version int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if logicalKey == "" || version <= 0 {
		return fmt.Errorf("storage: mark delivered requires a logical key and a positive version")
	}
	if f.forgeState == nil {
		f.forgeState = map[string]int64{}
	}
	if version > f.forgeState[logicalKey] {
		f.forgeState[logicalKey] = version
	}
	return nil
}

// ForceAllOutboxDue clears every retry deferral (the test analogue of a
// backoff window elapsing) while preserving attempts/dead-letter state.
func (f *dbFakeStore) ForceAllOutboxDue() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, meta := range f.outboxMeta {
		meta.nextAt = time.Time{}
		f.outboxMeta[id] = meta
	}
}

// fakeOutboxClaim mirrors the outbox claimed_at/claimed_by columns.
type fakeOutboxClaim struct {
	claimer string
	at      time.Time
}

// fakeOutboxMeta mirrors the outbox attempts/last_error/next_attempt_at/
// dead_lettered_at columns (migration 0015).
type fakeOutboxMeta struct {
	attempts  int
	lastError string
	nextAt    time.Time
	deadAt    time.Time
}

// ClaimOutbox atomically claims up to limit dispatchable rows for claimer:
// unclaimed rows plus rows whose claim is older than storage.OutboxClaimTTL,
// in FIFO order. Two concurrent flushers can never claim the same row. Dead
// letters and rows deferred by retry backoff are never claimed.
func (f *dbFakeStore) ClaimOutbox(ctx context.Context, claimer string, limit int) ([]storage.OutboxItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if claimer == "" || limit <= 0 {
		return nil, nil
	}
	now := time.Now().UTC()
	cutoff := now.Add(-storage.OutboxClaimTTL)
	out := []storage.OutboxItem{}
	for _, it := range f.outboxItems {
		if len(out) >= limit {
			break
		}
		if meta, ok := f.outboxMeta[it.ID]; ok {
			if !meta.deadAt.IsZero() {
				continue
			}
			if !meta.nextAt.IsZero() && meta.nextAt.After(now) {
				continue
			}
		}
		// Boundary parity with the SQL claim (claimed_at < cutoff).
		if c, ok := f.outboxClaims[it.ID]; ok && !c.at.Before(cutoff) {
			continue
		}
		f.outboxClaims[it.ID] = fakeOutboxClaim{claimer: claimer, at: now}
		out = append(out, it)
	}
	return out, nil
}

func (f *dbFakeStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.outboxClaims[id]; ok && c.claimer == claimer {
		delete(f.outboxClaims, id)
	}
	return nil
}

func (f *dbFakeStore) LoadTestHistory(ctx context.Context) (int64, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.testHistoryVersion, append([]byte(nil), f.testHistoryStats...), nil
}

func (f *dbFakeStore) SaveTestHistory(ctx context.Context, stats []byte) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.testHistorySaveCalls++
	if f.testHistorySaveErr != nil {
		return 0, f.testHistorySaveErr
	}
	f.testHistoryVersion++
	f.testHistoryStats = append([]byte(nil), stats...)
	return f.testHistoryVersion, nil
}

// ---------------------------------------------------------------------------
// storage.TestHistoryAggregateStore: the incremental repository-scoped
// history mirror of migration 0026. Every method works on the fake's maps
// only, so server tests can prove scoping, bounded updates and the
// fail-closed atomic upload without a database.
// ---------------------------------------------------------------------------

// historyKey is the fake's in-memory aggregate primary key.
func fakeHistoryKey(suite, class, name string) string {
	return suite + "\x00" + class + "\x00" + name
}

func (f *dbFakeStore) InsertTestReportWithHistory(ctx context.Context, rep model.TestReport, repoID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.insertReportHistoryErr != nil {
		return 0, f.insertReportHistoryErr
	}
	f.reports = append(f.reports, rep)
	rows := f.historyAggregates[repoID]
	if rows == nil {
		rows = map[string]storage.TestHistoryAggregate{}
		f.historyAggregates[repoID] = rows
	}
	for _, c := range rep.Cases {
		key := fakeHistoryKey(rep.JobKey, c.Class, c.Name)
		row := rows[key]
		row.RepoID, row.Suite, row.Class, row.Name = repoID, rep.JobKey, c.Class, c.Name
		rows[key] = storage.FoldTestHistoryAggregate(row, storage.TestHistoryEntry{Suite: rep.JobKey, Class: c.Class, Name: c.Name, Duration: c.Duration, Passed: c.Passed, When: rep.CreatedAt})
	}
	f.historyVersions[repoID]++
	f.testHistoryVersion++
	return f.historyVersions[repoID], nil
}

func (f *dbFakeStore) LoadRepoTestHistory(ctx context.Context, repoID string) (int64, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loadRepoHistoryErr != nil {
		return 0, nil, f.loadRepoHistoryErr
	}
	version, ok := f.historyVersions[repoID]
	if !ok {
		return 0, nil, nil
	}
	rows := make([]storage.TestHistoryAggregate, 0, len(f.historyAggregates[repoID]))
	for _, row := range f.historyAggregates[repoID] {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Suite != rows[j].Suite {
			return rows[i].Suite < rows[j].Suite
		}
		if rows[i].Class != rows[j].Class {
			return rows[i].Class < rows[j].Class
		}
		return rows[i].Name < rows[j].Name
	})
	stats, err := storage.EncodeTestHistoryStats(rows)
	if err != nil {
		return 0, nil, err
	}
	return version, stats, nil
}

func (f *dbFakeStore) ResolveTestHistoryRepoIDs(ctx context.Context, query string, limit int) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if limit <= 0 {
		limit = 64
	}
	seen := map[string]bool{}
	out := []string{}
	for _, run := range f.runs {
		if !runMatchesRepoQuery(run, query) {
			continue
		}
		id := repoIDForRun(run)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
		if len(out) >= limit {
			break
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *dbFakeStore) TestReportTotals(ctx context.Context, repoIDs []string, repoQuery string) (int, int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := map[string]bool{}
	for _, id := range repoIDs {
		ids[id] = true
	}
	var reports, tests, failures int
	for _, rep := range f.reports {
		run, ok := f.runs[rep.RunID]
		if !ok {
			continue
		}
		if !ids[repoIDForRun(run)] && !runMatchesRepoQuery(run, repoQuery) {
			continue
		}
		reports++
		tests += rep.Tests
		failures += rep.Failures
	}
	return reports, tests, failures, nil
}

func (f *dbFakeStore) FlakyTestNames(ctx context.Context, repoIDs []string, limit int) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if limit <= 0 {
		limit = 1000
	}
	seen := map[string]bool{}
	out := []string{}
	for _, id := range repoIDs {
		for _, row := range f.historyAggregates[id] {
			if row.Passes == 0 || row.Fails == 0 {
				continue
			}
			display := row.Name
			if row.Class != "" {
				display = row.Class + "." + row.Name
			}
			if seen[display] {
				continue
			}
			seen[display] = true
			out = append(out, display)
		}
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *dbFakeStore) RebuildRepoTestHistory(ctx context.Context, repoID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reports := []model.TestReport{}
	for _, rep := range f.reports {
		run, ok := f.runs[rep.RunID]
		if !ok || repoIDForRun(run) != repoID {
			continue
		}
		reports = append(reports, rep)
	}
	sort.SliceStable(reports, func(i, j int) bool {
		if !reports[i].CreatedAt.Equal(reports[j].CreatedAt) {
			return reports[i].CreatedAt.Before(reports[j].CreatedAt)
		}
		return reports[i].ID < reports[j].ID
	})
	rows := map[string]storage.TestHistoryAggregate{}
	for _, rep := range reports {
		for _, c := range rep.Cases {
			key := fakeHistoryKey(rep.JobKey, c.Class, c.Name)
			row := rows[key]
			row.RepoID, row.Suite, row.Class, row.Name = repoID, rep.JobKey, c.Class, c.Name
			rows[key] = storage.FoldTestHistoryAggregate(row, storage.TestHistoryEntry{Suite: rep.JobKey, Class: c.Class, Name: c.Name, Duration: c.Duration, Passed: c.Passed, When: rep.CreatedAt})
		}
	}
	f.historyAggregates[repoID] = rows
	f.historyVersions[repoID]++
	return f.historyVersions[repoID], nil
}

func (f *dbFakeStore) ListTestHistoryRepoIDs(ctx context.Context, limit int) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if limit <= 0 {
		limit = 1000
	}
	seen := map[string]bool{}
	for _, rep := range f.reports {
		if run, ok := f.runs[rep.RunID]; ok {
			if id := repoIDForRun(run); id != "" {
				seen[id] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *dbFakeStore) PutCheckRun(ctx context.Context, key, checkRunID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.checkRuns == nil {
		f.checkRuns = map[string]string{}
	}
	f.checkRuns[key] = checkRunID
	return nil
}

func (f *dbFakeStore) GetCheckRun(ctx context.Context, key string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.checkRuns[key]
	return id, ok, nil
}

func (f *dbFakeStore) GetSchedule(ctx context.Context, id string) (storage.Schedule, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sc, ok := f.schedules[id]
	return sc, ok, nil
}

func (f *dbFakeStore) UpsertSchedule(ctx context.Context, sc storage.Schedule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.schedules[sc.ID] = sc
	return nil
}

func (f *dbFakeStore) ListSchedules(ctx context.Context) ([]storage.Schedule, error) {
	if f.listSchedulesErr != nil {
		return nil, f.listSchedulesErr
	}
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

// AdvanceScheduleLastRun mirrors the SQL GREATEST update: the stored marker
// only ever moves forward, so a stale replica can never move it backwards.
func (f *dbFakeStore) AdvanceScheduleLastRun(ctx context.Context, id string, nominal time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.advanceScheduleErr != nil {
		return f.advanceScheduleErr
	}
	sc, ok := f.schedules[id]
	if !ok {
		return storage.ErrNotFound
	}
	nominal = nominal.UTC()
	if sc.LastRun == nil || sc.LastRun.Before(nominal) {
		sc.LastRun = &nominal
		f.schedules[id] = sc
	}
	return nil
}

func (f *dbFakeStore) InsertDeployment(ctx context.Context, d model.Deployment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deploymentInsertErr != nil {
		return f.deploymentInsertErr
	}
	f.deployments[d.ID] = d
	return nil
}

func (f *dbFakeStore) ListDeploymentsByRun(ctx context.Context, runID string) ([]model.Deployment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listDeploymentsErr != nil {
		return nil, f.listDeploymentsErr
	}
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
	if f.updateDeploymentErr != nil {
		return f.updateDeploymentErr
	}
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
	if f.snapshotErr != nil {
		return f.snapshotErr
	}
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
	if f.usageErr != nil {
		return 0, 0, f.usageErr
	}
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

// ---------------------------------------------------------------------------
// atomicity/storage round extension interfaces
// ---------------------------------------------------------------------------

// InsertCompiledRun applies the atomic enqueue in memory: the run, jobs,
// contracts, delivery claim, quota reservation and schedule claim commit
// together (or none of them do).
func (f *dbFakeStore) InsertCompiledRun(ctx context.Context, req storage.InsertCompiledRunRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.compiledCalls = append(f.compiledCalls, req)
	if f.enqueueErr != nil {
		return f.enqueueErr
	}
	if f.enqueueFailOnce {
		f.enqueueFailOnce = false
		return fmt.Errorf("enqueue: injected failure")
	}
	// Reservations are staged first and committed only after the whole
	// request validated, so a rejection leaves zero partial state (the SQL
	// enqueue is a single transaction with the same property).
	type quotaStage struct {
		key string
		c   [2]int
	}
	var (
		quotaStages       []quotaStage
		stagedDownstream  *storage.DownstreamLink
		downstreamLinkKey string
	)
	if req.DownstreamLaunch != nil {
		parts := strings.Split(req.DownstreamLaunch.LinkKey, "\x00")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return fmt.Errorf("storage: malformed downstream launch claim")
		}
		if len(req.DownstreamLaunch.StableChildID) != 64 {
			return fmt.Errorf("storage: malformed downstream stable child id")
		}
		l, ok := f.downstreamLinks[req.DownstreamLaunch.LinkKey]
		if !ok {
			return fmt.Errorf("storage: downstream launch claim link missing")
		}
		if l.ChildRunID != "" {
			if l.ChildRunID == req.Run.ID {
				return storage.ErrDownstreamLaunched
			}
			return fmt.Errorf("storage: downstream launch claim lost")
		}
		l.ChildRunID = req.Run.ID
		l.StableChildID = req.DownstreamLaunch.StableChildID
		l.Reserved = false
		l.ReservedAt = nil
		downstreamLinkKey = req.DownstreamLaunch.LinkKey
		stagedDownstream = &l
	}
	if req.ScheduleClaim != nil {
		for _, o := range f.occurrences[req.ScheduleClaim.ScheduleID] {
			if o.Nominal.Equal(req.ScheduleClaim.Nominal) {
				if o.RunID != req.Run.ID {
					return storage.ErrScheduleClaimLost
				}
			}
		}
	}
	if req.Quota != nil {
		jobCount := req.Quota.JobCount
		if jobCount < 0 {
			jobCount = 0
		}
		keys := []string{req.Quota.RepoKey}
		if req.Quota.TeamKey != "" && req.Quota.TeamKey != req.Quota.RepoKey {
			keys = append(keys, req.Quota.TeamKey)
		}
		for _, key := range keys {
			c := f.quotas[key]
			c[1] += jobCount
			isTeam := key == req.Quota.TeamKey
			runningLimit, queueLimit := req.Quota.RepoConcurrency, req.Quota.RepoQueueDepth
			reason := "REPO_QUOTA"
			if isTeam {
				runningLimit, queueLimit = req.Quota.TeamConcurrency, req.Quota.TeamQueueDepth
				reason = "TEAM_QUOTA"
			}
			if runningLimit > 0 && float64(c[0]) >= runningLimit {
				return &storage.QuotaExceededError{Reason: reason, Msg: fmt.Sprintf("concurrency limit %g", runningLimit)}
			}
			if queueLimit > 0 && float64(c[1]) > queueLimit {
				return &storage.QuotaExceededError{Reason: reason, Msg: fmt.Sprintf("queue depth limit %g", queueLimit)}
			}
			quotaStages = append(quotaStages, quotaStage{key: key, c: c})
		}
	}
	// Stage the supersede cancellations (explicit CancelPrevious IDs plus
	// the in-transaction policy, resolved against the currently committed
	// runs) and the enqueued jobs: the whole request commits in one step, so
	// an injected failure during supersession leaves the old run untouched
	// and the new run absent.
	now := time.Now().UTC()
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
	seenCancel := map[string]bool{}
	for _, id := range cancelIDs {
		if seenCancel[id] {
			continue
		}
		seenCancel[id] = true
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
	}
	if f.enqueueFailDuringSupersede && len(cancelStages) > 0 {
		f.enqueueFailDuringSupersede = false
		return fmt.Errorf("enqueue: injected failure during supersession")
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
	}
	// The delivery-dedupe claim is validated after the staged supersede
	// cancellations, mirroring the SQL transaction: a replayed delivery
	// rolls the whole enqueue back, cancellations included.
	if req.WebhookClaim != nil {
		if _, exists := f.deliveries[req.WebhookClaim.Forge+"/"+req.WebhookClaim.DeliveryID]; exists {
			return storage.ErrDeliveryDuplicate
		}
	}
	// Commit: nothing below can fail, so every staged reservation and
	// cancellation lands together with the new run.
	if stagedDownstream != nil {
		f.downstreamLinks[downstreamLinkKey] = *stagedDownstream
	}
	for _, st := range quotaStages {
		f.quotas[st.key] = st.c
	}
	cancelled := map[string]bool{}
	cancelledRuns := map[string]bool{}
	for _, st := range cancelStages {
		f.jobs[st.id] = st.job
		cancelled[st.id] = true
		if st.job.RunID != "" {
			cancelledRuns[st.job.RunID] = true
		}
		f.audit = append(f.audit, model.AuditEvent{ID: st.id + "|audit", Action: "job.superseded", Actor: "scheduler", RunID: st.job.RunID, JobID: st.id, Message: "cancelled", CreatedAt: now})
		// A superseded running job releases its runner slot and quota slot
		// in the same transaction, mirroring the SQL cancel-superseded path.
		if st.wasRunning {
			f.adjustQuotaLocked(storage.RepoIDForJob(st.job), -1, 0)
			if st.runnerID != "" {
				f.releaseRunnerSlotLocked(st.runnerID, st.id)
			}
		} else {
			f.adjustQuotaLocked(storage.RepoIDForJob(st.job), 0, -1)
		}
	}
	// Dependents recomputed per existing cancel semantics, then the
	// superseded runs are cancelled: an active run is never left with only
	// cancelled jobs.
	f.recomputeDependentsLocked(cancelled, now)
	for runID := range cancelledRuns {
		if r, ok := f.runs[runID]; ok && !r.Status.Terminal() {
			r.Status = model.StatusCancelled
			r.FinishedAt = &now
			f.runs[runID] = r
		}
	}
	f.insertRunCalls = append(f.insertRunCalls, req.Run)
	f.runs[req.Run.ID] = req.Run
	for _, st := range jobStages {
		f.jobs[st.id] = st.job
		if contracts, ok := req.Contracts[st.id]; ok {
			f.contracts[st.id] = contracts
		}
	}
	if req.WebhookClaim != nil {
		f.deliveries[req.WebhookClaim.Forge+"/"+req.WebhookClaim.DeliveryID] = req.Run.ID
	}
	if req.ScheduleClaim != nil {
		f.occurrences[req.ScheduleClaim.ScheduleID] = append(f.occurrences[req.ScheduleClaim.ScheduleID], storage.Occurrence{ScheduleID: req.ScheduleClaim.ScheduleID, Nominal: req.ScheduleClaim.Nominal, RunID: req.Run.ID})
	}
	return nil
}

// supersededJobIDsLocked resolves a supersede policy against the currently
// committed runs (caller holds f.mu), mirroring the SQL in-transaction
// resolver.
func (f *dbFakeStore) supersededJobIDsLocked(p *storage.SupersedePolicy, newRunID string) []string {
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
	sort.Strings(out)
	return out
}

// recomputeDependentsLocked re-evaluates queued/waiting jobs that need a
// cancelled job, blocking them when their condition does not allow the
// outcome (caller holds f.mu). It mirrors the SQL recomputeDependentsTx.
func (f *dbFakeStore) recomputeDependentsLocked(cancelled map[string]bool, now time.Time) {
	recomputeDependentsMap(f.jobs, cancelled, now)
}

// recomputeDependentsMap re-evaluates queued/waiting jobs that need one of
// the changed jobs against the overlay job map, blocking them when their
// condition does not allow the fresh outcome, mirroring
// memStore.recomputeDependentsMap.
func recomputeDependentsMap(jobs map[string]model.Job, changed map[string]bool, now time.Time) {
	for id, j := range jobs {
		if j.Status != model.StatusQueued && j.Status != model.StatusWaitingApproval {
			continue
		}
		needsChanged := false
		for _, dep := range j.Needs {
			if changed[dep] {
				needsChanged = true
				break
			}
		}
		if !needsChanged {
			continue
		}
		ready, outcome := dependencyOutcomeLocked(j, jobs)
		if !ready {
			continue
		}
		j.DependencyStatus = outcome
		if !depsReadyLocked(j, jobs) {
			j.Status = model.StatusBlocked
			j.Error = "dependency failed"
			j.FinishedAt = &now
		}
		jobs[id] = j
	}
}

// AcquireLeaseAtomic mirrors the SQL atomic lease: the shared
// storage.LeasePredicate gates the claim (disabled/draining, capacity,
// labels, repo ACL, runtime capability, enforced-policy runtime grant and
// environment concurrency), the conditional quota transition and the job
// claim + runner slot commit together.
func (f *dbFakeStore) AcquireLeaseAtomic(ctx context.Context, claim storage.LeaseClaim) (model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.atomicLeaseErrs > 0 {
		f.atomicLeaseErrs--
		return model.Job{}, storage.ErrLeaseConflict
	}
	f.acquireCalls = append(f.acquireCalls, acquireArgs{claim.JobID, claim.RunnerID, claim.TokenHash, claim.Generation, claim.ExpiresAt})
	j, ok := f.jobs[claim.JobID]
	if !ok {
		return model.Job{}, storage.ErrNotFound
	}
	if j.Status != model.StatusQueued {
		return model.Job{}, storage.ErrLeaseConflict
	}
	r, rok := f.runners[claim.RunnerID]
	if !rok {
		return model.Job{}, storage.ErrNoCapacity
	}
	eff := r
	if strings.TrimSpace(r.CertSerial) != "" {
		if profileID, linked := f.certProfiles[r.CertSerial]; linked {
			p, pok := f.profiles[profileID]
			if !pok {
				return model.Job{}, storage.ErrNoCapacity
			}
			eff = storage.ResolveRunnerProfile(r, p, true)
		}
	}
	if f.atomicLeaseCapacity > 0 {
		eff.Capacity = f.atomicLeaseCapacity
	}
	envRunning := 0
	if j.Environment != "" && j.EnvironmentConcurrency > 0 {
		for _, other := range f.jobs {
			if other.ID == j.ID || other.Status != model.StatusRunning {
				continue
			}
			if other.Environment == j.Environment && other.RepoURL == j.RepoURL {
				envRunning++
			}
		}
	}
	runtimes, enforced := storage.LeasePolicyRuntimes(j)
	if !(storage.LeasePredicate{Runner: eff, Job: j, EnvRunning: envRunning, PolicyEnforced: enforced, PolicyRuntimes: runtimes}).Allows() {
		if j.Environment != "" && j.EnvironmentConcurrency > 0 && envRunning >= j.EnvironmentConcurrency {
			return model.Job{}, storage.ErrEnvConcurrency
		}
		return model.Job{}, storage.ErrNoCapacity
	}
	repoID := storage.RepoIDForJob(j)
	keys := []string{repoID}
	if team := storage.RepoTeamKey(repoID); team != "" && team != repoID {
		keys = append(keys, team)
	}
	for i, key := range keys {
		limit := claim.RepoConcurrency
		reason := "REPO_QUOTA"
		if i > 0 {
			limit = claim.TeamConcurrency
			reason = "TEAM_QUOTA"
		}
		if limit <= 0 {
			continue
		}
		if float64(f.quotas[key][0]) >= limit {
			return model.Job{}, &storage.QuotaExceededError{Reason: reason, Msg: fmt.Sprintf("%s concurrency limit %g reached", key, limit)}
		}
	}
	now := time.Now().UTC()
	j.Status = model.StatusRunning
	j.Attempts++
	if j.StartedAt == nil {
		j.StartedAt = &now
	}
	j.CostRate = eff.CostPerHour
	j.PowerWatts = eff.PowerWatts
	j.LeaseRunnerID = claim.RunnerID
	j.LeaseTokenHash = claim.TokenHash
	j.LeaseGeneration = claim.Generation
	j.LeaseExpiresAt = &claim.ExpiresAt
	f.jobs[claim.JobID] = j
	r.ActiveJobs = append(r.ActiveJobs, claim.JobID)
	r.Busy = eff.Capacity > 0 && len(r.ActiveJobs) >= eff.Capacity
	if len(r.ActiveJobs) > 0 {
		r.CurrentJob = r.ActiveJobs[0]
	}
	f.runners[claim.RunnerID] = r
	for _, key := range keys {
		c := f.quotas[key]
		c[0]++
		if c[1] > 0 {
			c[1]--
		}
		f.quotas[key] = c
	}
	return j, nil
}

func (f *dbFakeStore) AdjustQuotaCounter(ctx context.Context, repoKey, teamKey string, runningDelta, queuedDelta int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, key := range []string{repoKey, teamKey} {
		if key == "" {
			continue
		}
		c := f.quotas[key]
		c[0] += runningDelta
		if c[0] < 0 {
			c[0] = 0
		}
		c[1] += queuedDelta
		if c[1] < 0 {
			c[1] = 0
		}
		f.quotas[key] = c
	}
	return nil
}

func (f *dbFakeStore) QuotaCounts(ctx context.Context, repoKey, teamKey string) (int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var running, queued int
	for _, key := range []string{repoKey, teamKey} {
		if key == "" {
			continue
		}
		c := f.quotas[key]
		running += c[0]
		queued += c[1]
	}
	return running, queued, nil
}

func (f *dbFakeStore) ReserveDownstreamLaunch(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := parentJobID + "\x00" + targetRepo + "\x00" + targetRef
	l, ok := f.downstreamLinks[key]
	if !ok {
		now := time.Now().UTC()
		f.downstreamLinks[key] = storage.DownstreamLink{ParentJobID: parentJobID, TargetRepo: targetRepo, TargetRef: targetRef, LaunchToken: launchToken, Reserved: true, ReservedAt: &now, CreatedAt: now}
		return true, nil
	}
	if l.ChildRunID != "" || l.Reserved {
		return false, nil
	}
	now := time.Now().UTC()
	l.Reserved = true
	l.ReservedAt = &now
	if l.LaunchToken == "" {
		l.LaunchToken = launchToken
	}
	f.downstreamLinks[key] = l
	return true, nil
}

func (f *dbFakeStore) ReleaseDownstreamReservation(ctx context.Context, parentJobID, targetRepo, targetRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := parentJobID + "\x00" + targetRepo + "\x00" + targetRef
	l, ok := f.downstreamLinks[key]
	if !ok || l.ChildRunID != "" {
		return nil
	}
	l.Reserved = false
	l.ReservedAt = nil
	f.downstreamLinks[key] = l
	return nil
}

func (f *dbFakeStore) ExpireDownstreamReservations(ctx context.Context, olderThan time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for key, l := range f.downstreamLinks {
		if !l.Reserved || l.ChildRunID != "" {
			continue
		}
		if l.ReservedAt == nil || l.ReservedAt.Before(olderThan) {
			l.Reserved = false
			l.ReservedAt = nil
			f.downstreamLinks[key] = l
			n++
		}
	}
	return n, nil
}

func (f *dbFakeStore) GetGeneratedFragment(ctx context.Context, parentJobID string, generation int64, fragmentID string) (storage.GeneratedFragmentReceipt, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.fragments[fragmentReceiptKey(parentJobID, generation, fragmentID)]
	return rec, ok, nil
}

// fragmentReceiptKey mirrors the generated_fragments primary key.
func fragmentReceiptKey(parentJobID string, generation int64, fragmentID string) string {
	return parentJobID + "|" + strconv.FormatInt(generation, 10) + "|" + fragmentID
}

// InsertGeneratedFragmentTx mirrors the SQL transaction under f.mu: a
// committed receipt is returned with replayed=true and nothing is inserted;
// otherwise the verifier runs with the run's job count read under the same
// lock and the fragment + receipt commit atomically.
func (f *dbFakeStore) InsertGeneratedFragmentTx(ctx context.Context, req storage.GeneratedFragmentRequest, verify storage.GeneratedJobVerifier) (storage.GeneratedFragmentReceipt, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fragmentReceiptKey(req.ParentJobID, req.LeaseGeneration, req.FragmentID)
	if rec, ok := f.fragments[key]; ok {
		return rec, true, nil
	}
	parent, ok := f.jobs[req.ParentJobID]
	if !ok {
		return storage.GeneratedFragmentReceipt{}, false, storage.ErrNotFound
	}
	count := 0
	for _, j := range f.jobs {
		if j.RunID == parent.RunID {
			count++
		}
	}
	if verify != nil {
		if err := verify(parent, count); err != nil {
			return storage.GeneratedFragmentReceipt{}, false, err
		}
	}
	for id, j := range req.Jobs {
		f.jobs[id] = j
	}
	for id, cs := range req.Contracts {
		f.contracts[id] = cs
	}
	rec := storage.GeneratedFragmentReceipt{
		ParentJobID:     req.ParentJobID,
		LeaseGeneration: req.LeaseGeneration,
		FragmentID:      req.FragmentID,
		Children:        append([]storage.GeneratedFragmentChild(nil), req.Children...),
		CreatedAt:       time.Now().UTC(),
	}
	f.fragments[key] = rec
	return rec, false, nil
}

func (f *dbFakeStore) PutCacheManifest(ctx context.Context, rec storage.CacheManifestRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cacheManErr != nil {
		return f.cacheManErr
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	f.cacheMans[rec.Repo+"\x00"+rec.TrustDomain+"\x00"+rec.LogicalKey] = rec
	return nil
}

func (f *dbFakeStore) GetCacheManifest(ctx context.Context, repo, trustDomain, logicalKey string) (storage.CacheManifestRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.cacheMans[repo+"\x00"+trustDomain+"\x00"+logicalKey]
	return rec, ok, nil
}

func (f *dbFakeStore) SetArtifactSidecars(ctx context.Context, id, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256 string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sidecarAttachErr != nil {
		return f.sidecarAttachErr
	}
	for i, a := range f.artifacts {
		if a.ID != id {
			continue
		}
		if sbomPath != "" {
			a.SBOMPath = sbomPath
		}
		if sbomSHA256 != "" {
			a.SBOMSHA256 = sbomSHA256
		}
		if sigstorePath != "" {
			a.SigstorePath = sigstorePath
		}
		if sigstoreSHA256 != "" {
			a.SigstoreSHA256 = sigstoreSHA256
		}
		f.artifacts[i] = a
		return nil
	}
	return storage.ErrNotFound
}

// fakePendingSidecar is one in-memory artifact_pending_sidecars row.
type fakePendingSidecar struct {
	digest    string
	createdAt time.Time
}

// fakePendingKey mirrors the artifact_pending_sidecars primary key.
func fakePendingKey(jobID, artifactName, kind string) string {
	return jobID + "\x00" + artifactName + "\x00" + kind
}

func (f *dbFakeStore) RememberPendingSidecar(ctx context.Context, jobID, artifactName, kind, digest string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pendingErr != nil {
		return f.pendingErr
	}
	f.pendingSidecars[fakePendingKey(jobID, artifactName, kind)] = fakePendingSidecar{digest: digest, createdAt: time.Now().UTC()}
	return nil
}

func (f *dbFakeStore) PendingSidecar(ctx context.Context, jobID, artifactName, kind string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pendingErr != nil {
		return "", false, f.pendingErr
	}
	row, ok := f.pendingSidecars[fakePendingKey(jobID, artifactName, kind)]
	if !ok {
		return "", false, nil
	}
	return row.digest, true, nil
}

func (f *dbFakeStore) ConsumePendingSidecar(ctx context.Context, jobID, artifactName, kind, digest string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pendingErr != nil {
		return f.pendingErr
	}
	key := fakePendingKey(jobID, artifactName, kind)
	if row, ok := f.pendingSidecars[key]; ok && row.digest == digest {
		delete(f.pendingSidecars, key)
	}
	return nil
}

func (f *dbFakeStore) DeletePendingSidecars(ctx context.Context, jobID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pendingErr != nil {
		return f.pendingErr
	}
	prefix := jobID + "\x00"
	for key := range f.pendingSidecars {
		if strings.HasPrefix(key, prefix) {
			delete(f.pendingSidecars, key)
		}
	}
	return nil
}

func (f *dbFakeStore) PrunePendingSidecars(ctx context.Context, olderThan time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pendingErr != nil {
		return 0, f.pendingErr
	}
	n := 0
	for key, row := range f.pendingSidecars {
		if row.createdAt.Before(olderThan) {
			delete(f.pendingSidecars, key)
			n++
		}
	}
	return n, nil
}

func (f *dbFakeStore) ClaimSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimErr != nil {
		return false, f.claimErr
	}
	key := jobID + "|" + itoa(generation) + "|" + secretName
	if f.secretClaims[key] {
		return false, nil
	}
	f.secretClaims[key] = true
	return true, nil
}

func (f *dbFakeStore) ReleaseSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secretClaims, jobID+"|"+itoa(generation)+"|"+secretName)
	return nil
}

func (f *dbFakeStore) UpsertProfile(ctx context.Context, p model.RunnerProfile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	f.profiles[p.ID] = p
	return nil
}

func (f *dbFakeStore) GetProfile(ctx context.Context, id string) (model.RunnerProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.profiles[id]
	if !ok {
		return model.RunnerProfile{}, storage.ErrNotFound
	}
	return p, nil
}

func (f *dbFakeStore) ListProfiles(ctx context.Context) ([]model.RunnerProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]model.RunnerProfile, 0, len(f.profiles))
	for _, p := range f.profiles {
		out = append(out, p)
	}
	return out, nil
}

func (f *dbFakeStore) BindCertProfile(ctx context.Context, serial, profileID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certProfiles[serial] = profileID
	return nil
}

func (f *dbFakeStore) ProfileForSerial(ctx context.Context, serial string) (model.RunnerProfile, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.certProfiles[serial]
	if !ok {
		return model.RunnerProfile{}, false, nil
	}
	p, ok := f.profiles[id]
	return p, ok, nil
}

func (f *dbFakeStore) UpsertRunnerToken(ctx context.Context, runnerID, tokenDigest string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runnerTokens[tokenDigest] = runnerID
	return nil
}

func (f *dbFakeStore) RunnerIDForToken(ctx context.Context, tokenDigest string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.runnerTokens[tokenDigest]
	return id, ok, nil
}

func (f *dbFakeStore) HasRunnerTokens(ctx context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runnerTokens) > 0, nil
}

func (f *dbFakeStore) RevokeCert(ctx context.Context, serial, runnerID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revocations[serial] = runnerID
	return nil
}

func (f *dbFakeStore) CertRevoked(ctx context.Context, serial string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.revocations[serial]
	return ok, nil
}

func (f *dbFakeStore) PutEnrollGrant(ctx context.Context, digest string, expiresAt time.Time, boundLabels []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[digest] = storage.EnrollGrantRecord{ExpiresAt: expiresAt, BoundLabels: append([]string(nil), boundLabels...)}
	return nil
}

func (f *dbFakeStore) GetEnrollGrant(ctx context.Context, digest string) (storage.EnrollGrantRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.grants[digest]
	return rec, ok, nil
}

func (f *dbFakeStore) ConsumeEnrollGrant(ctx context.Context, digest string, consumedBy string) (storage.EnrollGrantRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.grants[digest]
	if !ok {
		return storage.EnrollGrantRecord{}, storage.ErrNotFound
	}
	if rec.Consumed {
		return storage.EnrollGrantRecord{}, storage.ErrGrantConsumed
	}
	if !time.Now().UTC().Before(rec.ExpiresAt) {
		return storage.EnrollGrantRecord{}, storage.ErrGrantExpired
	}
	rec.Consumed = true
	f.grants[digest] = rec
	return rec, nil
}
