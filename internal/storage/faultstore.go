package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
	_ OutboxStore             = (*FaultyStore)(nil)
	_ ScheduleStore           = (*FaultyStore)(nil)
	_ DeploymentStore         = (*FaultyStore)(nil)
	_ SnapshotStore           = (*FaultyStore)(nil)
	_ ArtifactContractStore   = (*FaultyStore)(nil)
	_ QueueReasonStore        = (*FaultyStore)(nil)
	_ DynamicStore            = (*FaultyStore)(nil)
	_ DynamicStoreTx          = (*FaultyStore)(nil)
	_ DownstreamStore         = (*FaultyStore)(nil)
	_ UsageStore              = (*FaultyStore)(nil)
	_ RunDownstreamStore      = (*FaultyStore)(nil)
	_ ArtifactLookupStore     = (*FaultyStore)(nil)
	_ RunnerJobStore          = (*FaultyStore)(nil)
	_ RunEnqueueStore         = (*FaultyStore)(nil)
	_ AtomicLeaseStore        = (*FaultyStore)(nil)
	_ QuotaCounterStore       = (*FaultyStore)(nil)
	_ CacheManifestStore      = (*FaultyStore)(nil)
	_ ArtifactSidecarStore    = (*FaultyStore)(nil)
	_ SecretClaimStore        = (*FaultyStore)(nil)
	_ SecretClaimReleaser     = (*FaultyStore)(nil)
	_ ProfileStore            = (*FaultyStore)(nil)
	_ RunnerTokenStore        = (*FaultyStore)(nil)
	_ CertRevocationStore     = (*FaultyStore)(nil)
	_ EnrollGrantStore        = (*FaultyStore)(nil)
	_ TestHistoryStore        = (*FaultyStore)(nil)
	_ ArtifactIdempotentStore = (*FaultyStore)(nil)
	_ GeneratedFragmentStore  = (*FaultyStore)(nil)
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

func (f *FaultyStore) ListJobsByEnvironment(ctx context.Context, repoID, environment string) ([]model.Job, error) {
	return f.Inner.ListJobsByEnvironment(ctx, repoID, environment)
}

func (f *FaultyStore) ListJobsByRunner(ctx context.Context, runnerID string) ([]model.Job, error) {
	return f.Inner.(RunnerJobStore).ListJobsByRunner(ctx, runnerID)
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

func (f *FaultyStore) InsertArtifactOnce(ctx context.Context, a model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	return f.Inner.(ArtifactIdempotentStore).InsertArtifactOnce(ctx, a)
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

func (f *FaultyStore) ClaimOutbox(ctx context.Context, claimer string, limit int) ([]OutboxItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return nil, err
	}
	return f.Inner.(OutboxStore).ClaimOutbox(ctx, claimer, limit)
}

func (f *FaultyStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(OutboxStore).ReleaseOutboxClaim(ctx, id, claimer)
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

func (f *FaultyStore) AdvanceScheduleLastRun(ctx context.Context, id string, nominal time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(ScheduleStore).AdvanceScheduleLastRun(ctx, id, nominal)
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

func (f *FaultyStore) InsertGeneratedJobs(ctx context.Context, parentJobID string, depth int, jobs map[string]model.Job, deps map[string][]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(DynamicStore).InsertGeneratedJobs(ctx, parentJobID, depth, jobs, deps)
}

func (f *FaultyStore) InsertDownstreamLink(ctx context.Context, l DownstreamLink) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(DownstreamStore).InsertDownstreamLink(ctx, l)
}

func (f *FaultyStore) GetDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (DownstreamLink, bool, error) {
	return f.Inner.(DownstreamStore).GetDownstreamLink(ctx, parentJobID, targetRepo, targetRef)
}

func (f *FaultyStore) MarkDownstreamLaunched(ctx context.Context, parentJobID, targetRepo, targetRef, childRunID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(DownstreamStore).MarkDownstreamLaunched(ctx, parentJobID, targetRepo, targetRef, childRunID)
}

func (f *FaultyStore) RecentUsage(ctx context.Context, since time.Time) (float64, float64, error) {
	return f.Inner.(UsageStore).RecentUsage(ctx, since)
}

func (f *FaultyStore) AppendDownstreamRun(ctx context.Context, runID, childRunID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(RunDownstreamStore).AppendDownstreamRun(ctx, runID, childRunID)
}

func (f *FaultyStore) ReopenRunForChildren(ctx context.Context, runID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(RunDownstreamStore).ReopenRunForChildren(ctx, runID)
}

func (f *FaultyStore) GetArtifact(ctx context.Context, id string) (model.ArtifactRecord, error) {
	return f.Inner.(ArtifactLookupStore).GetArtifact(ctx, id)
}

// ---------------------------------------------------------------------------
// atomicity/storage round extension methods. The Inner Store must also
// implement these interfaces (the fault-injection memStore does).
// ---------------------------------------------------------------------------

func (f *FaultyStore) InsertCompiledRun(ctx context.Context, req InsertCompiledRunRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(RunEnqueueStore).InsertCompiledRun(ctx, req)
}

func (f *FaultyStore) AcquireLeaseAtomic(ctx context.Context, claim LeaseClaim) (model.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return model.Job{}, err
	}
	return f.Inner.(AtomicLeaseStore).AcquireLeaseAtomic(ctx, claim)
}

func (f *FaultyStore) AdjustQuotaCounter(ctx context.Context, repoKey, teamKey string, runningDelta, queuedDelta int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(QuotaCounterStore).AdjustQuotaCounter(ctx, repoKey, teamKey, runningDelta, queuedDelta)
}

func (f *FaultyStore) QuotaCounts(ctx context.Context, repoKey, teamKey string) (int, int, error) {
	return f.Inner.(QuotaCounterStore).QuotaCounts(ctx, repoKey, teamKey)
}

func (f *FaultyStore) ReserveDownstreamLaunch(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return false, err
	}
	return f.Inner.(DownstreamStore).ReserveDownstreamLaunch(ctx, parentJobID, targetRepo, targetRef, launchToken)
}

func (f *FaultyStore) ReleaseDownstreamReservation(ctx context.Context, parentJobID, targetRepo, targetRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(DownstreamStore).ReleaseDownstreamReservation(ctx, parentJobID, targetRepo, targetRef)
}

func (f *FaultyStore) ExpireDownstreamReservations(ctx context.Context, olderThan time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return 0, err
	}
	return f.Inner.(DownstreamStore).ExpireDownstreamReservations(ctx, olderThan)
}

func (f *FaultyStore) InsertGeneratedFragmentTx(ctx context.Context, req GeneratedFragmentRequest, verify GeneratedJobVerifier) (GeneratedFragmentReceipt, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	return f.Inner.(DynamicStoreTx).InsertGeneratedFragmentTx(ctx, req, verify)
}

func (f *FaultyStore) GetGeneratedFragment(ctx context.Context, parentJobID string, generation int64, fragmentID string) (GeneratedFragmentReceipt, bool, error) {
	return f.Inner.(GeneratedFragmentStore).GetGeneratedFragment(ctx, parentJobID, generation, fragmentID)
}

func (f *FaultyStore) PutCacheManifest(ctx context.Context, rec CacheManifestRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(CacheManifestStore).PutCacheManifest(ctx, rec)
}

func (f *FaultyStore) GetCacheManifest(ctx context.Context, repo, trustDomain, logicalKey string) (CacheManifestRecord, bool, error) {
	return f.Inner.(CacheManifestStore).GetCacheManifest(ctx, repo, trustDomain, logicalKey)
}

func (f *FaultyStore) SetArtifactSidecars(ctx context.Context, id, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256 string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(ArtifactSidecarStore).SetArtifactSidecars(ctx, id, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256)
}

func (f *FaultyStore) RememberPendingSidecar(ctx context.Context, jobID, artifactName, kind, digest string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(ArtifactSidecarStore).RememberPendingSidecar(ctx, jobID, artifactName, kind, digest)
}

func (f *FaultyStore) PendingSidecar(ctx context.Context, jobID, artifactName, kind string) (string, bool, error) {
	return f.Inner.(ArtifactSidecarStore).PendingSidecar(ctx, jobID, artifactName, kind)
}

func (f *FaultyStore) ConsumePendingSidecar(ctx context.Context, jobID, artifactName, kind, digest string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(ArtifactSidecarStore).ConsumePendingSidecar(ctx, jobID, artifactName, kind, digest)
}

func (f *FaultyStore) DeletePendingSidecars(ctx context.Context, jobID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(ArtifactSidecarStore).DeletePendingSidecars(ctx, jobID)
}

func (f *FaultyStore) PrunePendingSidecars(ctx context.Context, olderThan time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return 0, err
	}
	return f.Inner.(ArtifactSidecarStore).PrunePendingSidecars(ctx, olderThan)
}

func (f *FaultyStore) ClaimSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return false, err
	}
	return f.Inner.(SecretClaimStore).ClaimSecretDelivery(ctx, jobID, generation, secretName)
}

func (f *FaultyStore) ReleaseSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(SecretClaimReleaser).ReleaseSecretDelivery(ctx, jobID, generation, secretName)
}

func (f *FaultyStore) UpsertProfile(ctx context.Context, p model.RunnerProfile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(ProfileStore).UpsertProfile(ctx, p)
}

func (f *FaultyStore) GetProfile(ctx context.Context, id string) (model.RunnerProfile, error) {
	return f.Inner.(ProfileStore).GetProfile(ctx, id)
}

func (f *FaultyStore) ListProfiles(ctx context.Context) ([]model.RunnerProfile, error) {
	return f.Inner.(ProfileStore).ListProfiles(ctx)
}

func (f *FaultyStore) BindCertProfile(ctx context.Context, serial, profileID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(ProfileStore).BindCertProfile(ctx, serial, profileID)
}

func (f *FaultyStore) ProfileForSerial(ctx context.Context, serial string) (model.RunnerProfile, bool, error) {
	return f.Inner.(ProfileStore).ProfileForSerial(ctx, serial)
}

func (f *FaultyStore) UpsertRunnerToken(ctx context.Context, runnerID, tokenDigest string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(RunnerTokenStore).UpsertRunnerToken(ctx, runnerID, tokenDigest)
}

func (f *FaultyStore) RunnerIDForToken(ctx context.Context, tokenDigest string) (string, bool, error) {
	return f.Inner.(RunnerTokenStore).RunnerIDForToken(ctx, tokenDigest)
}

func (f *FaultyStore) HasRunnerTokens(ctx context.Context) (bool, error) {
	return f.Inner.(RunnerTokenStore).HasRunnerTokens(ctx)
}

func (f *FaultyStore) RevokeCert(ctx context.Context, serial, runnerID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(CertRevocationStore).RevokeCert(ctx, serial, runnerID, reason)
}

func (f *FaultyStore) CertRevoked(ctx context.Context, serial string) (bool, error) {
	return f.Inner.(CertRevocationStore).CertRevoked(ctx, serial)
}

func (f *FaultyStore) PutEnrollGrant(ctx context.Context, digest string, expiresAt time.Time, boundLabels []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return f.Inner.(EnrollGrantStore).PutEnrollGrant(ctx, digest, expiresAt, boundLabels)
}

func (f *FaultyStore) GetEnrollGrant(ctx context.Context, digest string) (EnrollGrantRecord, bool, error) {
	return f.Inner.(EnrollGrantStore).GetEnrollGrant(ctx, digest)
}

func (f *FaultyStore) ConsumeEnrollGrant(ctx context.Context, digest string, consumedBy string) (EnrollGrantRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return EnrollGrantRecord{}, err
	}
	return f.Inner.(EnrollGrantStore).ConsumeEnrollGrant(ctx, digest, consumedBy)
}

func (f *FaultyStore) LoadTestHistory(ctx context.Context) (int64, []byte, error) {
	return f.Inner.(TestHistoryStore).LoadTestHistory(ctx)
}

func (f *FaultyStore) SaveTestHistory(ctx context.Context, stats []byte) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return 0, err
	}
	return f.Inner.(TestHistoryStore).SaveTestHistory(ctx, stats)
}

// memStore is a fully functional in-memory Store used as the fault-free
// baseline underneath FaultyStore in fault-injection tests.
type memStore struct {
	mu         sync.Mutex
	runs       map[string]model.Run
	jobs       map[string]model.Job
	runners    map[string]model.Runner
	receipts   map[string]model.CompletionReceipt
	audit      []model.AuditEvent
	logs       []model.LogEntry
	artifacts  []model.ArtifactRecord
	reports    []model.TestReport
	deliveries map[string]string
	outbox     []OutboxItem
	// outboxClaims tracks the cross-replica flush claims (claimed_at is
	// compared against OutboxClaimTTL on every claim attempt).
	outboxClaims map[string]outboxClaim
	// fragments is the generated-fragment idempotency receipt table.
	fragments   map[string]GeneratedFragmentReceipt
	schedules   map[string]Schedule
	occurrences map[string]map[time.Time]string
	deployments []model.Deployment
	snapshots   []model.SnapshotRecord
	contracts   map[string]map[string]ArtifactContract
	downstream  map[string]DownstreamLink
	quotas      map[string]quotaCounts
	cacheMans   map[string]CacheManifestRecord
	claims      map[string]time.Time
	// pendingSidecars mirrors artifact_pending_sidecars (migration 0012).
	pendingSidecars map[string]pendingSidecar

	profiles     map[string]model.RunnerProfile
	certProfiles map[string]string
	runnerTokens map[string]string
	revocations  map[string]string
	grants       map[string]EnrollGrantRecord

	testHistoryVersion int64
	testHistoryStats   []byte

	// enqueueFaultOps, when > 0, makes the next InsertCompiledRun fail after
	// staging that many operations (superseded cancellations first, then
	// enqueued jobs) with enqueueFaultErr: the in-memory analogue of a
	// storage error on the Nth write INSIDE the enqueue transaction. It
	// fires before anything is committed, so fault-injection tests can prove
	// a mid-enqueue failure leaves zero rows (run included). One-shot.
	enqueueFaultOps int
	enqueueFaultErr error
}

// quotaCounts is the in-memory reserved counter pair for one quota key.
type quotaCounts struct {
	running int
	queued  int
}

// pendingSidecar is one in-memory artifact_pending_sidecars row.
type pendingSidecar struct {
	digest    string
	createdAt time.Time
}

// pendingSidecarKey is the in-memory artifact_pending_sidecars primary key.
func pendingSidecarKey(jobID, artifactName, kind string) string {
	return jobID + "\x00" + artifactName + "\x00" + kind
}

// outboxClaim is one in-memory outbox claim lease.
type outboxClaim struct {
	claimer string
	at      time.Time
}

// fragmentKey is the in-memory generated-fragments primary key.
func fragmentKey(parentJobID string, generation int64, fragmentID string) string {
	return fmt.Sprintf("%s|%d|%s", parentJobID, generation, fragmentID)
}

func newMemStore() *memStore {
	return &memStore{
		runs:            map[string]model.Run{},
		jobs:            map[string]model.Job{},
		runners:         map[string]model.Runner{},
		receipts:        map[string]model.CompletionReceipt{},
		deliveries:      map[string]string{},
		outboxClaims:    map[string]outboxClaim{},
		fragments:       map[string]GeneratedFragmentReceipt{},
		schedules:       map[string]Schedule{},
		occurrences:     map[string]map[time.Time]string{},
		contracts:       map[string]map[string]ArtifactContract{},
		downstream:      map[string]DownstreamLink{},
		quotas:          map[string]quotaCounts{},
		cacheMans:       map[string]CacheManifestRecord{},
		claims:          map[string]time.Time{},
		pendingSidecars: map[string]pendingSidecar{},
		profiles:        map[string]model.RunnerProfile{},
		certProfiles:    map[string]string{},
		runnerTokens:    map[string]string{},
		revocations:     map[string]string{},
		grants:          map[string]EnrollGrantRecord{},
	}
}

var _ Store = (*memStore)(nil)

var (
	_ OutboxStore             = (*memStore)(nil)
	_ ScheduleStore           = (*memStore)(nil)
	_ DeploymentStore         = (*memStore)(nil)
	_ SnapshotStore           = (*memStore)(nil)
	_ ArtifactContractStore   = (*memStore)(nil)
	_ QueueReasonStore        = (*memStore)(nil)
	_ DynamicStore            = (*memStore)(nil)
	_ DynamicStoreTx          = (*memStore)(nil)
	_ DownstreamStore         = (*memStore)(nil)
	_ UsageStore              = (*memStore)(nil)
	_ RunDownstreamStore      = (*memStore)(nil)
	_ ArtifactLookupStore     = (*memStore)(nil)
	_ RunnerJobStore          = (*memStore)(nil)
	_ RunEnqueueStore         = (*memStore)(nil)
	_ AtomicLeaseStore        = (*memStore)(nil)
	_ QuotaCounterStore       = (*memStore)(nil)
	_ CacheManifestStore      = (*memStore)(nil)
	_ ArtifactSidecarStore    = (*memStore)(nil)
	_ SecretClaimStore        = (*memStore)(nil)
	_ SecretClaimReleaser     = (*memStore)(nil)
	_ ProfileStore            = (*memStore)(nil)
	_ ArtifactIdempotentStore = (*memStore)(nil)
	_ GeneratedFragmentStore  = (*memStore)(nil)
	_ RunnerTokenStore        = (*memStore)(nil)
	_ CertRevocationStore     = (*memStore)(nil)
	_ EnrollGrantStore        = (*memStore)(nil)
	_ TestHistoryStore        = (*memStore)(nil)
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

// ListJobsByEnvironment mirrors the SQL store: jobs are matched on the
// canonical repository identity (stored RepoID, legacy fallback derivation),
// so HTTPS and SSH spellings of one repository share an environment key.
func (m *memStore) ListJobsByEnvironment(ctx context.Context, repoID, environment string) ([]model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.Job{}
	for _, j := range m.jobs {
		if j.Environment == environment && RepoIDForJob(j) == repoID {
			out = append(out, j)
		}
	}
	return out, nil
}

func (m *memStore) ListJobsByRunner(ctx context.Context, runnerID string) ([]model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.Job{}
	for _, j := range m.jobs {
		if j.Status == model.StatusRunning && j.LeaseRunnerID == runnerID {
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
	m.jobs[jobID] = j
	m.adjustQuotaLocked(RepoIDForJob(j), 1, -1)
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
	if generation < 0 {
		return fmt.Errorf("storage: invalid lease generation %d", generation)
	}
	// The receipt identity must match the completion identity: the receipt
	// key is what makes a replay idempotent, so a mismatched receipt would
	// silently poison the dedupe table (SQL rejects generation < 0 and keys
	// the receipt by the completion row for the same reason).
	if receipt.JobID != jobID || receipt.Generation != generation || receipt.RunnerID != runnerID {
		return fmt.Errorf("storage: completion receipt identity mismatch")
	}
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
	// Required-artifact verification inside the completion: a successful
	// completion must have an artifact row for every Required contract.
	// A missing artifact fails closed (the job stays running) with
	// ErrRequiredArtifactMissing; a contract-store failure does the same.
	if status == model.StatusSuccess {
		if missing := m.requiredArtifactMissingLocked(jobID); missing != "" {
			return fmt.Errorf("%w: %s", ErrRequiredArtifactMissing, missing)
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
	m.jobs[jobID] = j
	m.receipts[key] = receipt
	m.adjustQuotaLocked(RepoIDForJob(j), -1, 0)
	// Release the completing runner's slot and bump its counters in the
	// same critical section, mirroring the SQL completeRunnerTx: capacity 0
	// survives (never clamped), busy recomputes from the remaining set.
	if r, rok := m.runners[runnerID]; rok {
		r.ActiveJobs = removeString(r.ActiveJobs, jobID)
		r.CurrentJob = ""
		if len(r.ActiveJobs) > 0 {
			r.CurrentJob = r.ActiveJobs[0]
		}
		r.Busy = r.Capacity > 0 && len(r.ActiveJobs) >= r.Capacity
		if status == model.StatusSuccess {
			r.Completed++
		} else if status == model.StatusFailure {
			r.Failed++
		}
		r.LastSeen = now
		m.runners[runnerID] = r
	}
	// Post-transaction completion effects mirror the SQL contract: one
	// outbox intent per effect kind, committed with the completion under
	// the deterministic effect IDs the completing server queues locally.
	// The payload carries two strings, so marshaling cannot fail.
	payload, _ := json.Marshal(CompletionEffectsPayload{JobID: jobID, RunID: j.RunID})
	for _, kind := range CompletionEffectKinds() {
		m.outbox = append(m.outbox, OutboxItem{ID: CompletionEffectID(jobID, generation, kind), Kind: kind, Payload: payload, CreatedAt: now})
	}
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
		wasRunning := j.Status == model.StatusRunning
		runnerID := j.LeaseRunnerID
		j.Status = model.StatusCancelled
		j.Error = reason
		j.FinishedAt = &now
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		m.jobs[id] = j
		if wasRunning {
			m.adjustQuotaLocked(RepoIDForJob(j), -1, 0)
			// The cancelled running job releases its runner slot in the
			// same critical section, so the runner is immediately
			// schedulable again.
			if runnerID != "" {
				m.releaseRunnerSlotLocked(runnerID, id)
			}
		} else {
			m.adjustQuotaLocked(RepoIDForJob(j), 0, -1)
		}
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
		// The runner row is gone (deregistered): the job's reserved quota
		// slot is repository-scoped, so it is released regardless of the
		// missing runner row.
		m.releaseJobQuotaLocked(jobID)
		return ErrNotFound
	}
	r.ActiveJobs = removeString(r.ActiveJobs, jobID)
	if len(r.ActiveJobs) > 0 && r.CurrentJob == jobID {
		r.CurrentJob = r.ActiveJobs[0]
	}
	if len(r.ActiveJobs) == 0 {
		r.CurrentJob = ""
	}
	// Capacity 0 survives release; busy mirrors the SQL recompute, and the
	// completion/failure counters and last_seen move exactly like the SQL
	// ReleaseRunnerJob so lost-runner accounting is identical in every mode.
	r.Busy = r.Capacity > 0 && len(r.ActiveJobs) >= r.Capacity
	if status == model.StatusSuccess {
		r.Completed++
	} else if status == model.StatusFailure {
		r.Failed++
	}
	r.LastSeen = time.Now().UTC()
	m.runners[runnerID] = r
	m.releaseJobQuotaLocked(jobID)
	return nil
}

// releaseJobQuotaLocked returns a released job's reserved quota slot: the
// running slot for any released job, plus a fresh queued slot when the job
// was requeued. The caller holds m.mu.
func (m *memStore) releaseJobQuotaLocked(jobID string) {
	j, jok := m.jobs[jobID]
	if !jok {
		return
	}
	queuedDelta := 0
	if j.Status == model.StatusQueued {
		queuedDelta = 1
	}
	m.adjustQuotaLocked(RepoIDForJob(j), -1, queuedDelta)
}

func (m *memStore) InsertArtifact(ctx context.Context, a model.ArtifactRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.artifacts = append(m.artifacts, a)
	return nil
}

// InsertArtifactOnce mirrors the SQL unique-key idempotency: the
// (job, generation, name) key admits exactly one record; a same-digest
// replay returns the stored record, a different digest returns
// ErrArtifactDigestConflict.
func (m *memStore) InsertArtifactOnce(ctx context.Context, a model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a.JobID != "" {
		for _, existing := range m.artifacts {
			if existing.JobID != a.JobID || existing.LeaseGeneration != a.LeaseGeneration || existing.Name != a.Name {
				continue
			}
			if existing.SHA256 != a.SHA256 {
				return existing, false, ErrArtifactDigestConflict
			}
			return existing, false, nil
		}
	}
	m.artifacts = append(m.artifacts, a)
	return a, true, nil
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
	// Outbox IDs are the durable primary key (SQL: id TEXT PRIMARY KEY): a
	// duplicate append fails so a retried intent can never create a second
	// row that would be dispatched twice under the same stable ID.
	for _, it := range m.outbox {
		if it.ID == e.ID {
			return fmt.Errorf("storage: duplicate outbox id %q", e.ID)
		}
	}
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
	delete(m.outboxClaims, id)
	return nil
}

func (m *memStore) OutboxPending(ctx context.Context) ([]OutboxItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]OutboxItem(nil), m.outbox...), nil
}

// ClaimOutbox claims up to limit dispatchable rows for claimer: unclaimed or
// stale (claimed_at older than OutboxClaimTTL) items in FIFO order. Two
// concurrent flushers under m.mu claim disjoint batches, mirroring the SQL
// SELECT ... FOR UPDATE SKIP LOCKED claim.
func (m *memStore) ClaimOutbox(ctx context.Context, claimer string, limit int) ([]OutboxItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if claimer == "" || limit <= 0 {
		return nil, nil
	}
	cutoff := time.Now().UTC().Add(-OutboxClaimTTL)
	out := []OutboxItem{}
	for _, it := range m.outbox {
		if len(out) >= limit {
			break
		}
		// Boundary parity with the SQL claim (claimed_at < cutoff): a
		// claim exactly at the cutoff is still honored.
		if c, ok := m.outboxClaims[it.ID]; ok && !c.at.Before(cutoff) {
			continue
		}
		m.outboxClaims[it.ID] = outboxClaim{claimer: claimer, at: time.Now().UTC()}
		out = append(out, it)
	}
	return out, nil
}

// ReleaseOutboxClaim clears one claim held by claimer so a retry can claim
// the row again immediately.
func (m *memStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.outboxClaims[id]; ok && c.claimer == claimer {
		delete(m.outboxClaims, id)
	}
	return nil
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

// AdvanceScheduleLastRun advances the stored marker monotonically:
// last_run = max(existing, nominal), mirroring the SQL GREATEST update. A
// stale caller can never move the marker backwards. An unknown schedule is
// ErrNotFound.
func (m *memStore) AdvanceScheduleLastRun(ctx context.Context, id string, nominal time.Time) error {
	if id == "" {
		return fmt.Errorf("storage: empty schedule id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sc, ok := m.schedules[id]
	if !ok {
		return ErrNotFound
	}
	nominal = nominal.UTC()
	if sc.LastRun == nil || sc.LastRun.Before(nominal) {
		sc.LastRun = &nominal
		m.schedules[id] = sc
	}
	return nil
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

func (m *memStore) InsertGeneratedJobs(ctx context.Context, parentJobID string, depth int, jobs map[string]model.Job, deps map[string][]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[parentJobID]; !ok {
		return ErrNotFound
	}
	for id, j := range jobs {
		m.jobs[id] = j
	}
	return nil
}

func (m *memStore) InsertDownstreamLink(ctx context.Context, l DownstreamLink) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := l.ParentJobID + "\x00" + l.TargetRepo + "\x00" + l.TargetRef
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	if prev, ok := m.downstream[key]; ok {
		_ = prev
		return nil
	}
	m.downstream[key] = l
	return nil
}

func (m *memStore) GetDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (DownstreamLink, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.downstream[parentJobID+"\x00"+targetRepo+"\x00"+targetRef]
	return l, ok, nil
}

func (m *memStore) ReserveDownstreamLaunch(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := parentJobID + "\x00" + targetRepo + "\x00" + targetRef
	l, ok := m.downstream[key]
	if !ok {
		now := time.Now().UTC()
		m.downstream[key] = DownstreamLink{ParentJobID: parentJobID, TargetRepo: targetRepo, TargetRef: targetRef, LaunchToken: launchToken, Reserved: true, ReservedAt: &now, CreatedAt: now}
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
	m.downstream[key] = l
	return true, nil
}

func (m *memStore) ReleaseDownstreamReservation(ctx context.Context, parentJobID, targetRepo, targetRef string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := parentJobID + "\x00" + targetRepo + "\x00" + targetRef
	l, ok := m.downstream[key]
	if !ok || l.ChildRunID != "" {
		return nil
	}
	l.Reserved = false
	l.ReservedAt = nil
	m.downstream[key] = l
	return nil
}

func (m *memStore) ExpireDownstreamReservations(ctx context.Context, olderThan time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for key, l := range m.downstream {
		if !l.Reserved || l.ChildRunID != "" {
			continue
		}
		if l.ReservedAt == nil || l.ReservedAt.Before(olderThan) {
			l.Reserved = false
			l.ReservedAt = nil
			m.downstream[key] = l
			n++
		}
	}
	return n, nil
}

func (m *memStore) MarkDownstreamLaunched(ctx context.Context, parentJobID, targetRepo, targetRef, childRunID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := parentJobID + "\x00" + targetRepo + "\x00" + targetRef
	l, ok := m.downstream[key]
	if !ok || l.ChildRunID != "" {
		return nil
	}
	l.ChildRunID = childRunID
	l.Reserved = false
	l.ReservedAt = nil
	m.downstream[key] = l
	return nil
}

func (m *memStore) RecentUsage(ctx context.Context, since time.Time) (float64, float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var cost, energy float64
	for _, j := range m.jobs {
		if j.FinishedAt == nil || j.FinishedAt.Before(since) {
			continue
		}
		cost += j.Cost
		energy += j.EnergyWh
	}
	return cost, energy, nil
}

func (m *memStore) AppendDownstreamRun(ctx context.Context, runID, childRunID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[runID]
	if !ok {
		return ErrNotFound
	}
	for _, id := range r.DownstreamRuns {
		if id == childRunID {
			return nil
		}
	}
	r.DownstreamRuns = append(r.DownstreamRuns, childRunID)
	m.runs[runID] = r
	return nil
}

func (m *memStore) ReopenRunForChildren(ctx context.Context, runID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[runID]
	if !ok {
		return ErrNotFound
	}
	if r.Status != model.StatusSuccess {
		return nil
	}
	r.Status = model.StatusRunning
	r.FinishedAt = nil
	m.runs[runID] = r
	return nil
}

func (m *memStore) GetArtifact(ctx context.Context, id string) (model.ArtifactRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.artifacts {
		if a.ID == id {
			return a, nil
		}
	}
	return model.ArtifactRecord{}, ErrNotFound
}

// ---------------------------------------------------------------------------
// atomicity/storage round extension methods (in-memory)
// ---------------------------------------------------------------------------

// memQuotaKeys mirrors the SQL quota key derivation for one canonical
// repository identity.
func memQuotaKeys(repoID string) []string {
	return QuotaKeys(repoID)
}

// adjustQuotaLocked shifts counters for the repo/team keys (caller holds
// m.mu). Missing rows are tolerated.
func (m *memStore) adjustQuotaLocked(repoID string, runningDelta, queuedDelta int) {
	for _, key := range memQuotaKeys(repoID) {
		c := m.quotas[key]
		c.running += runningDelta
		if c.running < 0 {
			c.running = 0
		}
		c.queued += queuedDelta
		if c.queued < 0 {
			c.queued = 0
		}
		m.quotas[key] = c
	}
}

// InsertCompiledRun applies the whole atomic-enqueue request under m.mu:
// every write is staged and only committed when the whole request validates
// (delivery dedupe, duplicate rows, quota limits, schedule claim), so a
// rejected request leaves zero partial state. Supersession — explicit
// CancelPrevious IDs and the in-transaction Supersede policy resolved
// against the currently committed runs — commits with the new run: the
// superseded jobs are terminal-cancelled with their leases cleared, their
// runner slots and quota released, their dependents re-evaluated, and the
// superseded runs marked cancelled in the SAME critical section that
// publishes the new run.
func (m *memStore) InsertCompiledRun(ctx context.Context, req InsertCompiledRunRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	runID := req.Run.ID
	if runID == "" {
		return fmt.Errorf("storage: empty run id")
	}
	// Every reservation is STAGED first and committed only after the whole
	// request validated: a rejection (duplicate delivery, quota limit, lost
	// schedule claim) must leave zero partial state, exactly like the SQL
	// transaction. Mutating m.downstream/m.quotas in place before a later
	// validation fails would leak a consumed launch claim or an inflated
	// counter.
	type quotaStage struct {
		key string
		c   quotaCounts
	}
	var (
		quotaStages       []quotaStage
		stagedDownstream  *DownstreamLink
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
		key := req.DownstreamLaunch.LinkKey
		l, ok := m.downstream[key]
		if !ok {
			return fmt.Errorf("storage: downstream launch claim link missing")
		}
		if l.ChildRunID != "" {
			if l.ChildRunID == runID {
				return ErrDownstreamLaunched
			}
			return fmt.Errorf("storage: downstream launch claim lost")
		}
		l.ChildRunID = runID
		l.StableChildID = req.DownstreamLaunch.StableChildID
		l.Reserved = false
		l.ReservedAt = nil
		downstreamLinkKey = key
		stagedDownstream = &l
	}
	// Duplicate primary keys mirror the SQL INSERT failures (the downstream
	// launch claim above is resolved first, exactly like the SQL order): a
	// replayed run must fail the whole enqueue rather than overwrite the
	// committed rows.
	if _, exists := m.runs[runID]; exists {
		return fmt.Errorf("storage: run %s already exists", runID)
	}
	for id := range req.Jobs {
		if _, exists := m.jobs[id]; exists {
			return fmt.Errorf("storage: job %s already exists", id)
		}
	}
	// Quota reservation: re-enforce limits against the reserved counters.
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
			c := m.quotas[key]
			c.queued += jobCount
			isTeam := key == req.Quota.TeamKey
			runningLimit, queueLimit := req.Quota.RepoConcurrency, req.Quota.RepoQueueDepth
			reason, scope := "REPO_QUOTA", "repository"
			if isTeam {
				runningLimit, queueLimit = req.Quota.TeamConcurrency, req.Quota.TeamQueueDepth
				reason, scope = "TEAM_QUOTA", "team"
			}
			if runningLimit > 0 && float64(c.running) >= runningLimit {
				return &QuotaExceededError{Reason: reason, Msg: fmt.Sprintf("%s already has %d running job(s), concurrency limit %g", scope, c.running, runningLimit)}
			}
			if queueLimit > 0 && float64(c.queued) > queueLimit {
				return &QuotaExceededError{Reason: reason, Msg: fmt.Sprintf("%s queue depth would reach %d, limit %g", scope, c.queued, queueLimit)}
			}
			quotaStages = append(quotaStages, quotaStage{key: key, c: c})
		}
	}
	if req.ScheduleClaim != nil {
		if byNominal, ok := m.occurrences[req.ScheduleClaim.ScheduleID]; ok {
			if existing, exists := byNominal[req.ScheduleClaim.Nominal]; exists && existing != runID {
				return ErrScheduleClaimLost
			}
		}
	}
	now := time.Now().UTC()
	// The in-transaction supersede policy resolves against the currently
	// committed runs (the new run is excluded by ID), exactly like the SQL
	// resolver under its advisory lock.
	stagedOps := 0
	bumpStaged := func() error {
		if m.enqueueFaultOps <= 0 {
			return nil
		}
		stagedOps++
		if stagedOps < m.enqueueFaultOps {
			return nil
		}
		err := m.enqueueFaultErr
		m.enqueueFaultOps = 0
		m.enqueueFaultErr = nil
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
		cancelIDs = append(cancelIDs, m.supersededJobIDsLocked(req.Supersede, runID)...)
	}
	cancelStages := make([]cancelStage, 0, len(cancelIDs))
	seenCancel := map[string]bool{}
	for _, id := range cancelIDs {
		if seenCancel[id] {
			continue
		}
		seenCancel[id] = true
		j, ok := m.jobs[id]
		if !ok || j.Status.Terminal() {
			continue
		}
		wasRunning := j.Status == model.StatusRunning
		runnerID := j.LeaseRunnerID
		j.Status = model.StatusCancelled
		j.Error = "superseded by run " + runID
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
		j.Needs = effectiveNeeds(id, j, req.Deps)
		jobStages = append(jobStages, jobStage{id: id, job: j})
		if err := bumpStaged(); err != nil {
			return err
		}
	}
	// The delivery-dedupe claim is validated against the staged request,
	// mirroring the SQL transaction where the webhook claim insert runs
	// after the run/jobs/supersession writes and its conflict rolls them all
	// back: a replayed delivery must not cancel the superseded run either.
	if req.WebhookClaim != nil {
		if _, exists := m.deliveries[req.WebhookClaim.Forge+"/"+req.WebhookClaim.DeliveryID]; exists {
			return ErrDeliveryDuplicate
		}
	}
	// Commit: from here on nothing can fail, so the staged reservations, the
	// superseded cancellations and the new run land together.
	if stagedDownstream != nil {
		m.downstream[downstreamLinkKey] = *stagedDownstream
	}
	for _, st := range quotaStages {
		m.quotas[st.key] = st.c
	}
	cancelled := make(map[string]bool, len(cancelStages))
	cancelledRuns := map[string]bool{}
	for _, st := range cancelStages {
		m.jobs[st.id] = st.job
		cancelled[st.id] = true
		if st.job.RunID != "" {
			cancelledRuns[st.job.RunID] = true
		}
		m.audit = append(m.audit, model.AuditEvent{ID: st.id + "|audit", Action: "job.superseded", Actor: "scheduler", RunID: st.job.RunID, JobID: st.id, Message: "cancelled", CreatedAt: now})
		if st.wasRunning {
			m.adjustQuotaLocked(RepoIDForJob(st.job), -1, 0)
			// A superseded running job releases its runner slot in the
			// same transaction, exactly like the SQL cancel-superseded path.
			if st.runnerID != "" {
				m.releaseRunnerSlotLocked(st.runnerID, st.id)
			}
		} else {
			m.adjustQuotaLocked(RepoIDForJob(st.job), 0, -1)
		}
	}
	// Dependents recomputed per existing cancel semantics: a queued job
	// needing a superseded job is re-evaluated against the fresh outcome and
	// blocked when its condition does not allow it.
	m.recomputeDependentsLocked(cancelled, now)
	// The superseded runs are cancelled in the same step as the new run's
	// publication, never leaving an active run with only cancelled jobs.
	for rid := range cancelledRuns {
		if r, ok := m.runs[rid]; ok && !r.Status.Terminal() {
			r.Status = model.StatusCancelled
			r.FinishedAt = &now
			m.runs[rid] = r
		}
	}
	m.runs[runID] = req.Run
	for _, st := range jobStages {
		m.jobs[st.id] = st.job
		if contracts, ok := req.Contracts[st.id]; ok {
			m.contracts[st.id] = contracts
		}
	}
	if req.WebhookClaim != nil {
		m.deliveries[req.WebhookClaim.Forge+"/"+req.WebhookClaim.DeliveryID] = runID + "/" + req.WebhookClaim.PayloadDigest
	}
	if req.ScheduleClaim != nil {
		byNominal, ok := m.occurrences[req.ScheduleClaim.ScheduleID]
		if !ok {
			byNominal = map[time.Time]string{}
			m.occurrences[req.ScheduleClaim.ScheduleID] = byNominal
		}
		byNominal[req.ScheduleClaim.Nominal] = runID
	}
	return nil
}

// supersededJobIDsLocked resolves a supersede policy against the currently
// committed runs (caller holds m.mu): every other non-terminal run of the
// same CANONICAL repository identity and concurrency group contributes its
// non-terminal job IDs, in deterministic order. The identity is read through
// RepoIDForRun (stored RepoID, legacy URL + full-name fallback), so the same
// repository submitted once via HTTPS and once via SSH supersedes, exactly
// like the SQL store's repo_id predicate.
func (m *memStore) supersededJobIDsLocked(p *SupersedePolicy, newRunID string) []string {
	repoID := strings.TrimSpace(p.RepoID)
	group := strings.TrimSpace(p.ConcurrencyGroup)
	if repoID == "" || group == "" {
		return nil
	}
	runIDs := []string{}
	for id, r := range m.runs {
		if id == newRunID || r.Status.Terminal() {
			continue
		}
		if RepoIDForRun(r) != repoID || r.ConcurrencyGroup != group {
			continue
		}
		runIDs = append(runIDs, id)
	}
	sort.Strings(runIDs)
	out := []string{}
	for _, rid := range runIDs {
		for id, j := range m.jobs {
			if j.RunID != rid || j.Status.Terminal() {
				continue
			}
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// recomputeDependentsLocked re-evaluates every queued/waiting job that needs
// one of the cancelled jobs against the fresh dependency outcome (caller
// holds m.mu), blocking it when its condition does not allow the outcome.
// It mirrors recomputeDependentsTx from the SQL enqueue transaction.
func (m *memStore) recomputeDependentsLocked(cancelled map[string]bool, now time.Time) {
	if len(cancelled) == 0 {
		return
	}
	for id, j := range m.jobs {
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
		statuses := map[string]model.Status{}
		for _, dep := range j.Needs {
			if d, ok := m.jobs[dep]; ok {
				statuses[dep] = d.Status
			}
		}
		ready, outcome := dependencyOutcome(statuses, j.Needs)
		if !ready {
			continue
		}
		j.DependencyStatus = outcome
		if outcome != model.StatusSuccess && !dependencyConditionAllows(j.Condition, outcome) {
			j.Status = model.StatusBlocked
			j.Error = "dependency failed"
			j.FinishedAt = &now
		}
		m.jobs[id] = j
	}
}

// resolveProfileLocked resolves the LIVE profile bound to the runner's
// certificate serial (caller holds m.mu). linked reports whether a
// cert_profile_links row exists; found whether its profile row exists. A
// linked-but-missing profile denies the lease (fail closed).
func (m *memStore) resolveProfileLocked(r model.Runner) (effective model.Runner, linked, found bool) {
	if strings.TrimSpace(r.CertSerial) == "" {
		return r, false, false
	}
	profileID, ok := m.certProfiles[r.CertSerial]
	if !ok {
		return r, false, false
	}
	p, ok := m.profiles[profileID]
	if !ok {
		return r, true, false
	}
	return ResolveRunnerProfile(r, p, true), true, true
}

// claimQuotaLocked re-checks the conditional queued->running quota
// transition for the repository/team keys (limit <= 0 means unlimited) and
// reports a *QuotaExceededError when the running count is already at the
// limit. Caller holds m.mu; the caller performs the counter move only after
// every other claim predicate passed, so a rejected lease leaves the
// counters untouched.
func (m *memStore) claimQuotaLocked(repoID string, repoLimit, teamLimit float64) error {
	for i, key := range memQuotaKeys(repoID) {
		limit := repoLimit
		reason, scope := "REPO_QUOTA", "repository"
		if i > 0 {
			limit = teamLimit
			reason, scope = "TEAM_QUOTA", "team"
		}
		if limit <= 0 {
			continue
		}
		if float64(m.quotas[key].running) >= limit {
			return &QuotaExceededError{Reason: reason, Msg: fmt.Sprintf("%s %s already holds the maximum %g running job(s)", scope, key, limit)}
		}
	}
	return nil
}

// releaseRunnerSlotLocked splices one job ID out of a runner's active set
// and recomputes busy/current_job (caller holds m.mu). Capacity 0 survives:
// a zero-capacity runner is never busy.
func (m *memStore) releaseRunnerSlotLocked(runnerID, jobID string) {
	r, ok := m.runners[runnerID]
	if !ok {
		return
	}
	r.ActiveJobs = removeString(r.ActiveJobs, jobID)
	if len(r.ActiveJobs) > 0 && r.CurrentJob == jobID {
		r.CurrentJob = r.ActiveJobs[0]
	}
	if len(r.ActiveJobs) == 0 {
		r.CurrentJob = ""
	}
	r.Busy = r.Capacity > 0 && len(r.ActiveJobs) >= r.Capacity
	m.runners[runnerID] = r
}

// AcquireLeaseAtomic mirrors the SQL atomic lease: the job claim (attempts
// incremented once, started_at stamped on the first lease only, live usage
// rates frozen), the full claim predicate (disabled/draining, capacity > 0,
// live profile repo ACL/capabilities/labels/region), the environment
// concurrency reservation and the conditional queued->running quota
// transition all commit or fail together under m.mu.
func (m *memStore) AcquireLeaseAtomic(ctx context.Context, claim LeaseClaim) (model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[claim.JobID]
	if !ok {
		return model.Job{}, ErrNotFound
	}
	if j.Status != model.StatusQueued {
		return model.Job{}, ErrLeaseConflict
	}
	r, rok := m.runners[claim.RunnerID]
	if !rok {
		return model.Job{}, ErrNoCapacity
	}
	effective, linked, found := m.resolveProfileLocked(r)
	if linked && !found {
		return model.Job{}, ErrNoCapacity
	}
	// The environment key is the CANONICAL repository identity of the claim
	// (falling back to the job's own identity for callers that carry none)
	// plus the environment name, exactly like the SQL count and
	// LeaseClaim.EnvKey: HTTPS/SSH spellings of one repository share a slot
	// pool. The claim's environment fields are authoritative, mirroring the
	// SQL claim.
	env := claim.Environment
	envLimit := claim.EnvironmentConcurrency
	claimRepoID := RepoIDFor(claim.CanonRepoID, j.RepoURL, j.RepoFullName)
	envRunning := 0
	if env != "" && envLimit > 0 {
		for id, other := range m.jobs {
			if id == j.ID || other.Status != model.StatusRunning {
				continue
			}
			if other.Environment == env && RepoIDForJob(other) == claimRepoID {
				envRunning++
			}
		}
	}
	runtimes, enforced := LeasePolicyRuntimes(j)
	if !(LeasePredicate{Runner: effective, Job: j, EnvRunning: envRunning, PolicyEnforced: enforced, PolicyRuntimes: runtimes}).Allows() {
		if effective.Disabled || effective.Draining || effective.Capacity <= 0 || len(effective.ActiveJobs) >= effective.Capacity {
			return model.Job{}, ErrNoCapacity
		}
		if j.Environment != "" && j.EnvironmentConcurrency > 0 && envRunning >= j.EnvironmentConcurrency {
			return model.Job{}, ErrEnvConcurrency
		}
		return model.Job{}, ErrNoCapacity
	}
	if err := m.claimQuotaLocked(RepoIDForJob(j), claim.RepoConcurrency, claim.TeamConcurrency); err != nil {
		return model.Job{}, err
	}
	now := time.Now().UTC()
	j.Status = model.StatusRunning
	j.Attempts++
	if j.StartedAt == nil {
		j.StartedAt = &now
	}
	// Freeze the live usage rates at lease time: completion derives
	// cost/energy from them plus the wall-clock duration.
	j.CostRate = effective.CostPerHour
	j.PowerWatts = effective.PowerWatts
	j.LeaseRunnerID = claim.RunnerID
	j.LeaseTokenHash = claim.TokenHash
	j.LeaseGeneration = claim.Generation
	j.LeaseExpiresAt = &claim.ExpiresAt
	m.jobs[claim.JobID] = j
	r.ActiveJobs = append(r.ActiveJobs, claim.JobID)
	r.Busy = effective.Capacity > 0 && len(r.ActiveJobs) >= effective.Capacity
	if len(r.ActiveJobs) > 0 {
		r.CurrentJob = r.ActiveJobs[0]
	}
	m.runners[claim.RunnerID] = r
	m.adjustQuotaLocked(RepoIDForJob(j), 1, -1)
	return j, nil
}

func (m *memStore) AdjustQuotaCounter(ctx context.Context, repoKey, teamKey string, runningDelta, queuedDelta int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, key := range []string{repoKey, teamKey} {
		if key == "" {
			continue
		}
		c := m.quotas[key]
		c.running += runningDelta
		if c.running < 0 {
			c.running = 0
		}
		c.queued += queuedDelta
		if c.queued < 0 {
			c.queued = 0
		}
		m.quotas[key] = c
	}
	return nil
}

func (m *memStore) QuotaCounts(ctx context.Context, repoKey, teamKey string) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var running, queued int
	for _, key := range []string{repoKey, teamKey} {
		if key == "" {
			continue
		}
		c := m.quotas[key]
		running += c.running
		queued += c.queued
	}
	return running, queued, nil
}

// GetGeneratedFragment returns the idempotency receipt of an admitted
// fragment.
func (m *memStore) GetGeneratedFragment(ctx context.Context, parentJobID string, generation int64, fragmentID string) (GeneratedFragmentReceipt, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.fragments[fragmentKey(parentJobID, generation, fragmentID)]
	return rec, ok, nil
}

// InsertGeneratedFragmentTx mirrors the SQL transaction under m.mu: a
// committed receipt is returned with replayed=true and nothing is inserted;
// otherwise the parent is re-validated (via the verifier, with the run's job
// count read under the same lock), the whole fragment is staged, and the
// receipt commits with the jobs.
func (m *memStore) InsertGeneratedFragmentTx(ctx context.Context, req GeneratedFragmentRequest, verify GeneratedJobVerifier) (GeneratedFragmentReceipt, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec, ok := m.fragments[fragmentKey(req.ParentJobID, req.LeaseGeneration, req.FragmentID)]; ok {
		return rec, true, nil
	}
	parent, ok := m.jobs[req.ParentJobID]
	if !ok {
		return GeneratedFragmentReceipt{}, false, ErrNotFound
	}
	count := 0
	for _, j := range m.jobs {
		if j.RunID == parent.RunID {
			count++
		}
	}
	if verify != nil {
		if err := verify(parent, count); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
	}
	// Stage the whole fragment first (mirroring the SQL transaction: any
	// validation failure — including a malformed contract job ID — rolls
	// the ENTIRE fragment back, leaving no partial jobs or contracts).
	// A map key that disagrees with the job's own ID would make this store
	// insert the job under a different primary key than SQL (which inserts
	// under j.ID), so it fails closed.
	for id, j := range req.Jobs {
		if err := ValidateJobID(id); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
		if j.ID != id {
			return GeneratedFragmentReceipt{}, false, fmt.Errorf("storage: fragment job key %s carries id %s", id, j.ID)
		}
	}
	for id := range req.Contracts {
		if err := ValidateJobID(id); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
		if _, ok := req.Jobs[id]; !ok {
			return GeneratedFragmentReceipt{}, false, fmt.Errorf("storage: fragment contracts reference unknown job %s", id)
		}
	}
	for id, j := range req.Jobs {
		m.jobs[id] = j
	}
	for id, cs := range req.Contracts {
		cp := make(map[string]ArtifactContract, len(cs))
		for k, v := range cs {
			cp[k] = v
		}
		m.contracts[id] = cp
	}
	rec := GeneratedFragmentReceipt{
		ParentJobID:     req.ParentJobID,
		LeaseGeneration: req.LeaseGeneration,
		FragmentID:      req.FragmentID,
		Children:        append([]GeneratedFragmentChild(nil), req.Children...),
		CreatedAt:       time.Now().UTC(),
	}
	m.fragments[fragmentKey(req.ParentJobID, req.LeaseGeneration, req.FragmentID)] = rec
	return rec, false, nil
}

func (m *memStore) PutCacheManifest(ctx context.Context, rec CacheManifestRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	m.cacheMans[rec.Repo+"\x00"+rec.TrustDomain+"\x00"+rec.LogicalKey] = rec
	return nil
}

func (m *memStore) GetCacheManifest(ctx context.Context, repo, trustDomain, logicalKey string) (CacheManifestRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.cacheMans[repo+"\x00"+trustDomain+"\x00"+logicalKey]
	return rec, ok, nil
}

// SetArtifactSidecars updates one artifact record's sidecar references.
func (m *memStore) SetArtifactSidecars(ctx context.Context, id, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, a := range m.artifacts {
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
		m.artifacts[i] = a
		return nil
	}
	return ErrNotFound
}

// RememberPendingSidecar upserts the pending sidecar digest for
// (job, artifact, kind), replacing the digest of a re-upload.
func (m *memStore) RememberPendingSidecar(ctx context.Context, jobID, artifactName, kind, digest string) error {
	if err := validatePendingSidecarKey(jobID, artifactName, kind); err != nil {
		return err
	}
	if err := validatePendingSidecarDigest(digest); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingSidecars[pendingSidecarKey(jobID, artifactName, kind)] = pendingSidecar{digest: digest, createdAt: time.Now().UTC()}
	return nil
}

// PendingSidecar resolves the pending sidecar digest, or ok=false when the
// row is absent.
func (m *memStore) PendingSidecar(ctx context.Context, jobID, artifactName, kind string) (string, bool, error) {
	if err := validatePendingSidecarKey(jobID, artifactName, kind); err != nil {
		return "", false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.pendingSidecars[pendingSidecarKey(jobID, artifactName, kind)]
	if !ok {
		return "", false, nil
	}
	return row.digest, true, nil
}

// ConsumePendingSidecar deletes the pending row only while it still carries
// the consumed digest.
func (m *memStore) ConsumePendingSidecar(ctx context.Context, jobID, artifactName, kind, digest string) error {
	if err := validatePendingSidecarKey(jobID, artifactName, kind); err != nil {
		return err
	}
	if err := validatePendingSidecarDigest(digest); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pendingSidecarKey(jobID, artifactName, kind)
	if row, ok := m.pendingSidecars[key]; ok && row.digest == digest {
		delete(m.pendingSidecars, key)
	}
	return nil
}

// DeletePendingSidecars clears every leftover pending row for the job.
func (m *memStore) DeletePendingSidecars(ctx context.Context, jobID string) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := jobID + "\x00"
	for key := range m.pendingSidecars {
		if strings.HasPrefix(key, prefix) {
			delete(m.pendingSidecars, key)
		}
	}
	return nil
}

// PrunePendingSidecars drops rows created before the cutoff.
func (m *memStore) PrunePendingSidecars(ctx context.Context, olderThan time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for key, row := range m.pendingSidecars {
		if row.createdAt.Before(olderThan) {
			delete(m.pendingSidecars, key)
			n++
		}
	}
	return n, nil
}

// requiredArtifactMissingLocked returns the name of the first Required
// contract entry with no artifact record for (job, name), or "" when every
// required artifact is present. The caller holds m.mu.
func (m *memStore) requiredArtifactMissingLocked(jobID string) string {
	contracts, ok := m.contracts[jobID]
	if !ok || len(contracts) == 0 {
		return ""
	}
	for name, c := range contracts {
		if !c.Required {
			continue
		}
		found := false
		for _, a := range m.artifacts {
			if a.JobID == jobID && a.Name == name {
				found = true
				break
			}
		}
		if !found {
			return name
		}
	}
	return ""
}

// ClaimSecretDelivery reserves the once-only (job, generation, secret name)
// claim under m.mu; the first claim reports true, replays report false.
func (m *memStore) ClaimSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s|%d|%s", jobID, generation, secretName)
	if _, exists := m.claims[key]; exists {
		return false, nil
	}
	m.claims[key] = time.Now().UTC()
	return true, nil
}

// ReleaseSecretDelivery drops a claimed delivery whose resolution failed.
func (m *memStore) ReleaseSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.claims, fmt.Sprintf("%s|%d|%s", jobID, generation, secretName))
	return nil
}

// ---------------------------------------------------------------------------
// runner profiles, per-runner tokens, revocations, enrollment grants
// ---------------------------------------------------------------------------

func (m *memStore) UpsertProfile(ctx context.Context, p model.RunnerProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	m.profiles[p.ID] = p
	return nil
}

func (m *memStore) GetProfile(ctx context.Context, id string) (model.RunnerProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.profiles[id]
	if !ok {
		return model.RunnerProfile{}, ErrNotFound
	}
	return p, nil
}

func (m *memStore) ListProfiles(ctx context.Context) ([]model.RunnerProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.RunnerProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *memStore) BindCertProfile(ctx context.Context, serial, profileID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certProfiles[serial] = profileID
	return nil
}

func (m *memStore) ProfileForSerial(ctx context.Context, serial string) (model.RunnerProfile, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.certProfiles[serial]
	if !ok {
		return model.RunnerProfile{}, false, nil
	}
	p, ok := m.profiles[id]
	if !ok {
		return model.RunnerProfile{}, false, nil
	}
	return p, true, nil
}

func (m *memStore) UpsertRunnerToken(ctx context.Context, runnerID, tokenDigest string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runnerTokens[tokenDigest] = runnerID
	return nil
}

func (m *memStore) RunnerIDForToken(ctx context.Context, tokenDigest string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.runnerTokens[tokenDigest]
	return id, ok, nil
}

func (m *memStore) HasRunnerTokens(ctx context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.runnerTokens) > 0, nil
}

func (m *memStore) RevokeCert(ctx context.Context, serial, runnerID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revocations[serial] = runnerID
	return nil
}

func (m *memStore) CertRevoked(ctx context.Context, serial string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revocations[serial]
	return ok, nil
}

func (m *memStore) PutEnrollGrant(ctx context.Context, digest string, expiresAt time.Time, boundLabels []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[digest] = EnrollGrantRecord{ExpiresAt: expiresAt, BoundLabels: append([]string(nil), boundLabels...)}
	return nil
}

func (m *memStore) GetEnrollGrant(ctx context.Context, digest string) (EnrollGrantRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.grants[digest]
	return rec, ok, nil
}

// ConsumeEnrollGrant mirrors the SQL conditional update under m.mu: exactly
// one consumer of a grant succeeds; unknown digests return ErrNotFound,
// consumed ones ErrGrantConsumed and expired ones ErrGrantExpired.
func (m *memStore) ConsumeEnrollGrant(ctx context.Context, digest string, consumedBy string) (EnrollGrantRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.grants[digest]
	if !ok {
		return EnrollGrantRecord{}, ErrNotFound
	}
	if rec.Consumed {
		return EnrollGrantRecord{}, ErrGrantConsumed
	}
	if !time.Now().UTC().Before(rec.ExpiresAt) {
		return EnrollGrantRecord{}, ErrGrantExpired
	}
	rec.Consumed = true
	m.grants[digest] = rec
	return rec, nil
}

func (m *memStore) LoadTestHistory(ctx context.Context) (int64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.testHistoryVersion, append([]byte(nil), m.testHistoryStats...), nil
}

func (m *memStore) SaveTestHistory(ctx context.Context, stats []byte) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.testHistoryVersion++
	m.testHistoryStats = append([]byte(nil), stats...)
	return m.testHistoryVersion, nil
}
