package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	// countRunningJobsErr, when non-nil, is returned by CountRunningJobs
	// instead of delegating to Inner. The general FailAfter counter is
	// write-only by design, but the drain path must also be provable against
	// a failing in-flight READ: an errored count is UNKNOWN and must never
	// be treated as "zero active jobs, drained".
	countRunningJobsErr error

	// staleLeaderErr, when non-nil, makes every leader-FENCED operation
	// return it before reaching Inner: the fault-injection analogue of a
	// stale leadership epoch (storage.ErrStaleLeader). It is deliberately
	// separate from FailAfter (whose counter models a mutation failing INSIDE
	// the store) because the stale-epoch contract is "rejected before
	// anything is touched".
	staleLeaderErr error
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

// FailFencedWith installs err (typically storage.ErrStaleLeader) as the
// result of every leader-fenced operation without touching Inner, so tests
// can prove the stale-leader fail-closed contract on the wrapper path too.
// A nil err disables the injection.
func (f *FaultyStore) FailFencedWith(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.staleLeaderErr = err
}

// fencedFail reports the injected stale-leader error, if any. It is checked
// BEFORE fail() so the fence rejection never consumes a mutation fault.
func (f *FaultyStore) fencedFail() error {
	return f.staleLeaderErr
}

// LeaderFenceStore delegation. The wrapper's fence view is Inner's: when
// Inner implements the contract (memStore, PostgresStore) its retained epoch
// governs and every fenced call behaves exactly like the wrapped store. A
// wrapper over a minimal Store that does not implement the contract reports
// "no retained epoch" (0, false), which is the same fail-closed view the
// wrapped store itself would present.
func (f *FaultyStore) SetLeaderEpoch(epoch int64) {
	if inner, ok := f.Inner.(LeaderFenceStore); ok {
		inner.SetLeaderEpoch(epoch)
	}
}

func (f *FaultyStore) LeaderEpoch() (int64, bool) {
	if inner, ok := f.Inner.(LeaderFenceStore); ok {
		return inner.LeaderEpoch()
	}
	return 0, false
}

func (f *FaultyStore) ClearLeaderEpoch() {
	if inner, ok := f.Inner.(LeaderFenceStore); ok {
		inner.ClearLeaderEpoch()
	}
}

func (f *FaultyStore) ReadLeaderEpoch(ctx context.Context) (int64, error) {
	if inner, ok := f.Inner.(LeaderFenceStore); ok {
		return inner.ReadLeaderEpoch(ctx)
	}
	return 0, nil
}

// Mutations returns how many mutating calls have been attempted so far.
func (f *FaultyStore) Mutations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mutCalls
}

// missingInnerInterfaceError reports that a FaultyStore extension method was
// called on an Inner Store that does not implement the optional interface the
// method delegates to. Wrapper methods return it instead of panicking on a
// bare type assertion, so wrapping a minimal Store fails closed with a
// diagnosable error. The capability check runs before fault injection: a
// missing interface is a wiring error, not a simulated storage failure, and
// must not consume or fire a fault.
type missingInnerInterfaceError struct {
	iface string
}

func (e *missingInnerInterfaceError) Error() string {
	return "storage: inner store does not implement " + e.iface
}

// errMissingInnerInterface builds the fail-closed error for an absent iface.
func errMissingInnerInterface(iface string) error {
	return &missingInnerInterfaceError{iface: iface}
}

var _ Store = (*FaultyStore)(nil)

var (
	_ OutboxStore               = (*FaultyStore)(nil)
	_ OutboxDeadLetterStore     = (*FaultyStore)(nil)
	_ ForgeCheckStateStore      = (*FaultyStore)(nil)
	_ ScheduleStore             = (*FaultyStore)(nil)
	_ DeploymentStore           = (*FaultyStore)(nil)
	_ SnapshotStore             = (*FaultyStore)(nil)
	_ ArtifactContractStore     = (*FaultyStore)(nil)
	_ QueueReasonStore          = (*FaultyStore)(nil)
	_ DynamicStore              = (*FaultyStore)(nil)
	_ DynamicStoreTx            = (*FaultyStore)(nil)
	_ DownstreamStore           = (*FaultyStore)(nil)
	_ UsageStore                = (*FaultyStore)(nil)
	_ UsageOnceStore            = (*FaultyStore)(nil)
	_ RunDownstreamStore        = (*FaultyStore)(nil)
	_ DownstreamParentRunStore  = (*FaultyStore)(nil)
	_ ArtifactLookupStore       = (*FaultyStore)(nil)
	_ RunnerJobStore            = (*FaultyStore)(nil)
	_ RunEnqueueStore           = (*FaultyStore)(nil)
	_ AtomicLeaseStore          = (*FaultyStore)(nil)
	_ QuotaCounterStore         = (*FaultyStore)(nil)
	_ CacheManifestStore        = (*FaultyStore)(nil)
	_ ArtifactSidecarStore      = (*FaultyStore)(nil)
	_ SecretClaimStore          = (*FaultyStore)(nil)
	_ SecretClaimReleaser       = (*FaultyStore)(nil)
	_ ProfileStore              = (*FaultyStore)(nil)
	_ RunnerTokenStore          = (*FaultyStore)(nil)
	_ CertRevocationStore       = (*FaultyStore)(nil)
	_ EnrollGrantStore          = (*FaultyStore)(nil)
	_ TestHistoryStore          = (*FaultyStore)(nil)
	_ TestHistoryAggregateStore = (*FaultyStore)(nil)
	_ TestReportDeliveryStore   = (*FaultyStore)(nil)
	_ RunnerDisableStore        = (*FaultyStore)(nil)
	_ ResourceReservationStore  = (*FaultyStore)(nil)
	_ ArtifactIdempotentStore   = (*FaultyStore)(nil)
	_ GeneratedFragmentStore    = (*FaultyStore)(nil)
	_ RecoveryStore             = (*FaultyStore)(nil)
	_ RecoveryScanStore         = (*FaultyStore)(nil)
	_ OutboxClaimBatchStore     = (*FaultyStore)(nil)
	_ LeaderFenceStore          = (*FaultyStore)(nil)
	_ RunPageStore              = (*FaultyStore)(nil)
	_ RunnerProfileLinkStore    = (*FaultyStore)(nil)
	_ LiveProfileResolver       = (*FaultyStore)(nil)
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

// ListRunsPage delegates the keyset-paged run read to Inner when it
// implements RunPageStore, and fails closed with a diagnosable capability
// error otherwise. It is a READ: the FailAfter mutation counter is never
// consumed, exactly like ListRuns.
func (f *FaultyStore) ListRunsPage(ctx context.Context, afterCreatedAt time.Time, afterID string, limit int) (RunPage, error) {
	inner, ok := f.Inner.(RunPageStore)
	if !ok {
		return RunPage{}, errMissingInnerInterface("RunPageStore")
	}
	return inner.ListRunsPage(ctx, afterCreatedAt, afterID, limit)
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

// MetricsAggregateStore delegation: the DB-mode state gauges read through the
// wrapper exactly like the raw store. The methods are plain reads (they never
// consume the write-fault counter); a wrapper over an Inner that does not
// implement the contract fails closed with a diagnosable capability error
// instead of falling back to run sampling.
func (f *FaultyStore) RunStatusCounts(ctx context.Context) (map[model.Status]int, error) {
	inner, ok := f.Inner.(MetricsAggregateStore)
	if !ok {
		return nil, errMissingInnerInterface("MetricsAggregateStore")
	}
	return inner.RunStatusCounts(ctx)
}

func (f *FaultyStore) JobStatusCounts(ctx context.Context) (map[model.Status]int, error) {
	inner, ok := f.Inner.(MetricsAggregateStore)
	if !ok {
		return nil, errMissingInnerInterface("MetricsAggregateStore")
	}
	return inner.JobStatusCounts(ctx)
}

func (f *FaultyStore) QueuedJobQueueReasonCounts(ctx context.Context) (map[string]int, error) {
	inner, ok := f.Inner.(MetricsAggregateStore)
	if !ok {
		return nil, errMissingInnerInterface("MetricsAggregateStore")
	}
	return inner.QueuedJobQueueReasonCounts(ctx)
}

func (f *FaultyStore) RunnerSlotTotals(ctx context.Context) (RunnerSlotTotals, error) {
	inner, ok := f.Inner.(MetricsAggregateStore)
	if !ok {
		return RunnerSlotTotals{}, errMissingInnerInterface("MetricsAggregateStore")
	}
	return inner.RunnerSlotTotals(ctx)
}

// CountRunningJobs passes through to Inner, reads never consume the
// write-fault counter, so a drain count can only fail when the configured
// CountRunningJobs fault is armed.
func (f *FaultyStore) CountRunningJobs(ctx context.Context) (int, error) {
	f.mu.Lock()
	err := f.countRunningJobsErr
	f.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return f.Inner.CountRunningJobs(ctx)
}

// SetCountRunningJobsError installs (or clears, with nil) the injected
// CountRunningJobs failure. It is safe to call while a drain poll is running.
func (f *FaultyStore) SetCountRunningJobsError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.countRunningJobsErr = err
}

func (f *FaultyStore) ListQueuedJobs(ctx context.Context) ([]model.Job, error) {
	return f.Inner.ListQueuedJobs(ctx)
}

func (f *FaultyStore) ListJobsByEnvironment(ctx context.Context, repoID, environment string) ([]model.Job, error) {
	return f.Inner.ListJobsByEnvironment(ctx, repoID, environment)
}

func (f *FaultyStore) ListJobsByRunner(ctx context.Context, runnerID string) ([]model.Job, error) {
	inner, ok := f.Inner.(RunnerJobStore)
	if !ok {
		return nil, errMissingInnerInterface("RunnerJobStore")
	}
	return inner.ListJobsByRunner(ctx, runnerID)
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

func (f *FaultyStore) RevokeRunnerLeases(ctx context.Context, runnerID, reason string) ([]string, error) {
	inner, ok := f.Inner.(RecoveryStore)
	if !ok {
		return nil, errMissingInnerInterface("RecoveryStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return nil, err
	}
	return inner.RevokeRunnerLeases(ctx, runnerID, reason)
}

// DisableRunnerAndRevokeCert is a mutating wrapper: an armed fault fails the
// whole atomic disable before the inner store is touched, so the injected
// failure can never leave a partial disable/revocation (the fail-closed
// contract the server relies on).
func (f *FaultyStore) DisableRunnerAndRevokeCert(ctx context.Context, runnerID, certSerial, actor string) (int, error) {
	inner, ok := f.Inner.(RunnerDisableStore)
	if !ok {
		return 0, errMissingInnerInterface("RunnerDisableStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return 0, err
	}
	return inner.DisableRunnerAndRevokeCert(ctx, runnerID, certSerial, actor)
}

func (f *FaultyStore) RecoverExpiredLease(ctx context.Context, jobID string, expectedGeneration int64, now time.Time) error {
	inner, ok := f.Inner.(RecoveryStore)
	if !ok {
		return errMissingInnerInterface("RecoveryStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return err
	}
	if err := f.fail(); err != nil {
		return err
	}
	return inner.RecoverExpiredLease(ctx, jobID, expectedGeneration, now)
}

func (f *FaultyStore) ExpireQueuedJob(ctx context.Context, jobID string, deadline time.Time) error {
	inner, ok := f.Inner.(RecoveryStore)
	if !ok {
		return errMissingInnerInterface("RecoveryStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return err
	}
	if err := f.fail(); err != nil {
		return err
	}
	return inner.ExpireQueuedJob(ctx, jobID, deadline)
}

// ListExpiredRunningJobs and ListQueueTimedOutJobs are read-only discovery
// passthroughs: reads never consume the write-fault counter, so a sweep's
// paging view can only fail through the inner store itself (the applier
// failures that must not stall a sweep are injected on RecoverExpiredLease /
// ExpireQueuedJob instead).
func (f *FaultyStore) ListExpiredRunningJobs(ctx context.Context, now time.Time, afterID string, limit int) ([]RecoveryCandidate, error) {
	inner, ok := f.Inner.(RecoveryDiscoveryStore)
	if !ok {
		return nil, errMissingInnerInterface("RecoveryDiscoveryStore")
	}
	return inner.ListExpiredRunningJobs(ctx, now, afterID, limit)
}

func (f *FaultyStore) ListQueueTimedOutJobs(ctx context.Context, now time.Time, afterID string, limit int) ([]RecoveryCandidate, error) {
	inner, ok := f.Inner.(RecoveryDiscoveryStore)
	if !ok {
		return nil, errMissingInnerInterface("RecoveryDiscoveryStore")
	}
	return inner.ListQueueTimedOutJobs(ctx, now, afterID, limit)
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
	inner, ok := f.Inner.(ArtifactIdempotentStore)
	if !ok {
		return model.ArtifactRecord{}, false, errMissingInnerInterface("ArtifactIdempotentStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	return inner.InsertArtifactOnce(ctx, a)
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
// interfaces (the fault-injection memStore does). A wrapper around a Store
// that lacks one returns a typed missing-interface error (fail closed)
// instead of panicking on a bare type assertion; the capability check runs
// before fault injection so a wiring error never fires or consumes a fault.
// ---------------------------------------------------------------------------

func (f *FaultyStore) OutboxAppend(ctx context.Context, e OutboxItem) error {
	inner, ok := f.Inner.(OutboxStore)
	if !ok {
		return errMissingInnerInterface("OutboxStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.OutboxAppend(ctx, e)
}

func (f *FaultyStore) OutboxAck(ctx context.Context, id string) error {
	inner, ok := f.Inner.(OutboxStore)
	if !ok {
		return errMissingInnerInterface("OutboxStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return err
	}
	if err := f.fail(); err != nil {
		return err
	}
	return inner.OutboxAck(ctx, id)
}

// OutboxEnqueueVersioned delegates the versioned enqueue to the inner store
// (the fault-injection memStore implements the same supersede/watermark
// semantics as the SQL store).
func (f *FaultyStore) OutboxEnqueueVersioned(ctx context.Context, e OutboxItem) (VersionedEnqueueOutcome, error) {
	inner, ok := f.Inner.(ForgeCheckStateStore)
	if !ok {
		return VersionedEnqueued, errMissingInnerInterface("ForgeCheckStateStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return VersionedEnqueued, err
	}
	return inner.OutboxEnqueueVersioned(ctx, e)
}

// OutboxVersionGuard is a read-only guard: a guard failure must never be
// converted into "publish anyway" by fault injection.
func (f *FaultyStore) OutboxVersionGuard(ctx context.Context, id, logicalKey string, version int64) (bool, error) {
	inner, ok := f.Inner.(ForgeCheckStateStore)
	if !ok {
		return false, errMissingInnerInterface("ForgeCheckStateStore")
	}
	return inner.OutboxVersionGuard(ctx, id, logicalKey, version)
}

// OutboxMarkDelivered delegates the post-publication watermark stamp to the
// inner store (legacy unversioned forge rows).
func (f *FaultyStore) OutboxMarkDelivered(ctx context.Context, logicalKey string, version int64) error {
	inner, ok := f.Inner.(ForgeCheckStateStore)
	if !ok {
		return errMissingInnerInterface("ForgeCheckStateStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.OutboxMarkDelivered(ctx, logicalKey, version)
}

func (f *FaultyStore) OutboxPending(ctx context.Context) ([]OutboxItem, error) {
	inner, ok := f.Inner.(OutboxStore)
	if !ok {
		return nil, errMissingInnerInterface("OutboxStore")
	}
	return inner.OutboxPending(ctx)
}

func (f *FaultyStore) ClaimOutbox(ctx context.Context, claimer string, limit int) ([]OutboxItem, error) {
	inner, ok := f.Inner.(OutboxStore)
	if !ok {
		return nil, errMissingInnerInterface("OutboxStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return nil, err
	}
	if err := f.fail(); err != nil {
		return nil, err
	}
	return inner.ClaimOutbox(ctx, claimer, limit)
}

func (f *FaultyStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	inner, ok := f.Inner.(OutboxStore)
	if !ok {
		return errMissingInnerInterface("OutboxStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return err
	}
	if err := f.fail(); err != nil {
		return err
	}
	return inner.ReleaseOutboxClaim(ctx, id, claimer)
}

// ReleaseOutboxClaims delegates the BATCH release to the inner store under
// the same fault counter as every other mutation: the wrapper is the
// sanctioned way to prove one aggregate cleanup either releases the whole
// matching batch or fails without touching any claim.
func (f *FaultyStore) ReleaseOutboxClaims(ctx context.Context, ids []string, claimer string) (int, error) {
	inner, ok := f.Inner.(OutboxClaimBatchStore)
	if !ok {
		return 0, errMissingInnerInterface("OutboxClaimBatchStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return 0, err
	}
	if err := f.fail(); err != nil {
		return 0, err
	}
	return inner.ReleaseOutboxClaims(ctx, ids, claimer)
}

// OutboxRetry delegates the retry/dead-letter transition to the inner store
// (the fault-injection memStore implements the same policy as the SQL store).
func (f *FaultyStore) OutboxRetry(ctx context.Context, id string, dispatchErr error, maxAttempts int) error {
	inner, ok := f.Inner.(interface {
		OutboxRetry(context.Context, string, error, int) error
	})
	if !ok {
		return errMissingInnerInterface("OutboxRetry")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.OutboxRetry(ctx, id, dispatchErr, maxAttempts)
}

func (f *FaultyStore) OutboxDeadLetters(ctx context.Context) ([]OutboxDeadLetter, error) {
	inner, ok := f.Inner.(OutboxDeadLetterStore)
	if !ok {
		return nil, errMissingInnerInterface("OutboxDeadLetterStore")
	}
	return inner.OutboxDeadLetters(ctx)
}

func (f *FaultyStore) OutboxRequeue(ctx context.Context, id string) error {
	inner, ok := f.Inner.(OutboxDeadLetterStore)
	if !ok {
		return errMissingInnerInterface("OutboxDeadLetterStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.OutboxRequeue(ctx, id)
}

func (f *FaultyStore) OutboxDelete(ctx context.Context, id string) error {
	inner, ok := f.Inner.(OutboxDeadLetterStore)
	if !ok {
		return errMissingInnerInterface("OutboxDeadLetterStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.OutboxDelete(ctx, id)
}

func (f *FaultyStore) UpsertSchedule(ctx context.Context, sc Schedule) error {
	inner, ok := f.Inner.(ScheduleStore)
	if !ok {
		return errMissingInnerInterface("ScheduleStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.UpsertSchedule(ctx, sc)
}

func (f *FaultyStore) ListSchedules(ctx context.Context) ([]Schedule, error) {
	inner, ok := f.Inner.(ScheduleStore)
	if !ok {
		return nil, errMissingInnerInterface("ScheduleStore")
	}
	return inner.ListSchedules(ctx)
}

func (f *FaultyStore) ClaimScheduleOccurrence(ctx context.Context, scheduleID string, nominal time.Time, runID string) (bool, error) {
	inner, ok := f.Inner.(ScheduleStore)
	if !ok {
		return false, errMissingInnerInterface("ScheduleStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return false, err
	}
	if err := f.fail(); err != nil {
		return false, err
	}
	return inner.ClaimScheduleOccurrence(ctx, scheduleID, nominal, runID)
}

func (f *FaultyStore) ListOccurrences(ctx context.Context, scheduleID string) ([]Occurrence, error) {
	inner, ok := f.Inner.(ScheduleStore)
	if !ok {
		return nil, errMissingInnerInterface("ScheduleStore")
	}
	return inner.ListOccurrences(ctx, scheduleID)
}

func (f *FaultyStore) AdvanceScheduleLastRun(ctx context.Context, id string, nominal time.Time) error {
	inner, ok := f.Inner.(ScheduleStore)
	if !ok {
		return errMissingInnerInterface("ScheduleStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return err
	}
	if err := f.fail(); err != nil {
		return err
	}
	return inner.AdvanceScheduleLastRun(ctx, id, nominal)
}

func (f *FaultyStore) InsertDeployment(ctx context.Context, d model.Deployment) error {
	inner, ok := f.Inner.(DeploymentStore)
	if !ok {
		return errMissingInnerInterface("DeploymentStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.InsertDeployment(ctx, d)
}

func (f *FaultyStore) ListDeploymentsByRun(ctx context.Context, runID string) ([]model.Deployment, error) {
	inner, ok := f.Inner.(DeploymentStore)
	if !ok {
		return nil, errMissingInnerInterface("DeploymentStore")
	}
	return inner.ListDeploymentsByRun(ctx, runID)
}

func (f *FaultyStore) UpdateDeploymentStatus(ctx context.Context, id string, status model.Status, finishedAt *time.Time) error {
	inner, ok := f.Inner.(DeploymentStore)
	if !ok {
		return errMissingInnerInterface("DeploymentStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.UpdateDeploymentStatus(ctx, id, status, finishedAt)
}

func (f *FaultyStore) InsertSnapshotRecord(ctx context.Context, rec model.SnapshotRecord) error {
	inner, ok := f.Inner.(SnapshotStore)
	if !ok {
		return errMissingInnerInterface("SnapshotStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.InsertSnapshotRecord(ctx, rec)
}

func (f *FaultyStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	inner, ok := f.Inner.(SnapshotStore)
	if !ok {
		return nil, errMissingInnerInterface("SnapshotStore")
	}
	return inner.ListSnapshotsByRun(ctx, runID)
}

func (f *FaultyStore) InsertJobContracts(ctx context.Context, jobID string, contracts map[string]ArtifactContract) error {
	inner, ok := f.Inner.(ArtifactContractStore)
	if !ok {
		return errMissingInnerInterface("ArtifactContractStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.InsertJobContracts(ctx, jobID, contracts)
}

func (f *FaultyStore) GetJobContracts(ctx context.Context, jobID string) (map[string]ArtifactContract, bool, error) {
	inner, ok := f.Inner.(ArtifactContractStore)
	if !ok {
		return nil, false, errMissingInnerInterface("ArtifactContractStore")
	}
	return inner.GetJobContracts(ctx, jobID)
}

func (f *FaultyStore) SetQueueReasons(ctx context.Context, reasons map[string]string) error {
	inner, ok := f.Inner.(QueueReasonStore)
	if !ok {
		return errMissingInnerInterface("QueueReasonStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.SetQueueReasons(ctx, reasons)
}

func (f *FaultyStore) InsertGeneratedJobs(ctx context.Context, parentJobID string, depth int, jobs map[string]model.Job, deps map[string][]string) error {
	inner, ok := f.Inner.(DynamicStore)
	if !ok {
		return errMissingInnerInterface("DynamicStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.InsertGeneratedJobs(ctx, parentJobID, depth, jobs, deps)
}

func (f *FaultyStore) InsertDownstreamLink(ctx context.Context, l DownstreamLink) error {
	inner, ok := f.Inner.(DownstreamStore)
	if !ok {
		return errMissingInnerInterface("DownstreamStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.InsertDownstreamLink(ctx, l)
}

func (f *FaultyStore) GetDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (DownstreamLink, bool, error) {
	inner, ok := f.Inner.(DownstreamStore)
	if !ok {
		return DownstreamLink{}, false, errMissingInnerInterface("DownstreamStore")
	}
	return inner.GetDownstreamLink(ctx, parentJobID, targetRepo, targetRef)
}

func (f *FaultyStore) MarkDownstreamLaunched(ctx context.Context, parentJobID, targetRepo, targetRef, childRunID string) error {
	inner, ok := f.Inner.(DownstreamStore)
	if !ok {
		return errMissingInnerInterface("DownstreamStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.MarkDownstreamLaunched(ctx, parentJobID, targetRepo, targetRef, childRunID)
}

func (f *FaultyStore) RecentUsage(ctx context.Context, since time.Time) (float64, float64, error) {
	inner, ok := f.Inner.(UsageStore)
	if !ok {
		return 0, 0, errMissingInnerInterface("UsageStore")
	}
	return inner.RecentUsage(ctx, since)
}

func (f *FaultyStore) RecordUsageOnce(ctx context.Context, jobID string, cost, energyWh float64) (bool, error) {
	inner, ok := f.Inner.(UsageOnceStore)
	if !ok {
		return false, errMissingInnerInterface("UsageOnceStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return false, err
	}
	return inner.RecordUsageOnce(ctx, jobID, cost, energyWh)
}

func (f *FaultyStore) AppendDownstreamRun(ctx context.Context, runID, childRunID string) error {
	inner, ok := f.Inner.(RunDownstreamStore)
	if !ok {
		return errMissingInnerInterface("RunDownstreamStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.AppendDownstreamRun(ctx, runID, childRunID)
}

func (f *FaultyStore) ReopenRunForChildren(ctx context.Context, runID string) error {
	inner, ok := f.Inner.(RunDownstreamStore)
	if !ok {
		return errMissingInnerInterface("RunDownstreamStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.ReopenRunForChildren(ctx, runID)
}

// ParentRunIDsForChild is a READ of the downstream reverse index, so it
// passes through to Inner unchanged (FaultyStore injects write faults only).
func (f *FaultyStore) ParentRunIDsForChild(ctx context.Context, childRunID string) ([]string, error) {
	inner, ok := f.Inner.(DownstreamParentRunStore)
	if !ok {
		return nil, errMissingInnerInterface("DownstreamParentRunStore")
	}
	return inner.ParentRunIDsForChild(ctx, childRunID)
}

func (f *FaultyStore) GetArtifact(ctx context.Context, id string) (model.ArtifactRecord, error) {
	inner, ok := f.Inner.(ArtifactLookupStore)
	if !ok {
		return model.ArtifactRecord{}, errMissingInnerInterface("ArtifactLookupStore")
	}
	return inner.GetArtifact(ctx, id)
}

// ---------------------------------------------------------------------------
// atomicity/storage round extension methods. The Inner Store must also
// implement these interfaces (the fault-injection memStore does). Wrappers
// fail closed with a typed missing-interface error when it does not.
// ---------------------------------------------------------------------------

func (f *FaultyStore) InsertCompiledRun(ctx context.Context, req InsertCompiledRunRequest) error {
	inner, ok := f.Inner.(RunEnqueueStore)
	if !ok {
		return errMissingInnerInterface("RunEnqueueStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// A schedule occurrence claim makes the enqueue leader-only, so the
	// stale-leader injection applies to it exactly as it does to the inner
	// store's fenced branch. Ordinary submissions are not fenced.
	if req.ScheduleClaim != nil {
		if err := f.fencedFail(); err != nil {
			return err
		}
	}
	if err := f.fail(); err != nil {
		return err
	}
	return inner.InsertCompiledRun(ctx, req)
}

func (f *FaultyStore) AcquireLeaseAtomic(ctx context.Context, claim LeaseClaim) (model.Job, error) {
	inner, ok := f.Inner.(AtomicLeaseStore)
	if !ok {
		return model.Job{}, errMissingInnerInterface("AtomicLeaseStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return model.Job{}, err
	}
	return inner.AcquireLeaseAtomic(ctx, claim)
}

func (f *FaultyStore) AdjustQuotaCounter(ctx context.Context, repoKey, teamKey string, runningDelta, queuedDelta int) error {
	inner, ok := f.Inner.(QuotaCounterStore)
	if !ok {
		return errMissingInnerInterface("QuotaCounterStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.AdjustQuotaCounter(ctx, repoKey, teamKey, runningDelta, queuedDelta)
}

func (f *FaultyStore) QuotaCounts(ctx context.Context, repoKey, teamKey string) (int, int, error) {
	inner, ok := f.Inner.(QuotaCounterStore)
	if !ok {
		return 0, 0, errMissingInnerInterface("QuotaCounterStore")
	}
	return inner.QuotaCounts(ctx, repoKey, teamKey)
}

func (f *FaultyStore) ReserveDownstreamLaunch(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	inner, ok := f.Inner.(DownstreamStore)
	if !ok {
		return false, errMissingInnerInterface("DownstreamStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return false, err
	}
	return inner.ReserveDownstreamLaunch(ctx, parentJobID, targetRepo, targetRef, launchToken)
}

func (f *FaultyStore) ReleaseDownstreamReservation(ctx context.Context, parentJobID, targetRepo, targetRef string) error {
	inner, ok := f.Inner.(DownstreamStore)
	if !ok {
		return errMissingInnerInterface("DownstreamStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.ReleaseDownstreamReservation(ctx, parentJobID, targetRepo, targetRef)
}

func (f *FaultyStore) ExpireDownstreamReservations(ctx context.Context, olderThan time.Time) (int, error) {
	inner, ok := f.Inner.(DownstreamStore)
	if !ok {
		return 0, errMissingInnerInterface("DownstreamStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return 0, err
	}
	if err := f.fail(); err != nil {
		return 0, err
	}
	return inner.ExpireDownstreamReservations(ctx, olderThan)
}

func (f *FaultyStore) InsertGeneratedFragmentTx(ctx context.Context, req GeneratedFragmentRequest, verify GeneratedJobVerifier) (GeneratedFragmentReceipt, bool, error) {
	inner, ok := f.Inner.(DynamicStoreTx)
	if !ok {
		return GeneratedFragmentReceipt{}, false, errMissingInnerInterface("DynamicStoreTx")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	return inner.InsertGeneratedFragmentTx(ctx, req, verify)
}

func (f *FaultyStore) GetGeneratedFragment(ctx context.Context, parentJobID string, generation int64, fragmentID string) (GeneratedFragmentReceipt, bool, error) {
	inner, ok := f.Inner.(GeneratedFragmentStore)
	if !ok {
		return GeneratedFragmentReceipt{}, false, errMissingInnerInterface("GeneratedFragmentStore")
	}
	return inner.GetGeneratedFragment(ctx, parentJobID, generation, fragmentID)
}

func (f *FaultyStore) PutCacheManifest(ctx context.Context, rec CacheManifestRecord) error {
	inner, ok := f.Inner.(CacheManifestStore)
	if !ok {
		return errMissingInnerInterface("CacheManifestStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.PutCacheManifest(ctx, rec)
}

func (f *FaultyStore) GetCacheManifest(ctx context.Context, repo, trustDomain, logicalKey string) (CacheManifestRecord, bool, error) {
	inner, ok := f.Inner.(CacheManifestStore)
	if !ok {
		return CacheManifestRecord{}, false, errMissingInnerInterface("CacheManifestStore")
	}
	return inner.GetCacheManifest(ctx, repo, trustDomain, logicalKey)
}

func (f *FaultyStore) SetArtifactSidecars(ctx context.Context, artifactID, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256 string) error {
	inner, ok := f.Inner.(ArtifactSidecarStore)
	if !ok {
		return errMissingInnerInterface("ArtifactSidecarStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.SetArtifactSidecars(ctx, artifactID, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256)
}

func (f *FaultyStore) RememberPendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind, digest string) error {
	inner, ok := f.Inner.(ArtifactSidecarStore)
	if !ok {
		return errMissingInnerInterface("ArtifactSidecarStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.RememberPendingSidecar(ctx, jobID, generation, artifactName, kind, digest)
}

func (f *FaultyStore) PendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind string) (string, bool, error) {
	inner, ok := f.Inner.(ArtifactSidecarStore)
	if !ok {
		return "", false, errMissingInnerInterface("ArtifactSidecarStore")
	}
	return inner.PendingSidecar(ctx, jobID, generation, artifactName, kind)
}

func (f *FaultyStore) ConsumePendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind, digest string) error {
	inner, ok := f.Inner.(ArtifactSidecarStore)
	if !ok {
		return errMissingInnerInterface("ArtifactSidecarStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.ConsumePendingSidecar(ctx, jobID, generation, artifactName, kind, digest)
}

func (f *FaultyStore) PrunePendingSidecars(ctx context.Context, olderThan time.Time) (int, error) {
	inner, ok := f.Inner.(ArtifactSidecarStore)
	if !ok {
		return 0, errMissingInnerInterface("ArtifactSidecarStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return 0, err
	}
	if err := f.fail(); err != nil {
		return 0, err
	}
	return inner.PrunePendingSidecars(ctx, olderThan)
}

func (f *FaultyStore) ClaimSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) (bool, error) {
	inner, ok := f.Inner.(SecretClaimStore)
	if !ok {
		return false, errMissingInnerInterface("SecretClaimStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return false, err
	}
	return inner.ClaimSecretDelivery(ctx, jobID, generation, secretName)
}

func (f *FaultyStore) ReleaseSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) error {
	inner, ok := f.Inner.(SecretClaimReleaser)
	if !ok {
		return errMissingInnerInterface("SecretClaimReleaser")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.ReleaseSecretDelivery(ctx, jobID, generation, secretName)
}

func (f *FaultyStore) UpsertProfile(ctx context.Context, p model.RunnerProfile) error {
	inner, ok := f.Inner.(ProfileStore)
	if !ok {
		return errMissingInnerInterface("ProfileStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.UpsertProfile(ctx, p)
}

func (f *FaultyStore) GetProfile(ctx context.Context, id string) (model.RunnerProfile, error) {
	inner, ok := f.Inner.(ProfileStore)
	if !ok {
		return model.RunnerProfile{}, errMissingInnerInterface("ProfileStore")
	}
	return inner.GetProfile(ctx, id)
}

func (f *FaultyStore) ListProfiles(ctx context.Context) ([]model.RunnerProfile, error) {
	inner, ok := f.Inner.(ProfileStore)
	if !ok {
		return nil, errMissingInnerInterface("ProfileStore")
	}
	return inner.ListProfiles(ctx)
}

func (f *FaultyStore) BindCertProfile(ctx context.Context, serial, profileID string) error {
	inner, ok := f.Inner.(ProfileStore)
	if !ok {
		return errMissingInnerInterface("ProfileStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.BindCertProfile(ctx, serial, profileID)
}

func (f *FaultyStore) ProfileForSerial(ctx context.Context, serial string) (model.RunnerProfile, bool, error) {
	inner, ok := f.Inner.(ProfileStore)
	if !ok {
		return model.RunnerProfile{}, false, errMissingInnerInterface("ProfileStore")
	}
	return inner.ProfileForSerial(ctx, serial)
}

func (f *FaultyStore) LinkRunnerProfile(ctx context.Context, runnerID, profileID string) error {
	inner, ok := f.Inner.(RunnerProfileLinkStore)
	if !ok {
		return errMissingInnerInterface("RunnerProfileLinkStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.LinkRunnerProfile(ctx, runnerID, profileID)
}

func (f *FaultyStore) ProfileForRunnerID(ctx context.Context, runnerID string) (model.RunnerProfile, bool, error) {
	inner, ok := f.Inner.(RunnerProfileLinkStore)
	if !ok {
		return model.RunnerProfile{}, false, errMissingInnerInterface("RunnerProfileLinkStore")
	}
	return inner.ProfileForRunnerID(ctx, runnerID)
}

func (f *FaultyStore) UnlinkRunnerProfile(ctx context.Context, runnerID string) error {
	inner, ok := f.Inner.(RunnerProfileLinkStore)
	if !ok {
		return errMissingInnerInterface("RunnerProfileLinkStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.UnlinkRunnerProfile(ctx, runnerID)
}

func (f *FaultyStore) RunnerIDsForProfile(ctx context.Context, profileID string) ([]string, error) {
	inner, ok := f.Inner.(RunnerProfileLinkStore)
	if !ok {
		return nil, errMissingInnerInterface("RunnerProfileLinkStore")
	}
	return inner.RunnerIDsForProfile(ctx, profileID)
}

// ResolveLiveRunnerProfile delegates the shared live resolution to the
// wrapped store so the scheduler prefilter and the queue explainers keep the
// same effective profile under fault injection; a missing inner contract is a
// wiring error, not a simulated failure (read paths inject no faults).
func (f *FaultyStore) ResolveLiveRunnerProfile(ctx context.Context, runnerID, serial string) (LiveProfileResolution, error) {
	inner, ok := f.Inner.(LiveProfileResolver)
	if !ok {
		return LiveProfileResolution{}, errMissingInnerInterface("LiveProfileResolver")
	}
	return inner.ResolveLiveRunnerProfile(ctx, runnerID, serial)
}

// RunnerReservedResources / ListResourceReservations delegate the
// reservation-ledger reads to the wrapped store (the lease claim itself is
// delegated through AcquireLeaseAtomic, fault-injectable like every other
// mutation).
func (f *FaultyStore) RunnerReservedResources(ctx context.Context, runnerID string) (model.ResourceCapacity, error) {
	inner, ok := f.Inner.(ResourceReservationStore)
	if !ok {
		return model.ResourceCapacity{}, errMissingInnerInterface("ResourceReservationStore")
	}
	return inner.RunnerReservedResources(ctx, runnerID)
}

func (f *FaultyStore) ListResourceReservations(ctx context.Context, runnerID string) ([]ResourceReservation, error) {
	inner, ok := f.Inner.(ResourceReservationStore)
	if !ok {
		return nil, errMissingInnerInterface("ResourceReservationStore")
	}
	return inner.ListResourceReservations(ctx, runnerID)
}

// ReconcileResourceReservations delegates the leader-fenced promotion/repair
// reconciliation to the wrapped store. The capability check runs first (a
// missing contract is a wiring error, not a simulated failure), then the
// injected stale-leader error, then the write-fault counter — the same order
// every other fenced mutation uses.
func (f *FaultyStore) ReconcileResourceReservations(ctx context.Context) (ResourceReconcileResult, error) {
	inner, ok := f.Inner.(ResourceReconcileStore)
	if !ok {
		return ResourceReconcileResult{}, errMissingInnerInterface("ResourceReconcileStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fencedFail(); err != nil {
		return ResourceReconcileResult{}, err
	}
	if err := f.fail(); err != nil {
		return ResourceReconcileResult{}, err
	}
	return inner.ReconcileResourceReservations(ctx)
}

func (f *FaultyStore) UpsertRunnerToken(ctx context.Context, runnerID, tokenDigest string) error {
	inner, ok := f.Inner.(RunnerTokenStore)
	if !ok {
		return errMissingInnerInterface("RunnerTokenStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.UpsertRunnerToken(ctx, runnerID, tokenDigest)
}

func (f *FaultyStore) RunnerIDForToken(ctx context.Context, tokenDigest string) (string, bool, error) {
	inner, ok := f.Inner.(RunnerTokenStore)
	if !ok {
		return "", false, errMissingInnerInterface("RunnerTokenStore")
	}
	return inner.RunnerIDForToken(ctx, tokenDigest)
}

func (f *FaultyStore) HasRunnerTokens(ctx context.Context) (bool, error) {
	inner, ok := f.Inner.(RunnerTokenStore)
	if !ok {
		return false, errMissingInnerInterface("RunnerTokenStore")
	}
	return inner.HasRunnerTokens(ctx)
}

func (f *FaultyStore) RevokeCert(ctx context.Context, serial, runnerID, reason string) error {
	inner, ok := f.Inner.(CertRevocationStore)
	if !ok {
		return errMissingInnerInterface("CertRevocationStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.RevokeCert(ctx, serial, runnerID, reason)
}

func (f *FaultyStore) CertRevoked(ctx context.Context, serial string) (bool, error) {
	inner, ok := f.Inner.(CertRevocationStore)
	if !ok {
		return false, errMissingInnerInterface("CertRevocationStore")
	}
	return inner.CertRevoked(ctx, serial)
}

func (f *FaultyStore) PutEnrollGrant(ctx context.Context, digest string, expiresAt time.Time, boundLabels []string) error {
	inner, ok := f.Inner.(EnrollGrantStore)
	if !ok {
		return errMissingInnerInterface("EnrollGrantStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.PutEnrollGrant(ctx, digest, expiresAt, boundLabels)
}

func (f *FaultyStore) GetEnrollGrant(ctx context.Context, digest string) (EnrollGrantRecord, bool, error) {
	inner, ok := f.Inner.(EnrollGrantStore)
	if !ok {
		return EnrollGrantRecord{}, false, errMissingInnerInterface("EnrollGrantStore")
	}
	return inner.GetEnrollGrant(ctx, digest)
}

func (f *FaultyStore) ConsumeEnrollGrant(ctx context.Context, digest string, consumedBy string) (EnrollGrantRecord, error) {
	inner, ok := f.Inner.(EnrollGrantStore)
	if !ok {
		return EnrollGrantRecord{}, errMissingInnerInterface("EnrollGrantStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return EnrollGrantRecord{}, err
	}
	return inner.ConsumeEnrollGrant(ctx, digest, consumedBy)
}

func (f *FaultyStore) LoadTestHistory(ctx context.Context) (int64, []byte, error) {
	inner, ok := f.Inner.(TestHistoryStore)
	if !ok {
		return 0, nil, errMissingInnerInterface("TestHistoryStore")
	}
	return inner.LoadTestHistory(ctx)
}

func (f *FaultyStore) SaveTestHistory(ctx context.Context, stats []byte) (int64, error) {
	inner, ok := f.Inner.(TestHistoryStore)
	if !ok {
		return 0, errMissingInnerInterface("TestHistoryStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return 0, err
	}
	return inner.SaveTestHistory(ctx, stats)
}

func (f *FaultyStore) InsertTestReportWithHistory(ctx context.Context, rep model.TestReport, repoID string) (int64, error) {
	inner, ok := f.Inner.(TestHistoryAggregateStore)
	if !ok {
		return 0, errMissingInnerInterface("TestHistoryAggregateStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return 0, err
	}
	return inner.InsertTestReportWithHistory(ctx, rep, repoID)
}

// InsertTestReportWithHistoryDelivery mirrors the wrapper contract for the
// delivery-keyed upload: the injected fault surfaces exactly like the
// non-delivery variant, otherwise the inner store's idempotent transaction
// runs unchanged.
func (f *FaultyStore) InsertTestReportWithHistoryDelivery(ctx context.Context, rep model.TestReport, repoID string, delivery TestReportDelivery) (TestReportInsertOutcome, error) {
	inner, ok := f.Inner.(TestReportDeliveryStore)
	if !ok {
		return TestReportInsertOutcome{}, errMissingInnerInterface("TestReportDeliveryStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return TestReportInsertOutcome{}, err
	}
	return inner.InsertTestReportWithHistoryDelivery(ctx, rep, repoID, delivery)
}

func (f *FaultyStore) LoadRepoTestHistory(ctx context.Context, repoID string) (int64, []byte, error) {
	inner, ok := f.Inner.(TestHistoryAggregateStore)
	if !ok {
		return 0, nil, errMissingInnerInterface("TestHistoryAggregateStore")
	}
	return inner.LoadRepoTestHistory(ctx, repoID)
}

func (f *FaultyStore) ResolveTestHistoryRepoIDs(ctx context.Context, query string, limit int) ([]string, error) {
	inner, ok := f.Inner.(TestHistoryAggregateStore)
	if !ok {
		return nil, errMissingInnerInterface("TestHistoryAggregateStore")
	}
	return inner.ResolveTestHistoryRepoIDs(ctx, query, limit)
}

func (f *FaultyStore) TestReportTotals(ctx context.Context, repoIDs []string, repoQuery string) (int, int, int, error) {
	inner, ok := f.Inner.(TestHistoryAggregateStore)
	if !ok {
		return 0, 0, 0, errMissingInnerInterface("TestHistoryAggregateStore")
	}
	return inner.TestReportTotals(ctx, repoIDs, repoQuery)
}

func (f *FaultyStore) FlakyTestNames(ctx context.Context, repoIDs []string, limit int) ([]string, error) {
	inner, ok := f.Inner.(TestHistoryAggregateStore)
	if !ok {
		return nil, errMissingInnerInterface("TestHistoryAggregateStore")
	}
	return inner.FlakyTestNames(ctx, repoIDs, limit)
}

func (f *FaultyStore) RebuildRepoTestHistory(ctx context.Context, repoID string) (int64, error) {
	inner, ok := f.Inner.(TestHistoryAggregateStore)
	if !ok {
		return 0, errMissingInnerInterface("TestHistoryAggregateStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return 0, err
	}
	return inner.RebuildRepoTestHistory(ctx, repoID)
}

func (f *FaultyStore) ListTestHistoryRepoIDs(ctx context.Context, limit int) ([]string, error) {
	inner, ok := f.Inner.(TestHistoryAggregateStore)
	if !ok {
		return nil, errMissingInnerInterface("TestHistoryAggregateStore")
	}
	return inner.ListTestHistoryRepoIDs(ctx, limit)
}

// memStore is a fully functional in-memory Store used as the fault-free
// baseline underneath FaultyStore in fault-injection tests.
type memStore struct {
	mu sync.Mutex
	// leaderEpoch is the retained leadership epoch (see the memStore fencing
	// note above LeaderEpoch). It starts at 1 — the in-memory store models a
	// single-process replica that always holds the claim — and is cleared to
	// 0 to simulate loss.
	leaderEpoch atomic.Int64
	fenceMu     sync.Mutex
	fences      map[string]*sync.Mutex
	checkRuns   checkRunMem
	logBatches  logBatchMem
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
	// outboxClaims tracks the cross-replica flush claims (claimed_at is
	// compared against OutboxClaimTTL on every claim attempt).
	outboxClaims map[string]outboxClaim
	// outboxMeta tracks the retry/dead-letter state of each durable outbox
	// row, mirroring migration 0015's attempts/last_error/next_attempt_at/
	// dead_lettered_at columns.
	outboxMeta map[string]outboxMeta
	// forgeState tracks the delivered state watermark per logical forge-check
	// key, mirroring migration 0018's forge_check_state table.
	forgeState map[string]int64
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
	// runnerProfiles mirrors migration 0031's runner_profile_links rows: the
	// durable runner-ID -> profile bindings that per-runner bearer
	// identities resolve their profile through (never the client-asserted
	// certificate serial).
	runnerProfiles map[string]string
	runnerTokens   map[string]string
	revocations    map[string]string
	grants         map[string]EnrollGrantRecord

	// reservations mirrors migration 0030's job_resource_reservations rows:
	// the per-lease resource reservations of RUNNING jobs, keyed by job ID.
	// The in-memory lease claim checks and inserts here under m.mu (the
	// single-process capacity guarantee), and every release path deletes the
	// job's row with it.
	reservations map[string]ResourceReservation

	testHistoryVersion int64
	testHistoryStats   []byte
	// historyAggregates / historyVersions mirror migration 0026's
	// test_history_aggregates / test_history_repos for the incremental
	// repository-scoped contract.
	historyAggregates map[string]map[string]TestHistoryAggregate
	historyVersions   map[string]int64
	// reportDeliveries mirrors migration 0029's test_report_deliveries rows:
	// the durable report-delivery receipts that make a retried upload
	// idempotent. Keyed by (job, lease generation, delivery ID).
	reportDeliveries map[string]memReportDelivery

	// enqueueFaultOps, when > 0, makes the next InsertCompiledRun fail after
	// staging that many operations (superseded cancellations first, then
	// enqueued jobs) with enqueueFaultErr: the in-memory analogue of a
	// storage error on the Nth write INSIDE the enqueue transaction. It
	// fires before anything is committed, so fault-injection tests can prove
	// a mid-enqueue failure leaves zero rows (run included). One-shot.
	enqueueFaultOps int
	enqueueFaultErr error

	// recoveryFaultOps, when > 0, makes the next RecoveryStore transaction
	// fail after staging that many operations with recoveryFaultErr: the
	// in-memory analogue of a statement failure at the Nth write INSIDE a
	// recovery transaction. The staged writes are discarded on failure, so
	// tests can prove the whole transition (job, runner slot, quota, run
	// aggregation, audit) rolls back and no partial state is observable.
	// One-shot.
	recoveryFaultOps int
	recoveryFaultErr error

	// undecodableJobs is a TEST-ONLY seam: the listed job ids model a
	// persisted payload the SQL store cannot json.Unmarshal (valid jsonb,
	// invalid model.Job). RecoveryExpiredLease / ExpireQueuedJob treat such a
	// job exactly like the SQL corruption path — terminal transition, lease
	// and capacity released, corruption audit, payload untouched — so the
	// in-memory and real-PostgreSQL recovery semantics stay in parity.
	// Production paths never populate it.
	undecodableJobs map[string]bool
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

// pendingSidecarKey is the in-memory artifact_pending_sidecars primary key:
// the full artifact identity (job, lease generation, artifact name, kind),
// mirroring migration 0028.
func pendingSidecarKey(jobID string, generation int64, artifactName, kind string) string {
	return jobID + "\x00" + strconv.FormatInt(generation, 10) + "\x00" + artifactName + "\x00" + kind
}

// outboxClaim is one in-memory outbox claim lease.
type outboxClaim struct {
	claimer string
	at      time.Time
}

// outboxMeta is the in-memory outbox retry/dead-letter row state.
type outboxMeta struct {
	attempts  int
	lastError string
	nextAt    time.Time
	deadAt    time.Time
}

// fragmentKey is the in-memory generated-fragments primary key.
func fragmentKey(parentJobID string, generation int64, fragmentID string) string {
	return fmt.Sprintf("%s|%d|%s", parentJobID, generation, fragmentID)
}

func newMemStore() *memStore {
	m := &memStore{
		runs:              map[string]model.Run{},
		jobs:              map[string]model.Job{},
		runners:           map[string]model.Runner{},
		receipts:          map[string]model.CompletionReceipt{},
		deliveries:        map[string]string{},
		outboxClaims:      map[string]outboxClaim{},
		outboxMeta:        map[string]outboxMeta{},
		forgeState:        map[string]int64{},
		fragments:         map[string]GeneratedFragmentReceipt{},
		schedules:         map[string]Schedule{},
		occurrences:       map[string]map[time.Time]string{},
		contracts:         map[string]map[string]ArtifactContract{},
		downstream:        map[string]DownstreamLink{},
		quotas:            map[string]quotaCounts{},
		cacheMans:         map[string]CacheManifestRecord{},
		claims:            map[string]time.Time{},
		pendingSidecars:   map[string]pendingSidecar{},
		profiles:          map[string]model.RunnerProfile{},
		certProfiles:      map[string]string{},
		runnerProfiles:    map[string]string{},
		runnerTokens:      map[string]string{},
		revocations:       map[string]string{},
		reservations:      map[string]ResourceReservation{},
		grants:            map[string]EnrollGrantRecord{},
		historyAggregates: map[string]map[string]TestHistoryAggregate{},
		historyVersions:   map[string]int64{},
		reportDeliveries:  map[string]memReportDelivery{},
		undecodableJobs:   map[string]bool{},
	}
	// The in-memory store models a single-process replica that always holds
	// the leadership claim, so it retains the initial epoch 1 (see
	// memStore.LeaderEpoch).
	m.leaderEpoch.Store(1)
	return m
}

var _ Store = (*memStore)(nil)

var (
	_ OutboxStore               = (*memStore)(nil)
	_ OutboxDeadLetterStore     = (*memStore)(nil)
	_ ForgeCheckStateStore      = (*memStore)(nil)
	_ ScheduleStore             = (*memStore)(nil)
	_ DeploymentStore           = (*memStore)(nil)
	_ SnapshotStore             = (*memStore)(nil)
	_ ArtifactContractStore     = (*memStore)(nil)
	_ QueueReasonStore          = (*memStore)(nil)
	_ DynamicStore              = (*memStore)(nil)
	_ DynamicStoreTx            = (*memStore)(nil)
	_ DownstreamStore           = (*memStore)(nil)
	_ UsageStore                = (*memStore)(nil)
	_ UsageOnceStore            = (*memStore)(nil)
	_ RunDownstreamStore        = (*memStore)(nil)
	_ DownstreamParentRunStore  = (*memStore)(nil)
	_ ArtifactLookupStore       = (*memStore)(nil)
	_ RunnerJobStore            = (*memStore)(nil)
	_ RunEnqueueStore           = (*memStore)(nil)
	_ AtomicLeaseStore          = (*memStore)(nil)
	_ QuotaCounterStore         = (*memStore)(nil)
	_ LiveProfileResolver       = (*memStore)(nil)
	_ CacheManifestStore        = (*memStore)(nil)
	_ ArtifactSidecarStore      = (*memStore)(nil)
	_ SecretClaimStore          = (*memStore)(nil)
	_ SecretClaimReleaser       = (*memStore)(nil)
	_ ProfileStore              = (*memStore)(nil)
	_ RunnerProfileLinkStore    = (*memStore)(nil)
	_ ArtifactIdempotentStore   = (*memStore)(nil)
	_ GeneratedFragmentStore    = (*memStore)(nil)
	_ RunnerTokenStore          = (*memStore)(nil)
	_ CertRevocationStore       = (*memStore)(nil)
	_ EnrollGrantStore          = (*memStore)(nil)
	_ TestHistoryStore          = (*memStore)(nil)
	_ TestHistoryAggregateStore = (*memStore)(nil)
	_ TestReportDeliveryStore   = (*memStore)(nil)
	_ RunnerDisableStore        = (*memStore)(nil)
	_ LeaderFenceStore          = (*memStore)(nil)
	_ RecoveryStore             = (*memStore)(nil)
	_ RecoveryScanStore         = (*memStore)(nil)
	_ OutboxClaimBatchStore     = (*memStore)(nil)
	_ RunPageStore              = (*memStore)(nil)
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

// ListRunsPage mirrors the SQL keyset page (see RunPageStore): the same
// (created_at DESC, id DESC) order, the same (created_at, id) < cursor
// predicate and the same bounded limit, computed by the shared PageRuns
// helper so the memory and SQL pages cannot drift. The run map under m.mu is
// a complete view, so paging is deterministic.
func (m *memStore) ListRunsPage(ctx context.Context, afterCreatedAt time.Time, afterID string, limit int) (RunPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	runs := make([]model.Run, 0, len(m.runs))
	for _, r := range m.runs {
		runs = append(runs, r)
	}
	return PageRuns(runs, afterCreatedAt, afterID, limit), nil
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

// MetricsAggregateStore: the in-memory mirror of the SQL aggregates. The
// maps under one mutex are always a complete view, so these counts are the
// reference values the DB-mode gauges must agree with. A canceled context is
// reported as an error (never as an empty/zero map), so the metrics path
// skips the family instead of rendering wrong zeros.
func (m *memStore) RunStatusCounts(ctx context.Context) (map[model.Status]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[model.Status]int, len(m.runs))
	for _, r := range m.runs {
		out[r.Status]++
	}
	return out, nil
}

func (m *memStore) JobStatusCounts(ctx context.Context) (map[model.Status]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[model.Status]int, len(m.jobs))
	for _, j := range m.jobs {
		out[j.Status]++
	}
	return out, nil
}

func (m *memStore) QueuedJobQueueReasonCounts(ctx context.Context) (map[string]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for _, j := range m.jobs {
		if j.QueueReason != "" && (j.Status == model.StatusQueued || j.Status == model.StatusWaitingApproval) {
			out[j.QueueReason]++
		}
	}
	return out, nil
}

func (m *memStore) RunnerSlotTotals(ctx context.Context) (RunnerSlotTotals, error) {
	if err := ctx.Err(); err != nil {
		return RunnerSlotTotals{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out RunnerSlotTotals
	for _, r := range m.runners {
		out.Runners++
		c := r.Capacity
		if c < 1 {
			c = 1
		}
		out.Capacity += c
		out.Busy += len(r.ActiveJobs)
	}
	return out, nil
}

// CountRunningJobs mirrors the SQL aggregate over the in-memory job map: the
// authoritative in-flight count for a drain, independent of run scans. The
// memory store's map under one mutex is always a complete view, so a returned
// count is known, never partial.
func (m *memStore) CountRunningJobs(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, j := range m.jobs {
		if j.Status == model.StatusRunning {
			n++
		}
	}
	return n, nil
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

// AcquireLease is the non-atomic in-memory claim (see the SQL counterpart):
// it claims the job without a runner-slot predicate and reserves no resource
// capacity. Bundle users claim through AcquireLeaseAtomic.
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
		// Idempotent replay only for the IDENTICAL result: a stored receipt
		// with a different ResultHash is a conflicting completion of the
		// same lease and fails closed, mirroring the SQL path.
		if rec, dup := m.receipts[key]; dup {
			if rec.ResultHash == receipt.ResultHash {
				return nil
			}
			return ErrCompletionConflict
		}
		return ErrGenerationMismatch
	}
	// The job is still running under the matching lease but a receipt key
	// already exists: validate payload identity instead of overwriting a
	// different result (the SQL ON CONFLICT DO NOTHING path).
	if rec, dup := m.receipts[key]; dup {
		if rec.ResultHash != receipt.ResultHash {
			return ErrCompletionConflict
		}
		return nil
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
	// The completion releases the job's resource reservation in the same
	// critical section (idempotent; a replay never re-inserted one).
	m.releaseReservationLocked(jobID)
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
	// Post-transaction completion effects mirror the SQL contract: TWO
	// durable intents committed with the completion under the deterministic
	// effect IDs the completing server queues locally — completion_reconcile
	// (internal consistency, unbounded retries) and forge_delivery (external
	// publication, bounded retries + dead-letter). The payload carries two
	// strings, so marshaling cannot fail. The kind table is shared with the
	// SQL completion transaction and its size is pinned by
	// CompletionEffectIntentCount.
	payload, _ := json.Marshal(CompletionEffectsPayload{JobID: jobID, RunID: j.RunID})
	kinds := NewCompletionEffectKinds()
	if len(kinds) != CompletionEffectIntentCount {
		return fmt.Errorf("storage: completion effect kind table has %d entries, want CompletionEffectIntentCount=%d", len(kinds), CompletionEffectIntentCount)
	}
	for _, kind := range kinds {
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
		// The cancelled job releases its resource reservation (a no-op for
		// queued jobs, which never acquired one).
		m.releaseReservationLocked(id)
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
		// missing runner row, and the resource reservation is keyed by job.
		m.releaseJobQuotaLocked(jobID)
		m.releaseReservationLocked(jobID)
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
	m.releaseReservationLocked(jobID)
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

// ---------------------------------------------------------------------------
// transactional lease recovery / revocation (in-memory mirrors)
// ---------------------------------------------------------------------------
//
// The three methods below apply the whole transition to OVERLAY copies of the
// affected collections and swap them in only when every staged write
// succeeded. A failure injected through recoveryFaultOps therefore leaves the
// committed state exactly as it was — the in-memory equivalent of a rolled
// back SQL transaction.

// recoveryBump advances the staged-write counter of the current recovery
// transaction and returns the injected failure when the configured op is
// reached. It is one-shot, mirroring enqueueFaultOps.
func recoveryBump(ops *int, errp *error, staged *int) error {
	if *ops <= 0 {
		return nil
	}
	*staged++
	if *staged < *ops {
		return nil
	}
	err := *errp
	*ops = 0
	*errp = nil
	if err == nil {
		err = errors.New("storage: injected recovery failure")
	}
	return err
}

// recoveryBumpFor is the bound form used by the memStore methods.
func (m *memStore) recoveryBumpFor(staged *int) error {
	return recoveryBump(&m.recoveryFaultOps, &m.recoveryFaultErr, staged)
}

func cloneRecoveryJobs(in map[string]model.Job) map[string]model.Job {
	out := make(map[string]model.Job, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRecoveryRunners(in map[string]model.Runner) map[string]model.Runner {
	out := make(map[string]model.Runner, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRecoveryRuns(in map[string]model.Run) map[string]model.Run {
	out := make(map[string]model.Run, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRecoveryQuotas(in map[string]quotaCounts) map[string]quotaCounts {
	out := make(map[string]quotaCounts, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// adjustQuotaMap shifts counters on an overlay quota map, clamping at zero
// exactly like adjustQuotaLocked.
func adjustQuotaMap(quotas map[string]quotaCounts, repoID string, runningDelta, queuedDelta int) {
	for _, key := range QuotaKeys(repoID) {
		c := quotas[key]
		c.running += runningDelta
		if c.running < 0 {
			c.running = 0
		}
		c.queued += queuedDelta
		if c.queued < 0 {
			c.queued = 0
		}
		quotas[key] = c
	}
}

// releaseRunnerSlotMap removes one job from an overlay runner's active set
// and recomputes busy/current_job, mirroring releaseRunnerSlotLocked.
func releaseRunnerSlotMap(runners map[string]model.Runner, runnerID, jobID string) {
	r, ok := runners[runnerID]
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
	runners[runnerID] = r
}

// recomputeDependentsMap re-evaluates queued/waiting jobs that need one of
// the changed jobs against the overlay job map, blocking them when their
// condition does not allow the fresh outcome. It mirrors the SQL
// recomputeDependentsTx pass.
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
		statuses := map[string]model.Status{}
		for _, dep := range j.Needs {
			if d, ok := jobs[dep]; ok {
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
		jobs[id] = j
	}
}

// recomputeRunMap recomputes one run's aggregation from the overlay job map,
// mirroring the SQL recomputeRunTx.
func recomputeRunMap(runs map[string]model.Run, jobs map[string]model.Job, runID string) {
	run, ok := runs[runID]
	if !ok {
		return
	}
	states := []jobState{}
	for _, j := range jobs {
		if j.RunID == runID {
			states = append(states, jobState{status: j.Status, startedAt: j.StartedAt, finishedAt: j.FinishedAt})
		}
	}
	if recomputeRunStatus(&run, states) {
		runs[runID] = run
	}
}

// recoveryAudit builds one audit event for a transactional recovery.
func recoveryAudit(j model.Job, action, actor, msg string, meta map[string]string, now time.Time) model.AuditEvent {
	return model.AuditEvent{ID: j.ID + "|" + action, Action: action, Actor: actor, RunID: j.RunID, JobID: j.ID, Message: msg, Metadata: meta, CreatedAt: now}
}

// RevokeRunnerLeases mirrors the SQL transaction: every running lease of the
// runner is requeued or cancelled, the lease cleared, the runner slot, quota
// counters, dependents, run aggregation and audit all move together.
func (m *memStore) RevokeRunnerLeases(ctx context.Context, runnerID, reason string) ([]string, error) {
	if err := ValidateRunnerID(runnerID); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	ids := []string{}
	for id, j := range m.jobs {
		if j.Status == model.StatusRunning && j.LeaseRunnerID == runnerID {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return []string{}, nil
	}
	sort.Strings(ids)
	jobs := cloneRecoveryJobs(m.jobs)
	runners := cloneRecoveryRunners(m.runners)
	runs := cloneRecoveryRuns(m.runs)
	quotas := cloneRecoveryQuotas(m.quotas)
	reservations := cloneRecoveryReservations(m.reservations)
	audit := append([]model.AuditEvent(nil), m.audit...)
	staged := 0
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
		// The invalidated lease releases its reservation in the same
		// transaction (a requeued job holds none until re-leased).
		releaseReservationMap(reservations, id)
		if err := m.recoveryBumpFor(&staged); err != nil {
			return nil, err
		}
		if requeue {
			adjustQuotaMap(quotas, RepoIDForJob(j), -1, 1)
		} else {
			adjustQuotaMap(quotas, RepoIDForJob(j), -1, 0)
		}
		if err := m.recoveryBumpFor(&staged); err != nil {
			return nil, err
		}
		action := "job.runner_disabled_cancelled"
		if requeue {
			action = "job.runner_disabled_requeued"
		}
		audit = append(audit, recoveryAudit(j, action, "admin", reason, map[string]string{"job": j.Key, "runner": runnerID}, now))
		if err := m.recoveryBumpFor(&staged); err != nil {
			return nil, err
		}
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
		if err := m.recoveryBumpFor(&staged); err != nil {
			return nil, err
		}
	}
	recomputeDependentsMap(jobs, changed, now)
	if err := m.recoveryBumpFor(&staged); err != nil {
		return nil, err
	}
	for runID := range runIDs {
		recomputeRunMap(runs, jobs, runID)
	}
	if err := m.recoveryBumpFor(&staged); err != nil {
		return nil, err
	}
	m.jobs = jobs
	m.runners = runners
	m.runs = runs
	m.quotas = quotas
	m.reservations = reservations
	m.audit = audit
	return ids, nil
}

// RecoverExpiredLease mirrors the SQL transaction for one expired running
// lease. A job that is not running with the expected generation, or whose
// lease is still live, is a no-op. A job marked undecodable (the test seam
// modelling a corrupt payload) follows the SQL corruption path: terminal
// failure with the corruption reason, capacity released, corruption audit —
// the in-memory mirror of recoverCorruptLeaseTx.
func (m *memStore) RecoverExpiredLease(ctx context.Context, jobID string, expectedGeneration int64, now time.Time) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	if err := m.fenceLeader(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[jobID]
	if !ok {
		return ErrNotFound
	}
	if j.Status != model.StatusRunning || j.LeaseGeneration != expectedGeneration {
		return nil
	}
	if j.LeaseExpiresAt != nil && j.LeaseExpiresAt.After(now) {
		return nil
	}
	jobs := cloneRecoveryJobs(m.jobs)
	runners := cloneRecoveryRunners(m.runners)
	runs := cloneRecoveryRuns(m.runs)
	quotas := cloneRecoveryQuotas(m.quotas)
	reservations := cloneRecoveryReservations(m.reservations)
	audit := append([]model.AuditEvent(nil), m.audit...)
	staged := 0
	corrupt := m.undecodableJobs[jobID]
	requeue := !corrupt && j.Attempts <= j.MaxInfraRetries
	switch {
	case corrupt:
		// Retry policy cannot be trusted from a corrupt payload: terminal
		// failure, never a re-queue.
		j.Status = model.StatusFailure
		j.Error = CorruptLeaseRecoveryReason
		j.FinishedAt = &now
	case requeue:
		j.Status = model.StatusQueued
		j.Error = "runner lease expired; retrying"
	default:
		j.Status = model.StatusFailure
		j.Error = "runner lease expired and infrastructure retry budget exhausted"
		j.FinishedAt = &now
	}
	leaseRunnerID := j.LeaseRunnerID
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	jobs[jobID] = j
	// The expired lease releases its resource reservation in the same
	// transaction, whether the job requeues or terminally fails (the
	// corrupt-payload path releases it too: the row is keyed by job ID and
	// needs no decoded request).
	releaseReservationMap(reservations, jobID)
	if err := m.recoveryBumpFor(&staged); err != nil {
		return err
	}
	if requeue {
		adjustQuotaMap(quotas, RepoIDForJob(j), -1, 1)
	} else {
		adjustQuotaMap(quotas, RepoIDForJob(j), -1, 0)
	}
	if err := m.recoveryBumpFor(&staged); err != nil {
		return err
	}
	if leaseRunnerID != "" {
		releaseRunnerSlotMap(runners, leaseRunnerID, jobID)
		if r, ok := runners[leaseRunnerID]; ok {
			r.Failed++
			r.LastSeen = now
			runners[leaseRunnerID] = r
		}
		if err := m.recoveryBumpFor(&staged); err != nil {
			return err
		}
	}
	action := "job.lease_expired"
	msg := "job requeued after lost runner"
	if !requeue {
		action = "job.lost_runner"
		msg = j.Error
	}
	if corrupt {
		action = "job.corrupt_payload_recovered"
		msg = CorruptLeaseRecoveryReason
	}
	audit = append(audit, recoveryAudit(j, action, "scheduler", msg, map[string]string{"job": j.Key}, now))
	if err := m.recoveryBumpFor(&staged); err != nil {
		return err
	}
	recomputeDependentsMap(jobs, map[string]bool{jobID: true}, now)
	if err := m.recoveryBumpFor(&staged); err != nil {
		return err
	}
	recomputeRunMap(runs, jobs, j.RunID)
	if err := m.recoveryBumpFor(&staged); err != nil {
		return err
	}
	m.jobs = jobs
	m.runners = runners
	m.runs = runs
	m.quotas = quotas
	m.reservations = reservations
	m.audit = audit
	return nil
}

// ListExpiredRunningJobs mirrors the SQL discovery page (see
// RecoveryDiscoveryStore): running jobs whose lease expiry elapsed or is
// absent, ordered by id ASC and keyset-paged with id > afterID, each as the
// lightweight relational-column candidate (id, lease_generation). The job map
// under m.mu is a complete view, so paging is deterministic.
func (m *memStore) ListExpiredRunningJobs(ctx context.Context, now time.Time, afterID string, limit int) ([]RecoveryCandidate, error) {
	if limit <= 0 {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []RecoveryCandidate{}
	for _, j := range m.jobs {
		if j.ID <= afterID || j.Status != model.StatusRunning {
			continue
		}
		if j.LeaseExpiresAt != nil && j.LeaseExpiresAt.After(now) {
			continue
		}
		out = append(out, RecoveryCandidate{ID: j.ID, LeaseGeneration: j.LeaseGeneration})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ListQueueTimedOutJobs mirrors the SQL discovery page: queued/waiting jobs
// whose EFFECTIVE queue deadline elapsed, ordered by id ASC and keyset-paged
// with id > afterID. The memory store has no derived deadline column, so
// QueueDeadlineFor (persisted field first, compiled-payload fallback second)
// is the single source of truth; an undecodable payload is limited to the
// persisted QueueDeadline field (the column analogue) so it can never derive
// a deadline the SQL store could not. The candidate carries the PERSISTED
// deadline (nil for payload-derived legacy rows), exactly like the SQL page.
func (m *memStore) ListQueueTimedOutJobs(ctx context.Context, now time.Time, afterID string, limit int) ([]RecoveryCandidate, error) {
	if limit <= 0 {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []RecoveryCandidate{}
	for _, j := range m.jobs {
		if j.ID <= afterID {
			continue
		}
		if j.Status != model.StatusQueued && j.Status != model.StatusWaitingApproval {
			continue
		}
		persisted := j.QueueDeadline
		eff := persisted
		if eff == nil && !m.undecodableJobs[j.ID] {
			eff = QueueDeadlineFor(j)
		}
		if eff == nil || eff.After(now) {
			continue
		}
		out = append(out, RecoveryCandidate{ID: j.ID, LeaseGeneration: j.LeaseGeneration, QueueDeadline: persisted})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ExpireQueuedJob mirrors the SQL transaction for one queue-timeout job:
// deadline is the persisted queue deadline the discovery observed (ZERO when
// only a payload-derived legacy deadline exists), and the effective deadline
// is re-derived under the lock with QueueDeadlineFor semantics. An
// undecodable payload (test seam) may still expire when the persisted field
// proves the elapsed deadline, with the corruption reason and the queued
// reservation released — the in-memory mirror of ExpireQueuedJob's SQL
// corruption path.
func (m *memStore) ExpireQueuedJob(ctx context.Context, jobID string, deadline time.Time) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	if err := m.fenceLeader(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[jobID]
	if !ok {
		return ErrNotFound
	}
	if j.Status != model.StatusQueued && j.Status != model.StatusWaitingApproval {
		return nil
	}
	now := time.Now().UTC()
	var observed *time.Time
	if !deadline.IsZero() {
		observed = &deadline
	}
	corrupt := m.undecodableJobs[jobID]
	eff := j.QueueDeadline
	if eff == nil {
		if corrupt {
			return nil
		}
		eff = QueueDeadlineFor(j)
	}
	if eff == nil || eff.After(now) || (observed != nil && (eff.After(*observed) || observed.After(now))) {
		return nil
	}
	jobs := cloneRecoveryJobs(m.jobs)
	runs := cloneRecoveryRuns(m.runs)
	quotas := cloneRecoveryQuotas(m.quotas)
	reservations := cloneRecoveryReservations(m.reservations)
	audit := append([]model.AuditEvent(nil), m.audit...)
	staged := 0
	reason := "queue timeout"
	action := "job.queue_timeout"
	msg := "job cancelled after queue deadline"
	if corrupt {
		reason = CorruptQueueExpiryReason
		action = "job.corrupt_payload_expired"
		msg = CorruptQueueExpiryReason
	}
	j.Status = model.StatusCancelled
	j.Error = reason
	j.FinishedAt = &now
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	jobs[jobID] = j
	// A queued job never acquired a resource reservation; the release is the
	// documented idempotent no-op that keeps every terminal transition on
	// one path.
	releaseReservationMap(reservations, jobID)
	if err := m.recoveryBumpFor(&staged); err != nil {
		return err
	}
	adjustQuotaMap(quotas, RepoIDForJob(j), 0, -1)
	if err := m.recoveryBumpFor(&staged); err != nil {
		return err
	}
	audit = append(audit, recoveryAudit(j, action, "scheduler", msg, map[string]string{"job": j.Key}, now))
	if err := m.recoveryBumpFor(&staged); err != nil {
		return err
	}
	recomputeDependentsMap(jobs, map[string]bool{jobID: true}, now)
	if err := m.recoveryBumpFor(&staged); err != nil {
		return err
	}
	recomputeRunMap(runs, jobs, j.RunID)
	if err := m.recoveryBumpFor(&staged); err != nil {
		return err
	}
	m.jobs = jobs
	m.runs = runs
	m.quotas = quotas
	m.reservations = reservations
	m.audit = audit
	return nil
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

// memStore fencing semantics: the in-memory store is single-process, so its
// TryAcquireLeadership is trivially true and no cross-process split brain
// exists to defend against. It therefore models a replica that ALWAYS retains
// a valid leadership epoch: the epoch starts at 1 and every leader-fenced
// operation is admitted. Clearing it (ClearLeaderEpoch / SetLeaderEpoch(0))
// simulates loss, after which every fenced operation fails closed with
// ErrStaleLeader until an epoch is set again — exact parity with the SQL
// store's fail-closed contract, without a durable row to compare against.
func (m *memStore) SetLeaderEpoch(epoch int64) {
	if epoch <= 0 {
		m.leaderEpoch.Store(0)
		return
	}
	m.leaderEpoch.Store(epoch)
}

func (m *memStore) LeaderEpoch() (int64, bool) {
	e := m.leaderEpoch.Load()
	return e, e > 0
}

func (m *memStore) ClearLeaderEpoch() { m.leaderEpoch.Store(0) }

func (m *memStore) ReadLeaderEpoch(ctx context.Context) (int64, error) {
	e := m.leaderEpoch.Load()
	return e, nil
}

// fenceLeader is the in-memory analogue of the SQL store's in-transaction
// epoch assertion: it fails closed when this store retains no epoch. There is
// no durable row to compare against, so presence is the whole contract (see
// the fencing note above).
func (m *memStore) fenceLeader() error {
	if _, ok := m.LeaderEpoch(); !ok {
		return ErrStaleLeader
	}
	return nil
}

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
	if err := m.fenceLeader(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.outbox[:0]
	for _, it := range m.outbox {
		if it.ID != id {
			out = append(out, it)
			continue
		}
		// Versioned ack advances the delivered watermark atomically with the
		// removal, mirroring the SQL CTE.
		if it.LogicalKey != "" && it.StateVersion > 0 {
			if it.StateVersion > m.forgeState[it.LogicalKey] {
				m.forgeState[it.LogicalKey] = it.StateVersion
			}
		}
	}
	m.outbox = out
	delete(m.outboxClaims, id)
	delete(m.outboxMeta, id)
	return nil
}

// OutboxEnqueueVersioned is the in-memory mirror of the SQL versioned
// enqueue: under one lock it checks the delivered watermark, deletes every
// older pending row of the logical key, and inserts the new row. Because the
// memory store has no replicas, m.mu is the serialization the SQL advisory
// lock provides there.
func (m *memStore) OutboxEnqueueVersioned(ctx context.Context, e OutboxItem) (VersionedEnqueueOutcome, error) {
	if e.LogicalKey == "" || e.StateVersion <= 0 {
		return VersionedEnqueued, fmt.Errorf("storage: versioned outbox enqueue requires a logical key and a positive version")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.StateVersion <= m.forgeState[e.LogicalKey] {
		return VersionedSuperseded, nil
	}
	// A newer pending version wins even when this enqueue arrives after it.
	for _, it := range m.outbox {
		if it.LogicalKey != e.LogicalKey || it.StateVersion <= e.StateVersion {
			continue
		}
		if meta, ok := m.outboxMeta[it.ID]; ok && !meta.deadAt.IsZero() {
			continue
		}
		return VersionedSuperseded, nil
	}
	kept := m.outbox[:0]
	for _, it := range m.outbox {
		if it.LogicalKey == e.LogicalKey && it.StateVersion <= e.StateVersion {
			meta := m.outboxMeta[it.ID]
			if !meta.deadAt.IsZero() {
				// Dead letters are terminal and operator-visible: never
				// silently deleted by a supersede.
				kept = append(kept, it)
				continue
			}
			delete(m.outboxClaims, it.ID)
			delete(m.outboxMeta, it.ID)
			continue
		}
		kept = append(kept, it)
	}
	m.outbox = kept
	for _, it := range m.outbox {
		if it.ID == e.ID {
			// Equal-version dead letter (pending rows were removed above):
			// report superseded, mirroring the SQL ON CONFLICT DO NOTHING.
			return VersionedSuperseded, nil
		}
	}
	m.outbox = append(m.outbox, e)
	return VersionedEnqueued, nil
}

// OutboxVersionGuard is the in-memory mirror of the SQL durable guard.
func (m *memStore) OutboxVersionGuard(ctx context.Context, id, logicalKey string, version int64) (bool, error) {
	if logicalKey == "" || version <= 0 {
		return true, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	alive := false
	newerPending := false
	for _, it := range m.outbox {
		if it.ID == id {
			alive = true
		}
		if it.LogicalKey != logicalKey || it.StateVersion <= version {
			continue
		}
		if meta, ok := m.outboxMeta[it.ID]; ok && !meta.deadAt.IsZero() {
			continue
		}
		newerPending = true
	}
	return alive && m.forgeState[logicalKey] < version && !newerPending, nil
}

// OutboxMarkDelivered is the in-memory mirror of the SQL watermark stamp for
// legacy (unversioned) forge rows: the dispatcher derives the identity from
// the payload and advances the delivered watermark after the forge accepted
// the state.
func (m *memStore) OutboxMarkDelivered(ctx context.Context, logicalKey string, version int64) error {
	if logicalKey == "" || version <= 0 {
		return fmt.Errorf("storage: mark delivered requires a logical key and a positive version")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.forgeState == nil {
		m.forgeState = map[string]int64{}
	}
	if version > m.forgeState[logicalKey] {
		m.forgeState[logicalKey] = version
	}
	return nil
}

// OutboxRetry mirrors the SQL retry policy: the attempt counter grows, the
// dispatch error is retained, the claim is dropped, and the next attempt is
// scheduled with bounded exponential backoff. After maxAttempts the row is
// dead-lettered instead of hot-looping. An unknown id is a no-op (the row was
// already acked).
func (m *memStore) OutboxRetry(ctx context.Context, id string, dispatchErr error, maxAttempts int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hasOutboxLocked(id) {
		return nil
	}
	msg := ""
	if dispatchErr != nil {
		msg = dispatchErr.Error()
	}
	meta := m.outboxMeta[id]
	backoff := time.Second
	for i := 0; i < meta.attempts && backoff < time.Minute; i++ {
		backoff *= 2
	}
	jitter := time.Duration(time.Now().UnixNano() % int64(backoff/4+1))
	meta.attempts++
	meta.lastError = msg
	delete(m.outboxClaims, id)
	if maxAttempts > 0 && meta.attempts >= maxAttempts {
		meta.deadAt = time.Now().UTC()
		meta.nextAt = time.Time{}
	} else {
		meta.nextAt = time.Now().UTC().Add(backoff + jitter)
	}
	m.outboxMeta[id] = meta
	return nil
}

// OutboxPending returns the active (not dead-lettered) rows in FIFO order,
// mirroring the SQL `WHERE dead_lettered_at IS NULL` filter: startup replay
// must never re-dispatch a retired intent.
func (m *memStore) OutboxPending(ctx context.Context) ([]OutboxItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]OutboxItem, 0, len(m.outbox))
	for _, it := range m.outbox {
		if meta, ok := m.outboxMeta[it.ID]; ok && !meta.deadAt.IsZero() {
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

// OutboxDeadLetters lists the dead-lettered rows in FIFO order with the
// operator context (attempts, last error, retirement time).
func (m *memStore) OutboxDeadLetters(ctx context.Context) ([]OutboxDeadLetter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []OutboxDeadLetter{}
	for _, it := range m.outbox {
		meta, ok := m.outboxMeta[it.ID]
		if !ok || meta.deadAt.IsZero() {
			continue
		}
		out = append(out, OutboxDeadLetter{
			ID:             it.ID,
			Kind:           it.Kind,
			Payload:        it.Payload,
			CreatedAt:      it.CreatedAt,
			Attempts:       meta.attempts,
			LastError:      meta.lastError,
			DeadLetteredAt: meta.deadAt,
			LogicalKey:     it.LogicalKey,
			StateVersion:   it.StateVersion,
		})
	}
	return out, nil
}

// OutboxRequeue resets one dead-lettered row to a fresh, immediately
// dispatchable state. Only dead letters can be requeued; an absent or live
// row is ErrNotFound, mirroring the SQL WHERE guard.
func (m *memStore) OutboxRequeue(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	meta, ok := m.outboxMeta[id]
	if !ok || meta.deadAt.IsZero() || !m.hasOutboxLocked(id) {
		return ErrNotFound
	}
	delete(m.outboxMeta, id)
	delete(m.outboxClaims, id)
	return nil
}

// OutboxDelete removes one dead-lettered row. Only dead letters can be
// deleted; an absent or live row is ErrNotFound.
func (m *memStore) OutboxDelete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	meta, ok := m.outboxMeta[id]
	if !ok || meta.deadAt.IsZero() || !m.hasOutboxLocked(id) {
		return ErrNotFound
	}
	out := m.outbox[:0]
	for _, it := range m.outbox {
		if it.ID != id {
			out = append(out, it)
		}
	}
	m.outbox = out
	delete(m.outboxMeta, id)
	delete(m.outboxClaims, id)
	return nil
}

// hasOutboxLocked reports whether the durable outbox (still) holds id.
func (m *memStore) hasOutboxLocked(id string) bool {
	for _, it := range m.outbox {
		if it.ID == id {
			return true
		}
	}
	return false
}

// ClaimOutbox claims up to limit dispatchable rows for claimer: unclaimed or
// stale (claimed_at older than OutboxClaimTTL) items in FIFO order. Two
// concurrent flushers under m.mu claim disjoint batches, mirroring the SQL
// SELECT ... FOR UPDATE SKIP LOCKED claim.
func (m *memStore) ClaimOutbox(ctx context.Context, claimer string, limit int) ([]OutboxItem, error) {
	if claimer == "" || limit <= 0 {
		return nil, nil
	}
	if err := m.fenceLeader(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	cutoff := now.Add(-OutboxClaimTTL)
	out := []OutboxItem{}
	for _, it := range m.outbox {
		if len(out) >= limit {
			break
		}
		// Dead letters are terminal: never claimable again until requeued.
		if meta, ok := m.outboxMeta[it.ID]; ok {
			if !meta.deadAt.IsZero() {
				continue
			}
			// Boundary parity with the SQL `next_attempt_at <= now()`.
			if !meta.nextAt.IsZero() && meta.nextAt.After(now) {
				continue
			}
		}
		// Boundary parity with the SQL claim (claimed_at < cutoff): a
		// claim exactly at the cutoff is still honored.
		if c, ok := m.outboxClaims[it.ID]; ok && !c.at.Before(cutoff) {
			continue
		}
		m.outboxClaims[it.ID] = outboxClaim{claimer: claimer, at: now}
		out = append(out, it)
	}
	return out, nil
}

// ReleaseOutboxClaim clears one claim held by claimer so a retry can claim
// the row again immediately.
func (m *memStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	if err := m.fenceLeader(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.outboxClaims[id]; ok && c.claimer == claimer {
		delete(m.outboxClaims, id)
	}
	return nil
}

// ReleaseOutboxClaims clears every claim in the batch still held by claimer
// and returns how many were released, mirroring the SQL single-statement
// batch release: foreign-claimed or already-cleared ids do not match and do
// not count, so a replayed batch is an idempotent no-op.
func (m *memStore) ReleaseOutboxClaims(ctx context.Context, ids []string, claimer string) (int, error) {
	if strings.TrimSpace(claimer) == "" {
		return 0, fmt.Errorf("storage: empty outbox claimer")
	}
	if err := m.fenceLeader(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	released := 0
	for _, id := range ids {
		if c, ok := m.outboxClaims[id]; ok && c.claimer == claimer {
			delete(m.outboxClaims, id)
			released++
		}
	}
	return released, nil
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
func (m *memStore) AcquireNamedFence(ctx context.Context, namespace, key string) (func(), error) {
	return m.acquireMemFence(namespace + "\x00" + key)
}

func (m *memStore) acquireMemFence(k string) (func(), error) {
	m.fenceMu.Lock()
	mu, ok := m.fences[k]
	if !ok {
		mu = &sync.Mutex{}
		if m.fences == nil {
			m.fences = map[string]*sync.Mutex{}
		}
		m.fences[k] = mu
	}
	m.fenceMu.Unlock()
	mu.Lock()
	var once sync.Once
	return func() { once.Do(mu.Unlock) }, nil
}

func (m *memStore) AcquireDigestFence(ctx context.Context, digest string) (func(), error) {
	m.fenceMu.Lock()
	mu, ok := m.fences[digest]
	if !ok {
		mu = &sync.Mutex{}
		if m.fences == nil {
			m.fences = map[string]*sync.Mutex{}
		}
		m.fences[digest] = mu
	}
	m.fenceMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mu.Lock()
	var once sync.Once
	return func() { once.Do(mu.Unlock) }, nil
}

func (m *memStore) WithDigestFence(ctx context.Context, digest string, fn func() error) error {
	m.fenceMu.Lock()
	mu, ok := m.fences[digest]
	if !ok {
		mu = &sync.Mutex{}
		if m.fences == nil {
			m.fences = map[string]*sync.Mutex{}
		}
		m.fences[digest] = mu
	}
	m.fenceMu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}

func (f *FaultyStore) WithDigestFence(ctx context.Context, digest string, fn func() error) error {
	inner, ok := f.Inner.(DigestFenceStore)
	if !ok {
		return errMissingInnerInterface("DigestFenceStore")
	}
	return inner.WithDigestFence(ctx, digest, fn)
}

func (f *FaultyStore) AcquireNamedFence(ctx context.Context, namespace, key string) (func(), error) {
	inner, ok := f.Inner.(DigestFenceStore)
	if !ok {
		return nil, errMissingInnerInterface("DigestFenceStore")
	}
	return inner.AcquireNamedFence(ctx, namespace, key)
}

func (f *FaultyStore) AcquireDigestFence(ctx context.Context, digest string) (func(), error) {
	inner, ok := f.Inner.(DigestFenceStore)
	if !ok {
		return nil, errMissingInnerInterface("DigestFenceStore")
	}
	return inner.AcquireDigestFence(ctx, digest)
}

func (f *FaultyStore) GetSchedule(ctx context.Context, id string) (Schedule, bool, error) {
	inner, ok := f.Inner.(ScheduleStore)
	if !ok {
		return Schedule{}, false, errMissingInnerInterface("ScheduleStore")
	}
	return inner.GetSchedule(ctx, id)
}

func (m *memStore) AppendLogBatch(ctx context.Context, entries []model.LogEntry, r LogBatchIdentity) (bool, error) {
	if r.JobID == "" || r.BatchID == "" {
		return false, fmt.Errorf("storage: log batch requires job id and batch id")
	}
	if len(entries) == 0 {
		return false, fmt.Errorf("storage: empty log batch")
	}
	key := r.JobID + "\x00" + strconv.FormatInt(r.Generation, 10) + "\x00" + r.BatchID
	claimed, conflict := m.logBatches.claim(key, LogBatchPayloadDigest(r, entries))
	if conflict {
		return false, ErrLogBatchConflict
	}
	if !claimed {
		return false, nil
	}
	m.mu.Lock()
	m.logs = append(m.logs, entries...)
	m.mu.Unlock()
	return true, nil
}

// AppendLogBatch passes the inner store's result (including
// ErrLogBatchConflict) through untouched; only injected faults replace it.
func (f *FaultyStore) AppendLogBatch(ctx context.Context, entries []model.LogEntry, r LogBatchIdentity) (bool, error) {
	op := f.fail()
	if op != nil {
		return false, op
	}
	inner, ok := f.Inner.(LogBatchStore)
	if !ok {
		return false, errMissingInnerInterface("LogBatchStore")
	}
	return inner.AppendLogBatch(ctx, entries, r)
}

func (m *memStore) PutCheckRun(ctx context.Context, key, checkRunID string) error {
	return m.checkRuns.put(key, checkRunID)
}

func (m *memStore) GetCheckRun(ctx context.Context, key string) (string, bool, error) {
	id, ok := m.checkRuns.get(key)
	return id, ok, nil
}

func (f *FaultyStore) PutCheckRun(ctx context.Context, key, checkRunID string) error {
	op := f.fail()
	if op != nil {
		return op
	}
	inner, ok := f.Inner.(CheckRunStore)
	if !ok {
		return errMissingInnerInterface("CheckRunStore")
	}
	return inner.PutCheckRun(ctx, key, checkRunID)
}

func (f *FaultyStore) GetCheckRun(ctx context.Context, key string) (string, bool, error) {
	op := f.fail()
	if op != nil {
		return "", false, op
	}
	inner, ok := f.Inner.(CheckRunStore)
	if !ok {
		return "", false, errMissingInnerInterface("CheckRunStore")
	}
	return inner.GetCheckRun(ctx, key)
}

func (f *FaultyStore) OutboxHas(ctx context.Context, id string) (bool, error) {
	op := f.fail()
	if op != nil {
		return false, op
	}
	inner, ok := f.Inner.(OutboxStore)
	if !ok {
		return false, errMissingInnerInterface("OutboxStore")
	}
	return inner.OutboxHas(ctx, id)
}

func (m *memStore) OutboxHas(ctx context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, it := range m.outbox {
		if it.ID == id {
			return true, nil
		}
	}
	return false, nil
}

func (m *memStore) GetSchedule(ctx context.Context, id string) (Schedule, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sc, ok := m.schedules[id]
	return sc, ok, nil
}

func (m *memStore) AdvanceScheduleLastRun(ctx context.Context, id string, nominal time.Time) error {
	if id == "" {
		return fmt.Errorf("storage: empty schedule id")
	}
	if err := m.fenceLeader(); err != nil {
		return err
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
	if err := m.fenceLeader(); err != nil {
		return false, err
	}
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
	if err := m.fenceLeader(); err != nil {
		return 0, err
	}
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

// RecordUsageOnce mirrors the SQL conditional update: only the first caller
// for a job wins; the marker and the cost/energy amounts are written in one
// critical section so they can never diverge.
func (m *memStore) RecordUsageOnce(ctx context.Context, jobID string, cost, energyWh float64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[jobID]
	if !ok || j.UsageRecorded {
		return false, nil
	}
	j.UsageRecorded = true
	j.Cost = cost
	j.EnergyWh = energyWh
	m.jobs[jobID] = j
	return true, nil
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

// ParentRunIDsForChild is the in-memory equivalent of the SQL reverse-index
// lookup: every downstream link launched as childRunID maps through its
// parent job to that job's run. Missing parent jobs are skipped (the SQL JOIN
// drops them), duplicates are folded and the result is ordered by run ID,
// exactly like PostgresStore.ParentRunIDsForChild.
func (m *memStore) ParentRunIDsForChild(ctx context.Context, childRunID string) ([]string, error) {
	if childRunID == "" {
		return nil, fmt.Errorf("storage: empty child run id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	out := []string{}
	for _, l := range m.downstream {
		if l.ChildRunID != childRunID {
			continue
		}
		j, ok := m.jobs[l.ParentJobID]
		if !ok || j.RunID == "" || seen[j.RunID] {
			continue
		}
		seen[j.RunID] = true
		out = append(out, j.RunID)
	}
	sort.Strings(out)
	return out, nil
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
	runID := req.Run.ID
	if runID == "" {
		return fmt.Errorf("storage: empty run id")
	}
	// A schedule occurrence claim makes this enqueue leader-only work, so the
	// same fail-closed fence as the SQL store applies here. Ordinary
	// submissions carry no claim and are deliberately not fenced.
	if req.ScheduleClaim != nil {
		if err := m.fenceLeader(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
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
		// The superseded job releases its resource reservation in the same
		// step (idempotent no-op for queued jobs).
		m.releaseReservationLocked(st.id)
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

// resolveProfileLocked resolves the runner's LIVE effective scheduling view
// through the ONE shared precedence (caller holds m.mu): the explicit
// certificate-serial binding wins when the runner presents a registered
// serial, otherwise the runner-ID binding applies, otherwise the
// registration snapshot. A dangling certificate binding denies the lease; a
// dangling runner-ID binding resolves as "no profile" (the snapshot, never
// more). See ResolveLiveProfileBinding for the documented policy.
func (m *memStore) resolveProfileLocked(r model.Runner) (effective model.Runner, resolution LiveProfileResolution) {
	certLookup := func() (model.RunnerProfile, bool, bool, error) {
		profileID, ok := m.certProfiles[r.CertSerial]
		if !ok {
			return model.RunnerProfile{}, false, false, nil
		}
		p, ok := m.profiles[profileID]
		if !ok {
			return model.RunnerProfile{}, true, false, nil
		}
		return p, true, true, nil
	}
	runnerLookup := func() (model.RunnerProfile, bool, bool, error) {
		profileID, ok := m.runnerProfiles[r.ID]
		if !ok {
			return model.RunnerProfile{}, false, false, nil
		}
		p, ok := m.profiles[profileID]
		if !ok {
			return model.RunnerProfile{}, true, false, nil
		}
		return p, true, true, nil
	}
	res, err := ResolveLiveProfileBinding(r.CertSerial, certLookup, runnerLookup)
	if err != nil {
		// Map lookups cannot fail; keep the registration snapshot on the
		// impossible error so the caller's own predicates still decide.
		return r, res
	}
	if res.Applies() {
		return ResolveRunnerProfile(r, res.Profile, true), res
	}
	return r, res
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

// reservedResourcesLocked sums the live reservations of one runner (caller
// holds m.mu). No reservation means zero on every dimension.
func (m *memStore) reservedResourcesLocked(runnerID string) model.ResourceCapacity {
	var out model.ResourceCapacity
	for _, r := range m.reservations {
		if r.RunnerID != runnerID {
			continue
		}
		out.CPU += r.CPU
		out.Memory += r.Memory
		out.Disk += r.Disk
		out.PIDs += r.PIDs
	}
	return out
}

// reserveResourcesLocked is the in-memory mirror of reserveResourcesTx: the
// shared ResourceAdmission predicate over the runner's remaining capacity,
// then the ledger row. The reserved quantities are the claim's TOTAL request
// (job request + aggregate service envelope, LeaseClaim.RequestedResources),
// so the one row per job covers the main container and every declared
// service and the release paths stay unchanged. It reports ErrResourceCapacity
// (wrapped with the requested/reserved/capacity values) when the request does
// not fit. The caller holds m.mu and has already passed every other claim
// predicate, so a rejection leaves the job queued and the runner untouched.
func (m *memStore) reserveResourcesLocked(claim LeaseClaim, capacity model.ResourceCapacity) error {
	reserved := m.reservedResourcesLocked(claim.RunnerID)
	requested := claim.RequestedResources()
	admission := ResourceAdmission{Capacity: capacity, Reserved: reserved, Requested: requested}
	if !admission.Allows() {
		return fmt.Errorf("%w: runner %s requested cpu=%v memory=%d disk=%d pids=%d, reserved cpu=%v memory=%d disk=%d pids=%d, capacity cpu=%v memory=%d disk=%d pids=%d",
			ErrResourceCapacity, claim.RunnerID,
			requested.CPU, requested.Memory, requested.Disk, requested.PIDs,
			reserved.CPU, reserved.Memory, reserved.Disk, reserved.PIDs,
			capacity.CPU, capacity.Memory, capacity.Disk, capacity.PIDs)
	}
	// job_id is the primary key: replacing a stale row keeps at most one
	// live reservation per job exactly like the SQL DELETE + INSERT.
	m.reservations[claim.JobID] = ResourceReservation{
		JobID: claim.JobID, RunnerID: claim.RunnerID, Generation: claim.Generation,
		CPU: requested.CPU, Memory: requested.Memory, Disk: requested.Disk, PIDs: requested.PIDs,
		CreatedAt: time.Now().UTC(),
	}
	return nil
}

// releaseReservationLocked deletes one job's reservation row (caller holds
// m.mu). It is idempotent: a missing row is a no-op, and a job can hold at
// most one row, so no path can double-release or leak.
func (m *memStore) releaseReservationLocked(jobID string) {
	delete(m.reservations, jobID)
}

// releaseReservationMap deletes one job's reservation from an overlay map,
// mirroring releaseReservationLocked for the transactional recovery
// methods.
func releaseReservationMap(reservations map[string]ResourceReservation, jobID string) {
	delete(reservations, jobID)
}

// cloneRecoveryReservations copies the reservation map for a transactional
// recovery overlay.
func cloneRecoveryReservations(in map[string]ResourceReservation) map[string]ResourceReservation {
	out := make(map[string]ResourceReservation, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// RunnerReservedResources implements ResourceReservationStore.
func (m *memStore) RunnerReservedResources(ctx context.Context, runnerID string) (model.ResourceCapacity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reservedResourcesLocked(runnerID), nil
}

// ListResourceReservations implements ResourceReservationStore.
func (m *memStore) ListResourceReservations(ctx context.Context, runnerID string) ([]ResourceReservation, error) {
	if err := ValidateRunnerID(runnerID); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ResourceReservation{}
	for _, r := range m.reservations {
		if r.RunnerID == runnerID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JobID < out[j].JobID })
	return out, nil
}

var _ ResourceReservationStore = (*memStore)(nil)

// ReconcileResourceReservations implements ResourceReconcileStore for the
// in-memory ledger (mem parity with the SQL promotion reconciliation): rows
// without a matching live lease are dropped, and every running leased job's
// row is rewritten from the authoritative job state (runner, generation, the
// job's TOTAL request — its own request plus the aggregate service envelope,
// Job.ReservedResources) under m.mu, so no claim can interleave. CreatedAt of
// a surviving row is preserved. Idempotent: a second pass on unchanged data
// deletes nothing and rewrites the same rows.
func (m *memStore) ReconcileResourceReservations(ctx context.Context) (ResourceReconcileResult, error) {
	if err := ctx.Err(); err != nil {
		return ResourceReconcileResult{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	res := ResourceReconcileResult{}
	// Phase 1: drop rows that do not describe a live running lease.
	for jobID, r := range m.reservations {
		j, ok := m.jobs[jobID]
		if !ok || j.Status != model.StatusRunning || j.LeaseRunnerID == "" || j.LeaseGeneration != r.Generation {
			delete(m.reservations, jobID)
			res.Deleted++
		}
	}
	// Phase 2: rewrite one reservation per running leased job.
	for jobID, j := range m.jobs {
		if j.Status != model.StatusRunning || j.LeaseRunnerID == "" {
			continue
		}
		res.Running++
		req := j.ReservedResources()
		want := ResourceReservation{
			JobID: jobID, RunnerID: j.LeaseRunnerID, Generation: j.LeaseGeneration,
			CPU: req.CPU, Memory: req.Memory, Disk: req.Disk, PIDs: req.PIDs,
			CreatedAt: time.Now().UTC(),
		}
		if cur, ok := m.reservations[jobID]; ok {
			want.CreatedAt = cur.CreatedAt
		}
		m.reservations[jobID] = want
		res.Upserted++
	}
	return res, nil
}

var _ ResourceReconcileStore = (*memStore)(nil)

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
// concurrency reservation, the resource check-and-reserve against the
// runner's remaining capacity and the conditional queued->running quota
// transition all commit or fail together under m.mu. Memory mode is
// single-process: the reservation guarantees capacity within this process,
// which is exactly the documented memory-mode semantics; HA deployments run
// the SQL store, where the runner row lock makes the same check atomic
// across replicas.
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
	effective, resolution := m.resolveProfileLocked(r)
	if resolution.DeniesLease() {
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
	// Resource check-and-reserve: the effective runner carries the LIVE
	// profile's capacities when linked (ResolveRunnerProfile overlays them),
	// the registration snapshot otherwise. Zero dimensions are
	// unconstrained, so capacity-less runners keep the count-only behavior.
	if err := m.reserveResourcesLocked(claim, effective.ResourceCapacity); err != nil {
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
func (m *memStore) SetArtifactSidecars(ctx context.Context, artifactID, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, a := range m.artifacts {
		if a.ID != artifactID {
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

// RememberPendingSidecar upserts the pending sidecar digest for one
// (job, generation, artifact, kind) identity, replacing the digest of a
// re-upload. Another generation's row is a different key.
func (m *memStore) RememberPendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind, digest string) error {
	if err := validatePendingSidecarKey(jobID, generation, artifactName, kind); err != nil {
		return err
	}
	if err := validatePendingSidecarDigest(digest); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingSidecars[pendingSidecarKey(jobID, generation, artifactName, kind)] = pendingSidecar{digest: digest, createdAt: time.Now().UTC()}
	return nil
}

// PendingSidecar resolves the pending sidecar digest for the exact
// (job, generation, artifact, kind) identity, or ok=false when the row is
// absent. It never falls back to another generation.
func (m *memStore) PendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind string) (string, bool, error) {
	if err := validatePendingSidecarKey(jobID, generation, artifactName, kind); err != nil {
		return "", false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.pendingSidecars[pendingSidecarKey(jobID, generation, artifactName, kind)]
	if !ok {
		return "", false, nil
	}
	return row.digest, true, nil
}

// ConsumePendingSidecar deletes the pending row only while it still carries
// the consumed digest, and only for the exact generation.
func (m *memStore) ConsumePendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind, digest string) error {
	if err := validatePendingSidecarKey(jobID, generation, artifactName, kind); err != nil {
		return err
	}
	if err := validatePendingSidecarDigest(digest); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pendingSidecarKey(jobID, generation, artifactName, kind)
	if row, ok := m.pendingSidecars[key]; ok && row.digest == digest {
		delete(m.pendingSidecars, key)
	}
	return nil
}

// PrunePendingSidecars drops rows created before the cutoff.
func (m *memStore) PrunePendingSidecars(ctx context.Context, olderThan time.Time) (int, error) {
	if err := m.fenceLeader(); err != nil {
		return 0, err
	}
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

// LinkRunnerProfile mirrors the SQL PRIMARY KEY upsert: one binding per
// runner ID, replaced in place. Empty IDs are rejected exactly like the SQL
// store so the mem and PostgreSQL contracts agree.
func (m *memStore) LinkRunnerProfile(ctx context.Context, runnerID, profileID string) error {
	if runnerID == "" {
		return fmt.Errorf("storage: runner id is required")
	}
	if profileID == "" {
		return fmt.Errorf("storage: profile id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runnerProfiles[runnerID] = profileID
	return nil
}

// ProfileForRunnerID resolves the LIVE profile for a runner-ID binding; a
// dangling link reports found=false, matching the SQL join.
func (m *memStore) ProfileForRunnerID(ctx context.Context, runnerID string) (model.RunnerProfile, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.runnerProfiles[runnerID]
	if !ok {
		return model.RunnerProfile{}, false, nil
	}
	p, ok := m.profiles[id]
	if !ok {
		return model.RunnerProfile{}, false, nil
	}
	return p, true, nil
}

// ResolveLiveRunnerProfile implements LiveProfileResolver on the in-memory
// store: the scheduler prefilter and the queue explainers resolve through the
// same shared precedence and the same maps the mem claim uses, so memory mode
// and the SQL store agree (including the dangling-binding policy).
func (m *memStore) ResolveLiveRunnerProfile(ctx context.Context, runnerID, serial string) (LiveProfileResolution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, resolution := m.resolveProfileLocked(model.Runner{ID: runnerID, CertSerial: serial})
	return resolution, nil
}

// UnlinkRunnerProfile drops one runner's binding; a missing binding is a
// successful no-op like the SQL DELETE. An empty runner ID is rejected
// exactly like the SQL store so the mem and PostgreSQL contracts agree.
func (m *memStore) UnlinkRunnerProfile(ctx context.Context, runnerID string) error {
	if runnerID == "" {
		return fmt.Errorf("storage: runner id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.runnerProfiles, runnerID)
	return nil
}

// RunnerIDsForProfile lists the runner IDs bound to one profile, ordered by
// runner ID to match the SQL ORDER BY.
func (m *memStore) RunnerIDsForProfile(ctx context.Context, profileID string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for id, pid := range m.runnerProfiles {
		if pid == profileID {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
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

// ---------------------------------------------------------------------------
// memStore: incremental repository-scoped test history (migration 0026)
// ---------------------------------------------------------------------------

// memHistoryKey is the in-memory analogue of the aggregate primary key.
func memHistoryKey(suite, class, name string) string {
	return suite + "\x00" + class + "\x00" + name
}

// memReportDelivery is one in-memory test_report_deliveries row (migration
// 0029): the server-computed payload digest and the report ID of a committed
// delivery.
type memReportDelivery struct {
	digest   string
	reportID string
}

// memReportDeliveryKey is the in-memory analogue of the (job_id,
// lease_generation, delivery_id) primary key.
func memReportDeliveryKey(jobID string, generation int64, deliveryID string) string {
	return jobID + "\x00" + strconv.FormatInt(generation, 10) + "\x00" + deliveryID
}

// InsertTestReportWithHistory mirrors the SQL contract without a database; it
// is the legacy (non-idempotent) entry point.
func (m *memStore) InsertTestReportWithHistory(ctx context.Context, rep model.TestReport, repoID string) (int64, error) {
	outcome, err := m.InsertTestReportWithHistoryDelivery(ctx, rep, repoID, TestReportDelivery{})
	if err != nil {
		return 0, err
	}
	return outcome.Version, nil
}

// InsertTestReportWithHistoryDelivery mirrors the SQL delivery transaction:
// report append, aggregate fold and the (job, generation, delivery ID)
// receipt commit together under the store lock. A replayed identical
// delivery returns the original report ID without appending or folding;
// a reused delivery ID with a different digest is a conflict.
func (m *memStore) InsertTestReportWithHistoryDelivery(ctx context.Context, rep model.TestReport, repoID string, delivery TestReportDelivery) (TestReportInsertOutcome, error) {
	if err := ctx.Err(); err != nil {
		return TestReportInsertOutcome{}, err
	}
	if repoID == "" {
		return TestReportInsertOutcome{}, fmt.Errorf("storage: test history repository identity is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if delivery.DeliveryID != "" {
		key := memReportDeliveryKey(delivery.JobID, delivery.LeaseGeneration, delivery.DeliveryID)
		if existing, ok := m.reportDeliveries[key]; ok {
			if existing.digest != delivery.ContentDigest {
				return TestReportInsertOutcome{}, fmt.Errorf("%w: job %s generation %d delivery %s", ErrTestReportDeliveryConflict, delivery.JobID, delivery.LeaseGeneration, delivery.DeliveryID)
			}
			return TestReportInsertOutcome{Replay: true, ReportID: existing.reportID}, nil
		}
		m.reportDeliveries[key] = memReportDelivery{digest: delivery.ContentDigest, reportID: rep.ID}
	}
	m.reports = append(m.reports, rep)
	rows := m.historyAggregates[repoID]
	if rows == nil {
		rows = map[string]TestHistoryAggregate{}
		m.historyAggregates[repoID] = rows
	}
	for _, c := range rep.Cases {
		// Skip policy: skipped cases are never folded as pass/fail
		// observations (see the PostgresStore delivery path).
		if c.Skipped {
			continue
		}
		key := memHistoryKey(rep.JobKey, c.Class, c.Name)
		row := rows[key]
		row.RepoID, row.Suite, row.Class, row.Name = repoID, rep.JobKey, c.Class, c.Name
		rows[key] = FoldTestHistoryAggregate(row, TestHistoryEntry{Suite: rep.JobKey, Class: c.Class, Name: c.Name, Duration: c.Duration, Passed: c.Passed, When: rep.CreatedAt})
	}
	m.historyVersions[repoID]++
	return TestReportInsertOutcome{Version: m.historyVersions[repoID], ReportID: rep.ID}, nil
}

func (m *memStore) LoadRepoTestHistory(ctx context.Context, repoID string) (int64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	version, ok := m.historyVersions[repoID]
	if !ok {
		return 0, nil, nil
	}
	rows := make([]TestHistoryAggregate, 0, len(m.historyAggregates[repoID]))
	for _, row := range m.historyAggregates[repoID] {
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
	stats, err := EncodeTestHistoryStats(rows)
	if err != nil {
		return 0, nil, err
	}
	return version, stats, nil
}

// memRunMatchesRepoQuery mirrors the server's runMatchesRepoQuery for the
// in-memory store: full name, canonical identity, or legacy host-less
// canonical form.
func memRunMatchesRepoQuery(r model.Run, query string) bool {
	if query == "" {
		return false
	}
	if query == r.RepoFullName || query == RepoIDForRun(r) {
		return true
	}
	return query == CanonicalRepoID("", r.RepoFullName)
}

func (m *memStore) ResolveTestHistoryRepoIDs(ctx context.Context, query string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 64
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	out := []string{}
	for _, r := range m.runs {
		if !memRunMatchesRepoQuery(r, query) {
			continue
		}
		id := RepoIDForRun(r)
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

// TestReportTotals mirrors the SQL contract: totals over EXACTLY the supplied
// canonical repository IDs, with no bare-name predicate (the full-name
// fallback belongs only to ResolveTestHistoryRepoIDs, which is candidate
// discovery). An empty set answers zero.
func (m *memStore) TestReportTotals(ctx context.Context, repoIDs []string, repoQuery string) (int, int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := map[string]bool{}
	for _, id := range repoIDs {
		if strings.TrimSpace(id) != "" {
			ids[id] = true
		}
	}
	if len(ids) == 0 {
		return 0, 0, 0, nil
	}
	var reports, tests, failures int
	for _, rep := range m.reports {
		run, ok := m.runs[rep.RunID]
		if !ok {
			continue
		}
		if !ids[RepoIDForRun(run)] {
			continue
		}
		reports++
		tests += rep.Tests
		failures += rep.Failures
	}
	return reports, tests, failures, nil
}

func (m *memStore) FlakyTestNames(ctx context.Context, repoIDs []string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 1000
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	out := []string{}
	for _, id := range repoIDs {
		for _, row := range m.historyAggregates[id] {
			// Window-derived predicate: identical to the SQL flake_prob > 0
			// and to testintel.History.Flaky.
			if row.FlakeProb <= 0 {
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

// ListTestHistoryRepoIDs returns every canonical repository ID with durable
// reports, in ascending order. The SQL store enumerates these with keyset
// pages of `limit` (TestHistoryRepoPageSize when non-positive); the
// in-memory store already holds the full set, so it returns the same complete
// enumeration without a page loop — the contract result is identical.
func (m *memStore) ListTestHistoryRepoIDs(ctx context.Context, limit int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	for _, rep := range m.reports {
		if run, ok := m.runs[rep.RunID]; ok {
			if id := RepoIDForRun(run); id != "" {
				seen[id] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// RebuildRepoTestHistory recomputes one repository's aggregates from the
// in-memory reports in created_at/id order — the same ordering the SQL
// repair uses.
func (m *memStore) RebuildRepoTestHistory(ctx context.Context, repoID string) (int64, error) {
	if repoID == "" {
		return 0, fmt.Errorf("storage: test history repository identity is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	reports := make([]model.TestReport, 0, len(m.reports))
	for _, rep := range m.reports {
		run, ok := m.runs[rep.RunID]
		if !ok || RepoIDForRun(run) != repoID {
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
	rows := map[string]TestHistoryAggregate{}
	for _, rep := range reports {
		for _, c := range rep.Cases {
			// Skip policy: excluded from the rebuilt aggregates exactly as
			// on the incremental path, so both agree.
			if c.Skipped {
				continue
			}
			key := memHistoryKey(rep.JobKey, c.Class, c.Name)
			row := rows[key]
			row.RepoID, row.Suite, row.Class, row.Name = repoID, rep.JobKey, c.Class, c.Name
			rows[key] = FoldTestHistoryAggregate(row, TestHistoryEntry{Suite: rep.JobKey, Class: c.Class, Name: c.Name, Duration: c.Duration, Passed: c.Passed, When: rep.CreatedAt})
		}
	}
	m.historyAggregates[repoID] = rows
	m.historyVersions[repoID]++
	return m.historyVersions[repoID], nil
}

// DisableRunnerAndRevokeCert is the memStore mirror of the SQL transaction:
// under one lock it revokes the runner's leases, disables the runner,
// records the durable-equivalent revocation and writes the audit evidence.
// A missing runner reports ErrNotFound and changes nothing.
func (m *memStore) DisableRunnerAndRevokeCert(ctx context.Context, runnerID, certSerial, actor string) (int, error) {
	if err := ValidateRunnerID(runnerID); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	disableAuditID, err := newID()
	if err != nil {
		return 0, err
	}
	revokeAuditID := ""
	if certSerial != "" {
		revokeAuditID, err = newID()
		if err != nil {
			return 0, err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ri, ok := m.runners[runnerID]
	if !ok {
		return 0, ErrNotFound
	}
	ids := []string{}
	for id, j := range m.jobs {
		if j.Status == model.StatusRunning && j.LeaseRunnerID == runnerID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	jobs := cloneRecoveryJobs(m.jobs)
	runners := cloneRecoveryRunners(m.runners)
	runs := cloneRecoveryRuns(m.runs)
	quotas := cloneRecoveryQuotas(m.quotas)
	reservations := cloneRecoveryReservations(m.reservations)
	audit := append([]model.AuditEvent(nil), m.audit...)
	revocations := map[string]string{}
	for k, v := range m.revocations {
		revocations[k] = v
	}
	now := time.Now().UTC()
	staged := 0
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
		// The invalidated lease releases its resource reservation in the
		// same transaction (a requeued job holds none until re-leased).
		releaseReservationMap(reservations, id)
		if err := m.recoveryBumpFor(&staged); err != nil {
			return 0, err
		}
		if requeue {
			adjustQuotaMap(quotas, RepoIDForJob(j), -1, 1)
		} else {
			adjustQuotaMap(quotas, RepoIDForJob(j), -1, 0)
		}
		if err := m.recoveryBumpFor(&staged); err != nil {
			return 0, err
		}
		action := "job.runner_disabled_cancelled"
		if requeue {
			action = "job.runner_disabled_requeued"
		}
		audit = append(audit, recoveryAudit(j, action, "admin", "runner disabled", map[string]string{"job": j.Key, "runner": runnerID}, now))
		if err := m.recoveryBumpFor(&staged); err != nil {
			return 0, err
		}
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
		if err := m.recoveryBumpFor(&staged); err != nil {
			return 0, err
		}
	}
	recomputeDependentsMap(jobs, changed, now)
	if err := m.recoveryBumpFor(&staged); err != nil {
		return 0, err
	}
	for runID := range runIDs {
		recomputeRunMap(runs, jobs, runID)
	}
	if err := m.recoveryBumpFor(&staged); err != nil {
		return 0, err
	}
	ri = runners[runnerID]
	ri.LastSeen = now
	ri.Disabled = true
	if certSerial != "" && ri.RevokedAt == nil {
		ri.RevokedAt = &now
	}
	runners[runnerID] = ri
	if certSerial != "" {
		revocations[certSerial] = runnerID
	}
	audit = append(audit, model.AuditEvent{ID: disableAuditID, Action: "runner.disable", Actor: actor, Message: "runner disabled", Metadata: map[string]string{"runner": runnerID}, CreatedAt: now})
	if certSerial != "" {
		audit = append(audit, model.AuditEvent{ID: revokeAuditID, Action: "runner.cert_revoked", Actor: actor, Message: "runner certificate serial revoked", Metadata: map[string]string{"runner": runnerID, "serial": certSerial}, CreatedAt: now})
	}
	if err := m.recoveryBumpFor(&staged); err != nil {
		return 0, err
	}
	m.jobs, m.runners, m.runs, m.quotas = jobs, runners, runs, quotas
	m.reservations = reservations
	m.audit, m.revocations = audit, revocations
	return len(ids), nil
}
