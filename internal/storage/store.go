// Package storage holds the durable control-plane state contracts. The
// filesystem Repository in fs.go remains the zero-dependency dev/local store;
// PostgresStore in postgres.go implements Store for HA deployments. The
// server keeps using its in-memory maps and the fs Repository until the
// scheduler phase wires the SQL store in.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Sentinel errors returned by Store implementations. Callers must compare
// with errors.Is: implementations may wrap them with query context.
var (
	ErrNotFound           = errors.New("storage: not found")
	ErrLeaseConflict      = errors.New("storage: lease conflict")
	ErrGenerationMismatch = errors.New("storage: lease generation mismatch")
	// ErrDeliveryDuplicate means a webhook delivery was already processed
	// by a previous enqueue: the InsertCompiledRun transaction rolled back
	// and the caller must return the original run.
	ErrDeliveryDuplicate = errors.New("storage: webhook delivery already processed")
	// ErrNoCapacity means the runner update inside AcquireLeaseAtomic
	// matched no runner row because the runner is at capacity; the job
	// lease was rolled back with it.
	ErrNoCapacity = errors.New("storage: runner at capacity")
	// ErrScheduleClaimLost means the (schedule, nominal) occurrence was
	// already claimed by a different run inside InsertCompiledRun; the
	// whole enqueue rolled back.
	ErrScheduleClaimLost = errors.New("storage: schedule occurrence claimed by another run")
	// ErrDownstreamLaunched means the downstream launch claim inside
	// InsertCompiledRun matched a link that is already launched with the
	// SAME stable child ID: the enqueue rolled back and the caller must
	// return the existing child run instead of creating a duplicate.
	ErrDownstreamLaunched = errors.New("storage: downstream link already launched")
	// ErrRequiredArtifactMissing means a successful job completion was
	// rolled back inside CompleteJob because the job's artifact contracts
	// declare a Required artifact with no matching artifact row yet. The
	// job stays running (not terminal) so the runner can upload the
	// artifact and retry the completion. The wrapped message names the
	// missing artifact.
	ErrRequiredArtifactMissing = errors.New("storage: required artifact missing")
	// ErrGrantConsumed means an enrollment grant's conditional consume
	// matched a row whose consumed_at is already set (a concurrent or
	// replayed enrollment): the grant is single-use and this caller lost.
	ErrGrantConsumed = errors.New("storage: enrollment grant already consumed")
	// ErrGrantExpired means an enrollment grant's expires_at has passed.
	ErrGrantExpired = errors.New("storage: enrollment grant expired")
	// ErrEnvConcurrency means the atomic lease's environment concurrency
	// predicate rejected the candidate: another running job already holds
	// the last slot of the candidate's (repo, environment) concurrency key.
	// The lease transaction rolled back; the scheduler tries the next
	// candidate.
	ErrEnvConcurrency = errors.New("storage: environment at capacity")
	// ErrQuotaExceeded means the atomic lease's conditional queued->running
	// quota transition matched zero rows: running+1 would exceed the
	// repository or team concurrency limit. The whole lease rolled back.
	// QuotaExceededError unwraps to this sentinel.
	ErrQuotaExceeded = errors.New("storage: quota concurrency exceeded")
	// ErrArtifactDigestConflict means an artifact row already exists for the
	// same (job_id, job_generation, name) idempotency key with a DIFFERENT
	// SHA256: the upload must be answered 409 and the stored record is never
	// overwritten.
	ErrArtifactDigestConflict = errors.New("storage: artifact digest conflict")
	// ErrCompletionConflict means a completion receipt already exists for the
	// same (job_id, generation, runner_id) identity but records a DIFFERENT
	// result_hash: two concurrent completions of one lease disagree, and the
	// losing result must fail closed (HTTP 409) instead of being acked as an
	// idempotent replay. An equal result_hash is still an idempotent success.
	ErrCompletionConflict = errors.New("storage: completion result conflict")
	// ErrLogBatchConflict means a log batch receipt already exists for the
	// same (job_id, generation, batch_id) identity but records a DIFFERENT
	// canonical payload digest: the runner reused a batch identity for
	// different lines, and the append fails closed (nothing is inserted)
	// instead of silently accepting the second payload or dropping it.
	ErrLogBatchConflict = errors.New("storage: log batch payload conflict")
)

// QuotaExceededError is returned by quota admission inside InsertCompiledRun
// when the reserved counters would exceed a configured limit. Reason carries
// the machine-readable admission reason (REPO_QUOTA/TEAM_QUOTA) and Msg the
// human-readable explanation. The whole enqueue transaction rolled back.
type QuotaExceededError struct {
	Reason string
	Msg    string
}

func (e *QuotaExceededError) Error() string {
	if e.Reason != "" {
		return e.Reason + ": " + e.Msg
	}
	return e.Msg
}

// Unwrap exposes the ErrQuotaExceeded sentinel so callers can match quota
// rejections with errors.Is regardless of which admission path (enqueue or
// atomic lease) produced them.
func (e *QuotaExceededError) Unwrap() error { return ErrQuotaExceeded }

// Store is the durable SQL contract for the control plane. It is separate
// from the filesystem Repository: the scheduler phase will back the server's
// in-memory maps with a Store instead of the fs snapshot.
//
// Error semantics:
//   - ErrNotFound: the addressed row does not exist.
//   - ErrLeaseConflict: a lease claim raced or the job is not in a leasable state.
//   - ErrGenerationMismatch: the presented lease generation/runner does not
//     match the job's current lease.
type Store interface {
	Close() error

	// runs
	InsertRun(ctx context.Context, run model.Run) error
	GetRun(ctx context.Context, id string) (model.Run, error)
	UpdateRunStatus(ctx context.Context, id string, status model.Status, startedAt, finishedAt *time.Time) error
	ListRuns(ctx context.Context, limit int) ([]model.Run, error)

	// jobs
	InsertJob(ctx context.Context, job model.Job) error
	GetJob(ctx context.Context, id string) (model.Job, error)
	ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error)
	// CountRunningJobs returns the number of jobs currently holding a
	// running lease (status='running') across every run, including
	// non-terminal runs. It is the authoritative in-flight count for a
	// graceful drain in DB mode: one aggregate query that never depends on
	// run pagination or per-run scans, so a drain can never conclude
	// "zero active jobs" from an incomplete or errored walk. An error means
	// the count is UNKNOWN, never zero.
	CountRunningJobs(ctx context.Context) (int, error)
	// ListJobsByEnvironment returns all jobs holding the given
	// repository-scoped environment, for environment concurrency accounting.
	// repoID is the CANONICAL repository identity ("<host>/<owner>/<name>",
	// see RepoIDForJob): the environment key is (RepoID, environment), so
	// two spellings of one clone URL (HTTPS/ssh) share one key while the
	// same environment name on two different repositories never does.
	// Legacy rows without a stored repo_id derive the same canonical
	// identity from their clone URL + full name.
	ListJobsByEnvironment(ctx context.Context, repoID, environment string) ([]model.Job, error)
	ListQueuedJobs(ctx context.Context) ([]model.Job, error)
	UpdateJob(ctx context.Context, job model.Job) error

	// leases
	// AcquireLease atomically claims a queued job: a single conditional
	// UPDATE ... SET status='running', lease fields ... WHERE id=$1 AND
	// status='queued' AND (lease_expires_at IS NULL OR lease_expires_at < now())
	// RETURNING *. A race (no row matched) returns ErrLeaseConflict.
	AcquireLease(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (model.Job, error)
	HeartbeatLease(ctx context.Context, jobID string, runnerID string, generation int64, expiresAt time.Time) error
	// CompleteJob is the one transaction for a runner completion: lock the
	// job FOR UPDATE, verify generation+runner+status running, insert the
	// completion receipt ON CONFLICT DO NOTHING (idempotent replay), update
	// the job, update runner counters, recompute dependent jobs and the run
	// status, and insert the audit event.
	CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt) error
	CancelRunJobs(ctx context.Context, runID string, reason string) ([]string, error)

	// runners
	UpsertRunner(ctx context.Context, runner model.Runner) error
	GetRunner(ctx context.Context, id string) (model.Runner, error)
	ListRunners(ctx context.Context) ([]model.Runner, error)
	ReleaseRunnerJob(ctx context.Context, runnerID, jobID string, status model.Status) error

	// artifacts, reports, logs, audit, deliveries, receipts
	InsertArtifact(ctx context.Context, a model.ArtifactRecord) error
	ListArtifacts(ctx context.Context, runID string) ([]model.ArtifactRecord, error)
	InsertTestReport(ctx context.Context, rep model.TestReport) error
	ListTestReports(ctx context.Context, runID string) ([]model.TestReport, error)
	ListTestReportsAll(ctx context.Context) ([]model.TestReport, error)
	AppendLog(ctx context.Context, e model.LogEntry) error
	ReadLogs(ctx context.Context, runID string, after int64, limit int) ([]model.LogEntry, error)
	AppendAudit(ctx context.Context, e model.AuditEvent) error
	ReadAudit(ctx context.Context, limit int) ([]model.AuditEvent, error)
	InsertCompletionReceipt(ctx context.Context, r model.CompletionReceipt) error
	HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error)
	UpsertDelivery(ctx context.Context, forge, deliveryID string, runID string, payloadDigest string) error
	FindDelivery(ctx context.Context, forge, deliveryID string) (string, bool, error)

	// leader / HA
	//
	// TryAcquireLeadership renews (or takes) the leadership claim and, on a
	// successful acquisition, publishes and retains a strictly-greater
	// leadership epoch on the same dedicated session (see LeaderFenceStore).
	// A true result may be served from a throttled cache and can therefore
	// briefly outlive the advisory-lock session; the epoch is what makes that
	// window harmless, because every leader-only mutation re-validates the
	// retained epoch inside its own transaction and fails closed with
	// ErrStaleLeader. See PostgresStore.TryAcquireLeadership for the full
	// invariant.
	TryAcquireLeadership(ctx context.Context, key string, ttl time.Duration) (bool, error)
	ReleaseLeadership(ctx context.Context, key string) error

	// schema
	Migrate(ctx context.Context) error
	SchemaVersion(ctx context.Context) (int, error)
}

// ---------------------------------------------------------------------------
// DB-mode extension stores
// ---------------------------------------------------------------------------
//
// These interfaces deliberately extend Store instead of widening it: they
// cover control-plane areas (durable outbox, cron schedules, deployments,
// workspace snapshots, artifact contracts, queue reasons) whose server wiring
// lands in a later phase. PostgresStore and the fault-injection memStore
// implement them so persistence and fault coverage exist before adoption;
// other Store implementations (the server/scheduler test fakes) compile
// unchanged because the Store interface itself is untouched.

// OutboxItem is one durable publish intent queued for dispatch.
//
// LogicalKey/StateVersion are set for VERSIONED forge-delivery intents
// (migration 0018): LogicalKey is the stable logical identity of the remote
// object (for a forge check: the 128-bit sha256 of forge host + run + check
// name) and StateVersion is the monotonic rank of the logical state it
// carries. Versioned row IDs are LogicalKey || '#' || StateVersion, so a
// newer state can never collide with, or be suppressed by, an older one.
type OutboxItem struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	Payload      []byte    `json:"payload"`
	CreatedAt    time.Time `json:"created_at"`
	LogicalKey   string    `json:"logical_key,omitempty"`
	StateVersion int64     `json:"state_version,omitempty"`
}

// VersionedEnqueueOutcome reports what OutboxEnqueueVersioned did with the
// intent.
type VersionedEnqueueOutcome int

const (
	// VersionedEnqueued: the intent was durably inserted (superseding older
	// pending versions of the same logical key).
	VersionedEnqueued VersionedEnqueueOutcome = iota
	// VersionedSuperseded: an equal-or-newer version is already delivered or
	// retired, so nothing was inserted and nothing must be dispatched.
	VersionedSuperseded
)

// ForgeCheckStateStore is the versioned forge-delivery contract:
//
//   - OutboxEnqueueVersioned atomically inserts a versioned intent and
//     supersedes every older pending version of the same logical key in ONE
//     operation, after checking the durable delivered watermark. It returns
//     VersionedSuperseded without inserting when the version is not newer
//     than what is already delivered.
//   - OutboxVersionGuard reports whether a claimed versioned row may be
//     published: false when a newer version is already delivered or pending,
//     or when the row itself no longer exists (a concurrent enqueue
//     superseded it). The check is durable, so two replicas cannot publish
//     an older state after a newer one once the newer one is visible.
//     A LEGACY pre-0018 row has NULL logical_key/state_version columns: the
//     dispatcher derives that identity from the payload and passes it here,
//     so those rows obey the same watermark invariant.
//   - OutboxMarkDelivered advances the durable delivered watermark for one
//     logical key after a successful publication. It exists for legacy rows
//     whose own ack cannot advance the watermark (their columns carry no
//     identity); versioned rows still advance it atomically inside
//     OutboxAck. GREATEST/max semantics keep the watermark monotonic.
//
// OutboxAck updates the delivered watermark in the same statement that
// deletes a VERSIONED row, so no separate method is needed for those; the
// explicit OutboxMarkDelivered exists only for legacy rows whose columns
// carry no identity.
type ForgeCheckStateStore interface {
	OutboxEnqueueVersioned(ctx context.Context, e OutboxItem) (VersionedEnqueueOutcome, error)
	OutboxVersionGuard(ctx context.Context, id, logicalKey string, version int64) (publish bool, err error)
	OutboxMarkDelivered(ctx context.Context, logicalKey string, version int64) error
}

// OutboxVersionLockNamespace is the advisory-lock key namespace that
// serializes versioned enqueues per logical key across replicas.
const OutboxVersionLockNamespace = "forge-check-state"

// Completion post-transaction effect outbox kinds. CompleteJob inserts ONE
// deterministic `completion_reconcile` row per (job, lease generation)
// INSIDE the completion transaction. Dispatching that single row runs the
// whole effect chain (each effect still checks its own durable marker before
// acting), which avoids the previous amplification where five durable rows
// each re-ran all five logical effects.
const (
	OutboxKindCompletionReconcile = "completion_reconcile"

	// OutboxKindForgeDelivery is the EXTERNAL forge-publication intent. It is
	// split from completion_reconcile so a persistently failing forge can
	// back off and dead-letter without ever retiring the INTERNAL consistency
	// row (markers/effects keep retrying until internal invariants converge).
	OutboxKindForgeDelivery = "forge_delivery"

	// Legacy per-kind rows remain recognized by the dispatcher for outbox
	// rows persisted before the single-row design.
	OutboxKindDownstreamCheck  = "downstream_check"
	OutboxKindDeploymentFinish = "deployment_finish"
	OutboxKindUsageAccount     = "usage_account"
	OutboxKindRunAggregate     = "run_aggregate"
	OutboxKindForgeStatus      = "forge_status"
)

// CompletionEffectsPayload is the outbox payload carried by completion
// effect intents.
type CompletionEffectsPayload struct {
	JobID string `json:"job_id"`
	RunID string `json:"run_id"`
}

// CompletionEffectKinds lists the legacy effect kinds (kept for dispatch
// compatibility with pre-existing rows). New completions persist exactly two
// intents: OutboxKindCompletionReconcile (internal consistency, unbounded
// retries) and OutboxKindForgeDelivery (external publication, bounded
// retries + dead-letter).
func CompletionEffectKinds() []string {
	return []string{
		OutboxKindDownstreamCheck,
		OutboxKindDeploymentFinish,
		OutboxKindUsageAccount,
		OutboxKindRunAggregate,
		OutboxKindForgeStatus,
	}
}

// CompletionEffectIntentCount is how many intents a NEW completion persists
// (completion_reconcile + forge_delivery). Legacy rows persist the five
// per-kind intents listed by CompletionEffectKinds.
const CompletionEffectIntentCount = 2

// NewCompletionEffectKinds is the ordered set of intents a NEW completion
// persists: ONE completion_reconcile row (internal consistency, unbounded
// retries) and ONE forge_delivery row (external publication, bounded retries
// + dead-letter). It is the single source of truth for the SQL completion
// transaction, the memStore mirror and the server's fs/memory enqueue path,
// and its size is pinned by CompletionEffectIntentCount.
func NewCompletionEffectKinds() []string {
	return []string{
		OutboxKindCompletionReconcile,
		OutboxKindForgeDelivery,
	}
}

// IsCompletionEffectKind reports whether kind is a completion effect intent:
// the split reconcile/forge_delivery rows or a legacy per-kind row.
func IsCompletionEffectKind(kind string) bool {
	if kind == OutboxKindCompletionReconcile || kind == OutboxKindForgeDelivery {
		return true
	}
	for _, k := range CompletionEffectKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

// InternalCompletionEffectKind reports whether kind is an INTERNAL completion
// effect: a completion effect whose dispatch runs the idempotent
// marker-guarded reconciliation chain, so it converges forever and is never
// dead-lettered. The external forge kinds (forge_delivery and the legacy
// forge_status) are carved out of the completion-effect family: they own the
// bounded retry/dead-letter policy, so a persistently failing forge can never
// retire the internal consistency rows.
func InternalCompletionEffectKind(kind string) bool {
	if !IsCompletionEffectKind(kind) {
		return false
	}
	switch kind {
	case OutboxKindForgeDelivery, OutboxKindForgeStatus:
		return false
	}
	return true
}

// CompletionEffectID derives the deterministic outbox item ID for one
// completion effect: sha256(job, lease generation, kind) truncated to the
// canonical 128-bit ID format. The store inserts effect rows under these
// IDs inside the completion transaction and the completing server queues
// the same IDs in memory, so the flush's OutboxAck removes the actual
// transaction rows.
func CompletionEffectID(jobID string, generation int64, kind string) string {
	sum := sha256.Sum256([]byte("kiwi-completion-effect\x00" + jobID + "\x00" + strconv.FormatInt(generation, 10) + "\x00" + kind))
	return hex.EncodeToString(sum[:16])
}

// OutboxClaimTTL is how long a flush's claim on an outbox row is honored
// before another replica may reclaim it. A claim is held between the atomic
// claim (SELECT ... FOR UPDATE SKIP LOCKED) and the durable ack; a flusher
// that crashes in between loses its claim after this TTL and the intent is
// retried by another replica.
const OutboxClaimTTL = 5 * time.Minute

// OutboxClaimBatch bounds how many rows one flush claims at a time. A crash
// can therefore strand at most this many intents for the TTL window.
const OutboxClaimBatch = 64

// OutboxStore is the durable outbox contract. OutboxAppend enqueues an item,
// OutboxAck removes a successfully dispatched item (clearing any claim),
// OutboxPending returns the unacked ACTIVE items (dead-lettered rows are
// excluded) in FIFO order for startup replay, and ClaimOutbox atomically
// claims a batch of dispatchable rows for one flusher so two replicas never
// dispatch the same intent: rows already claimed within OutboxClaimTTL are
// skipped and stale claims are reclaimable. ReleaseOutboxClaim returns an
// un-dispatched claim so a retry does not wait for the TTL.
type OutboxStore interface {
	OutboxAppend(ctx context.Context, e OutboxItem) error
	// OutboxHas reports whether the DURABLE store already holds this intent
	// ID. Recovery paths must distinguish "queued in this process" from
	// "durably recorded": a memory-only copy dies with the process and the
	// protected effect would be lost forever.
	OutboxHas(ctx context.Context, id string) (bool, error)
	OutboxAck(ctx context.Context, id string) error
	OutboxPending(ctx context.Context) ([]OutboxItem, error)
	ClaimOutbox(ctx context.Context, claimer string, limit int) ([]OutboxItem, error)
	ReleaseOutboxClaim(ctx context.Context, id, claimer string) error
}

// OutboxClaimBatchStore is the BATCH claim-release contract for a flusher
// that claimed one OutboxClaimBatch and then failed to dispatch some of it.
// ReleaseOutboxClaims clears every claim in ids that is still owned by
// claimer in ONE store operation, so a batch cleanup costs one round-trip
// with one aggregate deadline instead of one 5s-bounded round-trip per row
// (OutboxClaimBatch * per-row bound). The claimer match is the concurrency
// guard: a row re-claimed by another flusher in the meantime is left
// untouched and is not counted. It returns how many rows this call actually
// released; releasing an already-cleared or foreign-claimed id is a no-op,
// so replaying the batch is idempotent. Stores without this optional
// capability simply omit it; callers type-assert.
type OutboxClaimBatchStore interface {
	ReleaseOutboxClaims(ctx context.Context, ids []string, claimer string) (int, error)
}

// OutboxDeadLetter is one dead-lettered outbox row for operator inspection:
// the original intent plus why (and after how many attempts) it was retired.
type OutboxDeadLetter struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Payload        []byte    `json:"payload"`
	CreatedAt      time.Time `json:"created_at"`
	Attempts       int       `json:"attempts"`
	LastError      string    `json:"last_error"`
	DeadLetteredAt time.Time `json:"dead_lettered_at"`
	LogicalKey     string    `json:"logical_key,omitempty"`
	StateVersion   int64     `json:"state_version,omitempty"`
}

// OutboxDeadLetterStore is the operator-facing dead-letter contract for the
// durable outbox: list retired intents, requeue one for a fresh retry budget,
// or delete one. It deliberately extends the outbox area instead of widening
// OutboxStore, so existing Store implementations and test fakes compile
// unchanged.
type OutboxDeadLetterStore interface {
	// OutboxDeadLetters lists dead-lettered rows in FIFO order.
	OutboxDeadLetters(ctx context.Context) ([]OutboxDeadLetter, error)
	// OutboxRequeue resets one dead-lettered row to a fresh, immediately
	// dispatchable state: dead_lettered_at/attempts/last_error are cleared and
	// next_attempt_at is now(), so the row is claimable again. Only
	// dead-lettered rows can be requeued; an absent (or live) row returns
	// ErrNotFound.
	OutboxRequeue(ctx context.Context, id string) error
	// OutboxDelete removes one dead-lettered row. Only dead-lettered rows can
	// be deleted, so the operator API can never discard a live intent; an
	// absent (or live) row returns ErrNotFound.
	OutboxDelete(ctx context.Context, id string) error
}

// Schedule is one cron-triggered pipeline schedule. Repository is the
// repository full name (owner/name); RepoID is the canonical repository
// identity (forge host + full name); RepoURL is the clone URL; Forge is the
// forge adapter kind ("github"/"gitlab"/"forgejo"); Trusted marks a trusted
// schedule (creation/update/manual trigger require the repo-scoped
// trusted_run grant). Automatic firing uses these stored identity fields —
// never the request context — so sc.Repository is no longer both the clone
// URL and the identity.
type Schedule struct {
	ID         string     `json:"id"`
	Repository string     `json:"repository"`
	RepoID     string     `json:"repo_id,omitempty"`
	RepoURL    string     `json:"repo_url,omitempty"`
	Forge      string     `json:"forge,omitempty"`
	Trusted    bool       `json:"trusted,omitempty"`
	Spec       string     `json:"spec"`
	Enabled    bool       `json:"enabled"`
	LastRun    *time.Time `json:"last_run,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	// CreatedBy is the authenticated principal subject that created or last
	// updated the schedule. Trusted schedules are re-authorized against the
	// current principal store at automatic fire time, so trust is revocable.
	CreatedBy string `json:"created_by,omitempty"`
}

// Occurrence is one claimed firing of a schedule: the nominal time the cron
// spec resolved to and the run that was created for it.
type Occurrence struct {
	ScheduleID string    `json:"schedule_id"`
	Nominal    time.Time `json:"nominal"`
	RunID      string    `json:"run_id"`
}

// ScheduleStore is the durable schedule contract. ClaimScheduleOccurrence
// atomically reserves the (schedule, nominal) firing for runID and reports
// whether this call made the claim; re-claiming the same nominal for the same
// runID is idempotent and reports true, while a conflicting runID reports
// false.
type ScheduleStore interface {
	UpsertSchedule(ctx context.Context, s Schedule) error
	ListSchedules(ctx context.Context) ([]Schedule, error)
	// GetSchedule re-reads the authoritative row. The scheduler calls it
	// immediately before firing an occurrence, because a disablement,
	// spec update, trust downgrade or identity change performed on another
	// replica must take effect on the current leader without waiting for a
	// full reload.
	GetSchedule(ctx context.Context, id string) (Schedule, bool, error)
	ClaimScheduleOccurrence(ctx context.Context, scheduleID string, nominal time.Time, runID string) (bool, error)
	ListOccurrences(ctx context.Context, scheduleID string) ([]Occurrence, error)
	// AdvanceScheduleLastRun moves the schedule's LastRun marker forward to
	// nominal, durably and MONOTONICALLY: last_run is set to
	// GREATEST(existing, nominal), so a stale replica (or a retried skip)
	// can never move the marker backwards and make an already-settled
	// occurrence due again. Implementations must persist before returning
	// nil; an error means the marker was not advanced and the caller must
	// retry the advance on its next tick instead of touching a local
	// mirror.
	AdvanceScheduleLastRun(ctx context.Context, id string, nominal time.Time) error
}

// DeploymentStore is the durable deployment record contract.
type DeploymentStore interface {
	InsertDeployment(ctx context.Context, d model.Deployment) error
	ListDeploymentsByRun(ctx context.Context, runID string) ([]model.Deployment, error)
	UpdateDeploymentStatus(ctx context.Context, id string, status model.Status, finishedAt *time.Time) error
}

// SnapshotStore is the durable workspace snapshot record contract.
type SnapshotStore interface {
	InsertSnapshotRecord(ctx context.Context, rec model.SnapshotRecord) error
	ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error)
}

// ArtifactContract declares the artifacts a job promises to produce,
// persisted per job so consumers can verify uploads before use.
type ArtifactContract struct {
	Name             string        `json:"name"`
	Paths            []string      `json:"paths,omitempty"`
	Required         bool          `json:"required,omitempty"`
	Retention        time.Duration `json:"retention,omitempty"`
	MaxSize          int64         `json:"max_size,omitempty"`
	SHA256           string        `json:"sha256,omitempty"`
	SBOM             string        `json:"sbom,omitempty"`
	SigstoreRequired bool          `json:"sigstore_required,omitempty"`
	SigstoreIssuer   string        `json:"sigstore_issuer,omitempty"`
	SigstoreIdentity string        `json:"sigstore_identity,omitempty"`
}

// ArtifactContractStore is the durable per-job artifact contract contract.
// InsertJobContracts overwrites the full contract set for jobID; the bool
// returned by GetJobContracts reports whether a set is stored for the job.
type ArtifactContractStore interface {
	InsertJobContracts(ctx context.Context, jobID string, contracts map[string]ArtifactContract) error
	GetJobContracts(ctx context.Context, jobID string) (map[string]ArtifactContract, bool, error)
}

// QueueReasonStore persists scheduling queue reasons without rewriting whole
// job payloads: one jsonb_set per job. An empty reason removes the stored
// reason for that job.
type QueueReasonStore interface {
	SetQueueReasons(ctx context.Context, reasons map[string]string) error
}

// DownstreamLink is one cross-repo dispatch claim: a parent job's downstream
// declaration resolved to a target repository/ref. The link row is the
// exactly-once claim: leader dispatch atomically reserves the link
// (ReserveDownstreamLaunchLeader, epoch-fenced) BEFORE the child run is
// enqueued, and a link whose ChildRunID is set is never launched twice.
// TargetForge/TargetBaseURL/TargetRepoID persist the forge identity
// coordinates so dispatch never re-derives hosts from hard-coded public
// endpoints.
type DownstreamLink struct {
	ParentJobID   string     `json:"parent_job_id"`
	TargetRepo    string     `json:"target_repo"`
	TargetRef     string     `json:"target_ref"`
	LaunchToken   string     `json:"launch_token"`
	ChildRunID    string     `json:"child_run_id,omitempty"`
	Reserved      bool       `json:"reserved,omitempty"`
	ReservedAt    *time.Time `json:"reserved_at,omitempty"`
	TargetForge   string     `json:"target_forge,omitempty"`
	TargetBaseURL string     `json:"target_base_url,omitempty"`
	TargetRepoID  string     `json:"target_repo_id,omitempty"`
	// StableChildID is the derived launch idempotency key
	// (sha256(parent_job, target_repo, target_ref) hex). Every launch of
	// this link uses the SAME child run ID (the first 32 hex chars of the
	// key), so a crash between reservation and child launch can never
	// produce a duplicate child.
	StableChildID string    `json:"stable_child_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// DynamicStore persists atomically generated child jobs uploaded by a
// runner under an active lease (dynamic pipeline generation). The jobs are
// already fully compiled (IDs, needs resolved); the transaction makes the
// whole fragment visible or nothing.
type DynamicStore interface {
	InsertGeneratedJobs(ctx context.Context, parentJobID string, depth int, jobs map[string]model.Job, deps map[string][]string) error
}

// GeneratedJobVerifier is the transactional recheck closure for dynamic
// fragment insertion: the store reads the parent job FOR UPDATE and counts
// the run's jobs inside the transaction, then calls the verifier with that
// fresh state; a returned error rolls the whole fragment back.
type GeneratedJobVerifier func(parent model.Job, runJobCount int) error

// GeneratedFragmentChild is one created child of a generated fragment: the
// compiled fragment key (matrix/shard suffixes included) and the assigned
// job ID, in the order the admitting server reported them.
type GeneratedFragmentChild struct {
	Key string `json:"key"`
	ID  string `json:"id"`
}

// GeneratedFragmentReceipt is the durable idempotency receipt of one
// generated fragment upload: the (parent job, lease generation, fragment
// digest) triple maps to the children created for it, in canonical
// (sorted-key) order, so a replay reconstructs the original response
// exactly.
type GeneratedFragmentReceipt struct {
	ParentJobID     string                   `json:"parent_job_id"`
	LeaseGeneration int64                    `json:"lease_generation"`
	FragmentID      string                   `json:"fragment_id"`
	Children        []GeneratedFragmentChild `json:"children"`
	CreatedAt       time.Time                `json:"created_at"`
}

// GeneratedFragmentRequest is the full transactional fragment payload: the
// receipt identity, the already-compiled child jobs, their dependency edges
// and artifact contracts. The verification closure and the receipt are
// evaluated inside the same transaction as the insertion. Children lists the
// created child key/ID pairs in canonical (sorted fragment key) order,
// matching the response the admitting server reported.
type GeneratedFragmentRequest struct {
	ParentJobID     string
	Depth           int
	LeaseGeneration int64
	FragmentID      string
	Jobs            map[string]model.Job
	Deps            map[string][]string
	Contracts       map[string]map[string]ArtifactContract
	Children        []GeneratedFragmentChild
}

// GeneratedFragmentStore reads the idempotency receipt of a previously
// admitted fragment so a replayed upload returns the same children without
// re-inserting anything.
type GeneratedFragmentStore interface {
	GetGeneratedFragment(ctx context.Context, parentJobID string, generation int64, fragmentID string) (GeneratedFragmentReceipt, bool, error)
}

// DynamicStoreTx is the transactional dynamic-fragment contract. The
// verification closure and the idempotency receipt are evaluated inside the
// same transaction as the fragment insertion, so a stale lease or an
// over-cap run rejects the fragment atomically and a replayed fragment
// (same parent, generation and fragment id) returns the ORIGINAL receipt
// with replayed=true and inserts nothing. The fragment's artifact contracts
// commit in the SAME transaction as the jobs — a generated job with a
// required artifact has its contract row visible before any completion can
// run.
type DynamicStoreTx interface {
	InsertGeneratedFragmentTx(ctx context.Context, req GeneratedFragmentRequest, verify GeneratedJobVerifier) (GeneratedFragmentReceipt, bool, error)
}

// DownstreamStore is the durable cross-repo dispatch claim contract.
// InsertDownstreamLink records a launch intent (the link row is the claim);
// GetDownstreamLink reads it; ReserveDownstreamLaunch atomically reserves
// the link for the calling flusher (claim-if-unreserved, creating the row
// when a restart dropped it) BEFORE the child run is enqueued;
// MarkDownstreamLaunched sets the child run ID after a successful enqueue;
// ReleaseDownstreamReservation clears a reservation whose launch failed so a
// retried dispatch can re-reserve; ExpireDownstreamReservations releases
// reservations older than the given cutoff (crash recovery).
//
// Fencing split, exactly:
//
//   - InsertDownstreamLink (completion-effect recording) and
//     GetDownstreamLink (inspection) are unfenced plain persistence/reads:
//     recording an intent launches nothing, and reading mutates nothing.
//   - ReserveDownstreamLaunch, MarkDownstreamLaunched and
//     ReleaseDownstreamReservation are the UNFENCED operator/compatibility
//     mutators: no leader-dispatch caller uses them anymore (dispatch uses
//     DownstreamLeaderStore), they carry no leader authority, and they keep
//     working without a leadership epoch (operator triage, admin tooling,
//     non-Postgres doubles).
//   - ExpireDownstreamReservations is the leader-only reservation-recovery
//     sweep and is epoch-fenced by its implementation.
//
// Leader-owned dispatch must use DownstreamLeaderStore for reserve/release/
// append and reaches the fenced child enqueue through InsertCompiledRun's
// DownstreamLaunch claim (epoch-fenced inside the enqueue itself).
type DownstreamStore interface {
	InsertDownstreamLink(ctx context.Context, l DownstreamLink) error
	GetDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (DownstreamLink, bool, error)
	ReserveDownstreamLaunch(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error)
	MarkDownstreamLaunched(ctx context.Context, parentJobID, targetRepo, targetRef, childRunID string) error
	ReleaseDownstreamReservation(ctx context.Context, parentJobID, targetRepo, targetRef string) error
	ExpireDownstreamReservations(ctx context.Context, olderThan time.Time) (int, error)
}

// DownstreamLeaderStore is the leader-dispatch-fenced extension of
// DownstreamStore, implemented by PostgresStore and used ONLY by the
// leader-owned downstream dispatch chain (internal/server/downstream.go,
// driven by the leader-only outbox flush). Every method validates the
// store's retained leadership epoch inside its transaction and fails closed
// with ErrStaleLeader — mutating nothing — when another replica has published
// a newer epoch, so a replica whose cached claim outlived its advisory-lock
// session can neither reserve a link, record a parent→child edge, nor clear a
// reservation.
//
// The child launch itself is fenced by the enqueue that creates it:
// InsertCompiledRun with req.DownstreamLaunch set is leader-only work and
// epoch-fenced before the first insert. The unfenced DownstreamStore methods
// remain the operator/compatibility surface and are not used by dispatch.
type DownstreamLeaderStore interface {
	// ReserveDownstreamLaunchLeader is the fenced sibling of
	// ReserveDownstreamLaunch, used by leader dispatch.
	ReserveDownstreamLaunchLeader(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error)
	// ReleaseDownstreamReservationLeader is the fenced sibling of
	// ReleaseDownstreamReservation, used by leader dispatch failure/cleanup.
	ReleaseDownstreamReservationLeader(ctx context.Context, parentJobID, targetRepo, targetRef string) error
	// AppendDownstreamRunLeader is the fenced sibling of AppendDownstreamRun,
	// used by leader dispatch for the wait=true parent→child edge.
	AppendDownstreamRunLeader(ctx context.Context, runID, childRunID string) error
}

// UsageStore reports aggregated cost and energy usage since a cutoff time
// (the trailing daily-budget window). PostgresStore derives it from the
// cost/energy fields stored inside the jobs payload column.
type UsageStore interface {
	RecentUsage(ctx context.Context, since time.Time) (cost, energy float64, err error)
}

// RunDownstreamStore persists the parent run's child-run tracking for
// downstream wait=true aggregation: AppendDownstreamRun appends childRunID
// to the run's downstream_runs payload key exactly once (idempotent), and
// ReopenRunForChildren marks a terminal-success run running again while
// its wait=true children are still in flight (clearing finished_at).
//
// AppendDownstreamRun is the UNFENCED operator/compatibility variant; the
// leader-owned downstream dispatch uses AppendDownstreamRunLeader from
// DownstreamLeaderStore instead (epoch-fenced, fails closed with
// ErrStaleLeader). ReopenRunForChildren is aggregation bookkeeping driven by
// child completion from any replica; it is not leader-gated.
type RunDownstreamStore interface {
	AppendDownstreamRun(ctx context.Context, runID, childRunID string) error
	ReopenRunForChildren(ctx context.Context, runID string) error
}

// ArtifactLookupStore resolves one artifact record by ID (the artifact
// download path in DB mode). PostgresStore reads the artifacts table's
// payload column.
type ArtifactLookupStore interface {
	GetArtifact(ctx context.Context, id string) (model.ArtifactRecord, error)
}

// ArtifactIdempotentStore is the authoritative artifact-upload idempotency
// contract: the (job_id, job_generation, name) unique key makes the database
// the arbiter when two replicas stage the same artifact name concurrently.
// InsertArtifactOnce inserts the record unless the key already exists; on a
// conflict it returns the STORED record with created=false — and
// ErrArtifactDigestConflict when the stored SHA256 differs from the incoming
// digest. The caller answers 200/existing for the same digest and 409 for a
// different one; the stored record is never overwritten.
type ArtifactIdempotentStore interface {
	InsertArtifactOnce(ctx context.Context, a model.ArtifactRecord) (model.ArtifactRecord, bool, error)
}

// RunnerJobStore lists the currently running jobs leased by one runner. The
// runner disable kill switch itself goes through RecoveryStore
// (RevokeRunnerLeases); this read contract remains for inspection and for
// callers that need the lease set before deciding what to do with it.
type RunnerJobStore interface {
	ListJobsByRunner(ctx context.Context, runnerID string) ([]model.Job, error)
}

// RecoveryStore is the transaction-per-transition contract for lease
// recovery and revocation. Every method applies the complete transition —
// job row and payload, lease clearing, runner active-set/counters, quota
// counters, dependent jobs, run aggregation and the audit event — in the
// SAME durable transaction, so a crash between "job terminal/requeued" and
// "runner slot/quota released" is impossible. The methods are idempotent:
// a second caller (another replica racing the same recovery) observes the
// already-transitioned state and changes nothing.
//
// This replaces the previous scheduler-side multi-step sequencing
// (UpdateJob + ReleaseRunnerJob + quota release + Go-level recompute), which
// a crash could split and strand a runner slot or a quota reservation
// forever.
type RecoveryStore interface {
	// RevokeRunnerLeases invalidates every running lease held by runnerID
	// (the runner-disable kill switch). Each running job either requeues
	// (infrastructure retry budget still available) or is terminal-cancelled
	// with the given reason; lease fields are cleared, the runner's
	// active_jobs entry is removed, the running quota slot is released (and
	// the queued slot re-reserved for a requeued job), dependent jobs and the
	// affected runs are recomputed, and one audit event per job is written.
	// It returns the IDs of the revoked jobs.
	RevokeRunnerLeases(ctx context.Context, runnerID, reason string) ([]string, error)
	// RecoverExpiredLease transitions ONE running job whose lease expired
	// (LeaseExpiresAt <= now): requeue while the infrastructure retry budget
	// is available, otherwise terminal failure. The expectedGeneration
	// guards against recovering a lease that was replaced concurrently: a
	// job whose current lease generation differs, or that is no longer
	// running, is left untouched (nil error, no-op). The transition clears
	// the lease, releases the runner slot, moves the quota counter, and
	// recomputes dependents and the run in the same transaction.
	//
	// A payload that cannot be decoded does NOT leave the job running with
	// its runner slot, quota reservation and lease stranded: retry policy
	// cannot be trusted from a corrupt payload, so the job is terminally
	// failed with an explicit corruption reason
	// (CorruptLeaseRecoveryReason), the lease columns are cleared, the
	// runner active slot and the running quota reservation are released from
	// the relational columns (lease_runner_id, run_id), and one audit event
	// records the forced recovery — all in the same fenced transaction.
	RecoverExpiredLease(ctx context.Context, jobID string, expectedGeneration int64, now time.Time) error
	// ExpireQueuedJob terminal-cancels ONE queued (or approval-waiting) job
	// whose queue deadline has passed, releases its reserved queued quota
	// slot, and recomputes dependents and the run in the same transaction.
	// deadline is the persisted queue_deadline column the caller observed; a
	// ZERO deadline means the caller observed no persisted column (a legacy
	// row whose only deadline source is the payload). The effective deadline
	// is re-derived under the row lock exactly like QueueDeadlineFor (column
	// first, then the payload/compiled fallback for legacy rows), and the
	// job is expired only while that effective deadline is not after the
	// observed one and has elapsed. A job that is no longer queued, whose
	// deadline moved, or whose deadline cannot be established is left
	// untouched (no-op).
	//
	// A payload that cannot be decoded does NOT keep the queued quota
	// reservation forever: when the deadline is provable from the relational
	// column, the malformed job is terminally cancelled with an explicit
	// corruption reason (CorruptQueueExpiryReason) and the queued
	// reservation is released in the same transaction.
	ExpireQueuedJob(ctx context.Context, jobID string, deadline time.Time) error
}

// RunnerDisableStore is the ATOMIC runner-disable kill switch. It exists
// because the previous admin path composed several independent operations
// (UpsertRunner(disabled), RevokeRunnerLeases, RevokeCert, audit) and answered
// success even when the durable certificate revocation was never recorded: a
// disabled runner's still-valid certificate could then be replayed on another
// replica. DisableRunnerAndRevokeCert performs the whole disable in ONE
// transaction and the handler fails closed (no success response) when it
// cannot commit it.
type RunnerDisableStore interface {
	// DisableRunnerAndRevokeCert disables runnerID, invalidates every running
	// lease it holds (requeue or terminal-cancel exactly like
	// RevokeRunnerLeases), records the durable certificate revocation for
	// certSerial (skipped when certSerial is empty; permanent — re-enabling
	// the runner never clears it), and writes the audit evidence
	// (runner.disable and, when a serial is revoked, runner.cert_revoked)
	// inside the SAME transaction. It returns the number of invalidated
	// leases. Replaying the call is state-idempotent: already-revoked leases
	// move nothing and the revocation insert is conflict-tolerant.
	DisableRunnerAndRevokeCert(ctx context.Context, runnerID, certSerial, actor string) (revoked int, err error)
}

// RecoveryCandidate is one bounded-discovery result built ONLY from the
// authoritative relational job columns: the recovery sweeper needs no decoded
// payload to decide what to look at and to hand the appliers their guards.
// Decoding the payload during discovery used to be the single point where a
// malformed row silently disappeared from every sweep; carrying the
// relational identity instead means a corrupt row is still discovered and
// the fenced applier transaction (which re-reads the row and its columns
// under FOR UPDATE) is the place that decides what can be done with it.
//
// Fields:
//   - ID: jobs.id, the keyset cursor and the applier target.
//   - LeaseGeneration: the lease_generation COLUMN (never the payload copy),
//     the idempotence/race guard RecoverExpiredLease expects.
//   - QueueDeadline: the authoritative queue_deadline COLUMN (migration
//     0021, NULL when the row predates it). Nil means "the persisted column
//     holds no deadline"; the applier then falls back to the payload-derived
//     deadline EXACTLY as QueueDeadlineFor does, so legacy rows keep expiring
//     while a corrupt payload can never invent one.
type RecoveryCandidate struct {
	ID              string
	LeaseGeneration int64
	QueueDeadline   *time.Time
}

// RecoveryDiscoveryStore is the READ-ONLY half of RecoveryScanStore: the
// bounded, id-paged candidate queries the sweeper drives. It is a separate
// interface so read-only wrappers (FaultyStore) can fail closed with a precise
// capability error without demanding the applier transactions.
//
// Cursor semantics (both methods): results are a bounded page of
// RecoveryCandidates whose id is strictly greater than afterID, ordered by id
// ASC (jobs.id is the TEXT PRIMARY KEY, so the order is total and stable, and
// the cursor is the last id of the previous page). Ordering by (deadline, id)
// with an id-only cursor would SKIP candidates whose deadline sorts later than
// the last visited deadline while their id is smaller, so the cursor is the
// id order itself. A caller pages by calling with afterID="" and then with the
// last returned id until a page shorter than limit arrives. Because the
// cursor advances past every returned row even when its apply fails, one
// persistently failing row can never stall the rows behind it; a later sweep
// (restarting at afterID="") revisits the failure. limit <= 0 returns no rows.
//
// The reads are candidates, not decisions: the applier transaction re-checks
// the lease generation / effective deadline under its own lock, so a candidate
// that changed after discovery is a no-op. Discovery reads only relational
// columns, so an individually undecodable payload can neither be skipped
// (which used to hide the row from every sweep forever) nor shadow the
// candidates after it.
type RecoveryDiscoveryStore interface {
	// ListExpiredRunningJobs returns running jobs whose lease expired at or
	// before now: lease_expires_at <= now, or lease_expires_at IS NULL
	// (a running job with no recorded expiry is exactly the orphaned lease
	// the sweep exists to recover). Ordered by id ASC, id > afterID.
	ListExpiredRunningJobs(ctx context.Context, now time.Time, afterID string, limit int) ([]RecoveryCandidate, error)
	// ListQueueTimedOutJobs returns queued or approval-waiting jobs whose
	// queue deadline elapsed (effective deadline <= now), ordered by id ASC,
	// id > afterID. It may return the superset of jobs that have a deadline
	// source but whose effective deadline still lies in the future when the
	// deadline is only derivable from a legacy compiled payload; the applier
	// re-derives the effective deadline (QueueDeadlineFor semantics) and
	// no-ops while it is absent or still in the future.
	ListQueueTimedOutJobs(ctx context.Context, now time.Time, afterID string, limit int) ([]RecoveryCandidate, error)
}

// RecoveryScanStore couples the transactional per-candidate recovery appliers
// (RecoveryStore) with bounded, PAGED candidate discovery. The recovery
// sweeper must never enumerate runs and filter jobs in Go: with more than one
// page of newer runs, an old non-terminal job holding an expired lease (or an
// elapsed queue deadline) would fall outside every future sweep permanently.
// These queries visit candidates DIRECTLY, in id order, so every candidate is
// eventually reached no matter how many newer runs exist.
type RecoveryScanStore interface {
	RecoveryStore
	RecoveryDiscoveryStore
}

// WebhookClaim is the delivery-dedupe claim persisted inside the enqueue
// transaction: the (forge, delivery) row is inserted with ON CONFLICT DO
// NOTHING and a conflict rolls the whole enqueue back with
// ErrDeliveryDuplicate.
type WebhookClaim struct {
	Forge         string `json:"forge"`
	DeliveryID    string `json:"delivery_id"`
	PayloadDigest string `json:"payload_digest,omitempty"`
	RunID         string `json:"run_id"`
}

// QuotaReservation carries the quota admission decision into the enqueue
// transaction: the RepoKey/TeamKey counters are locked FOR UPDATE and
// incremented by JobCount after the limits are re-checked against the
// locked values, closing the check-then-reserve race. RepoKey is the run's
// canonical RepoID and TeamKey its host/owner team key (see QuotaKeys), so
// same-named repositories on different forges never share a counter.
// Zero/negative limits are unlimited.
type QuotaReservation struct {
	RepoKey  string `json:"repo_key"`
	TeamKey  string `json:"team_key"`
	JobCount int    `json:"job_count"`
	// Limits re-enforced inside the transaction.
	RepoConcurrency float64 `json:"repo_concurrency,omitempty"`
	TeamConcurrency float64 `json:"team_concurrency,omitempty"`
	RepoQueueDepth  float64 `json:"repo_queue_depth,omitempty"`
	TeamQueueDepth  float64 `json:"team_queue_depth,omitempty"`
}

// ScheduleClaim is the (schedule, nominal) occurrence claim persisted
// inside the enqueue transaction: the occurrence row and the run row
// commit or roll back together, and only a committed run advances the
// schedule's LastRun.
type ScheduleClaim struct {
	ScheduleID string    `json:"schedule_id"`
	Nominal    time.Time `json:"nominal"`
}

// DownstreamLaunchClaim folds the downstream child launch into the enqueue
// transaction: the child run insertion and the downstream link update
// (ChildRunID + StableChildID, reservation consumed) commit atomically, so
// a crash between the reservation and the child launch can never produce a
// duplicate child. LinkKey is the (parent_job, target_repo, target_ref)
// claim key; StableChildID is the derived launch idempotency key (sha256
// hex) whose first 32 hex chars are the child run ID. When the link is
// already launched with the SAME stable child ID the enqueue returns
// ErrDownstreamLaunched (the caller re-reads the existing child run).
//
// Carrying this claim makes the enqueue leader-only work: the whole
// transaction is epoch-fenced (fails closed with ErrStaleLeader, mutating
// nothing) before the first insert, because a downstream child launch is
// leader-owned outbox work.
type DownstreamLaunchClaim struct {
	LinkKey       string `json:"link_key"`
	StableChildID string `json:"stable_child_id"`
}

// DigestFencer serializes CAS publication and collection per digest. A
// writer holds the fence across "publish object + commit durable reference";
// the collector holds the same fence across "re-read references + delete".
// DB implementations use a session advisory lock so the fence spans HA
// replicas; memory implementations use a per-digest mutex.
type DigestFencer interface {
	WithDigestFence(ctx context.Context, digest string, fn func() error) error
}

// SupersedePolicy folds concurrency-group cancel-in-progress supersession
// into the enqueue transaction: every other non-terminal run of the same
// repository and concurrency group is cancelled — jobs terminal-cancelled
// with leases cleared, runner slots and quota released, dependents
// re-evaluated — in the SAME commit as the new run, or the whole enqueue
// rolls back. Stores resolve the conflicting runs INSIDE the transaction
// (SQL: under a per-(repo, group) advisory lock) so concurrent superseding
// enqueues of one group serialize and exactly one run survives
// non-terminal; the loser's cancellation commits together with the winner.
//
// RepoID is the CANONICAL repository identity of the checkout repository
// (model.Run.RepoID, see RepoIDForRun), never a clone URL: submitting the
// same repository once via HTTPS and once via SSH must supersede, while two
// repositories whose clone URLs only coincidentally match (mirrors, forks
// with identical names on different forges) must not. Stores compare the
// stored payload's repo_id and fall back to the legacy URL + full-name
// derivation for rows persisted before RepoID existed.
type SupersedePolicy struct {
	RepoID           string `json:"repo_id"`
	ConcurrencyGroup string `json:"concurrency_group"`
}

// InsertCompiledRunRequest is the full atomic-enqueue payload: one run, its
// compiled jobs, dependency edges, artifact contracts, superseded job IDs,
// an optional concurrency-group supersede policy, and the optional
// webhook-dedupe, quota-reservation, schedule-occurrence and
// downstream-launch claims. Everything commits in a single transaction or
// nothing does.
//
// ScheduleClaim and DownstreamLaunch make the enqueue leader-only work and
// the transaction is epoch-fenced before the first insert: a stale leader
// fires no occurrence and launches no downstream child. Requests carrying
// neither are ordinary submissions and are not leader-gated.
//
// The run's and jobs' canonical RepoID rides the run/job payload (jsonb), so
// no dedicated column is required; RepoIDForJob/RepoIDForRun recover the
// identity for records persisted before the field existed.
//
// Deps is the authoritative dependency-edge map for the enqueued jobs: when
// it carries an entry for a job ID that entry (including an explicitly empty
// list) replaces the job's Needs, so the persisted edges always match what
// the caller compiled. Jobs without a Deps entry keep their Needs.
type InsertCompiledRunRequest struct {
	Run              model.Run
	Jobs             map[string]model.Job
	Deps             map[string][]string
	Contracts        map[string]map[string]ArtifactContract
	CancelPrevious   []string
	Supersede        *SupersedePolicy
	WebhookClaim     *WebhookClaim
	Quota            *QuotaReservation
	ScheduleClaim    *ScheduleClaim
	DownstreamLaunch *DownstreamLaunchClaim
}

// effectiveNeeds resolves the dependency edges persisted for one enqueued
// job: the request's Deps entry is authoritative when present, otherwise the
// job's own Needs list is used. The result is always a fresh slice.
func effectiveNeeds(id string, j model.Job, deps map[string][]string) []string {
	needs, ok := deps[id]
	if !ok {
		return j.Needs
	}
	return append([]string(nil), needs...)
}

// RunEnqueueStore is the atomic enqueue contract: InsertCompiledRun persists
// the run, its jobs, dependencies and artifact contracts, cancels superseded
// jobs (explicit CancelPrevious IDs and/or the in-transaction Supersede
// policy), and claims the delivery/quota/schedule reservations in ONE
// transaction. On a webhook-dedupe conflict it returns ErrDeliveryDuplicate
// (the caller re-reads the original run via FindDelivery); on a quota limit
// it returns *QuotaExceededError; on a schedule-occurrence conflict it
// returns ErrScheduleClaimLost.
type RunEnqueueStore interface {
	InsertCompiledRun(ctx context.Context, req InsertCompiledRunRequest) error
}

// LeaseClaim is the full atomic-lease request. JobID/RunnerID/TokenHash/
// Generation/ExpiresAt carry the lease itself; every other field is a
// scheduling predicate that the claim transaction MUST enforce before the
// runner slot is appended:
//
//   - RunnerCapacity is the caller's registration snapshot. The SQL claim
//     reads the runner's live capacity column instead, and when the runner
//     has a live profile link the profile's MaxCapacity wins over both, so
//     a profile edit takes effect on the very next lease. Memory stores
//     that keep no live row read this field.
//   - Runtime/CanonRepoID/RepoFullName/RequiredLabels/PlacementRegions are
//     checked against the LIVE profile rows (cert_profile_links ->
//     runner_profiles) when the runner is linked; an unlinked runner keeps
//     the legacy behavior (predicates evaluated by the caller's snapshot).
//     CanonRepoID is the job's immutable canonical RepoID
//     ("<host>/<owner>/<name>"), so a profile grant for github.com/acme/api
//     never authorizes gitlab.company.com/acme/api; RepoFullName is only the
//     explicit bare alias.
//   - Environment/EnvironmentConcurrency reserve an environment slot inside
//     the transaction under a per-key advisory lock, so two concurrent
//     claims can never both take the last slot. The key is the CANONICAL
//     repository identity plus the environment name (see EnvKey), never the
//     clone URL: HTTPS and SSH submissions of one repository share the key.
//   - RepoConcurrency/TeamConcurrency gate the queued->running quota
//     transition: the quota_reservations row is updated conditionally and
//     zero matched rows rolls the whole lease back with ErrQuotaExceeded.
type LeaseClaim struct {
	JobID      string
	RunnerID   string
	TokenHash  []byte
	Generation int64
	ExpiresAt  time.Time

	RunnerCapacity int

	Runtime          string
	CanonRepoID      string
	RepoFullName     string
	RequiredLabels   []string
	PlacementRegions []string

	Environment            string
	EnvironmentConcurrency int
	RepoConcurrency        float64
	TeamConcurrency        float64
}

// EnvKey names the environment concurrency key: the CANONICAL repository
// identity plus the environment name. An environment name is not a global
// lock across repositories, and a clone URL is not an identity: the same
// repository submitted once via HTTPS and once via SSH resolves to one
// canonical RepoID and therefore one key. The key is logical only and
// contains no NUL byte; SQL advisory locks are derived from it with
// advisoryLockKey, so no scalar containing raw separators is ever bound as a
// SQL text parameter.
func (c LeaseClaim) EnvKey() string {
	if c.CanonRepoID == "" || c.Environment == "" {
		return ""
	}
	return c.CanonRepoID + "\x1f" + c.Environment
}

// AtomicLeaseStore acquires a job lease and reserves the runner capacity
// slot in the SAME transaction: the job UPDATE claims the lease (incrementing
// attempts once, stamping started_at only on the first lease, freezing the
// live usage rates), then the runner UPDATE appends the job to active_jobs
// guarded by the full claim predicate (disabled/draining, capacity, live
// profile repo ACL, runtime capability, labels, region), and the quota
// counters move one slot from queued to running conditionally. Any rejected
// predicate rolls the job lease back:
//
//   - ErrNoCapacity: the runner is at capacity, disabled, or draining.
//   - ErrEnvConcurrency: the environment slot was taken concurrently.
//   - ErrQuotaExceeded: the repo/team concurrency limit would be exceeded.
//
// Implemented by the SQL store and by the in-memory store (used by
// fault-injection and server tests) with identical predicate ordering.
type AtomicLeaseStore interface {
	AcquireLeaseAtomic(ctx context.Context, claim LeaseClaim) (model.Job, error)
}

// QuotaCounterStore adjusts the reserved running/queued counters for a
// repository/team key pair (deltas may be negative; counters clamp at 0)
// and reads the current reservation state. Completion, cancellation and
// lease-recovery paths keep the counters in sync with job state.
type QuotaCounterStore interface {
	AdjustQuotaCounter(ctx context.Context, repoKey, teamKey string, runningDelta, queuedDelta int) error
	QuotaCounts(ctx context.Context, repoKey, teamKey string) (running, queued int, err error)
}

// QuotaKeys derives the reservation counter keys for one canonical
// repository identity ("<host>/<owner>/<name>"; a legacy repo URL still
// derives the same pair): the repository key is the identity itself and the
// team key is the forge host plus the first path segment (the owner), so
// teams never collide across forges and gitlab.company.com/acme/backend and
// github.com/acme/backend never share a counter. The result is deduplicated
// when both keys coincide and empty for an empty identity. Every counter
// mutation (enqueue reservation, lease transition, completion, cancellation,
// queue-timeout expiry) must use this SAME derivation — feeding it the
// canonical RepoID — or the counters drift.
func QuotaKeys(repoID string) []string {
	repo := strings.TrimSpace(repoID)
	if repo == "" {
		return nil
	}
	team := repoTeamKey(repo)
	if team == repo {
		return []string{repo}
	}
	return []string{repo, team}
}

// repoTeamKey derives the team counter key of a canonical repository
// identity: the forge host plus the owner segment. Legacy URL inputs derive
// the same pair (host + first path segment) so pre-canonical counters stay
// addressable.
func repoTeamKey(repo string) string {
	if u, err := url.Parse(repo); err == nil && u.Host != "" {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) > 0 && parts[0] != "" {
			return u.Host + "/" + parts[0]
		}
		return u.Host
	}
	// Canonical "host/owner/name": the first two slash-separated segments.
	// A bare "owner/name" (no forge host) has no distinct team key; a first
	// segment containing a dot with a nested remainder also qualifies as a
	// canonical host.
	parts := strings.Split(repo, "/")
	if len(parts) >= 3 && parts[0] != "" && parts[1] != "" {
		return parts[0] + "/" + parts[1]
	}
	if len(parts) == 2 && strings.Contains(parts[0], ".") {
		return parts[0] + "/" + parts[1]
	}
	return repo
}

// RepoTeamKey returns the team counter key for a canonical repository
// identity ("" when the identity does not derive a distinct team key). It is
// the second element of QuotaKeys, for callers that adjust a single
// repository/team pair.
func RepoTeamKey(repoID string) string {
	keys := QuotaKeys(repoID)
	if len(keys) > 1 {
		return keys[1]
	}
	return ""
}

// CacheManifestRecord is one signed shared-cache manifest row: the
// (repo, trust_domain, logical_key) namespace maps to a content-addressed
// blob digest with its producer provenance. Envelope holds the signed DSSE
// envelope bytes so replicas serve a byte-identical manifest.
type CacheManifestRecord struct {
	Repo        string    `json:"repo"`
	TrustDomain string    `json:"trust_domain"`
	LogicalKey  string    `json:"logical_key"`
	BlobSHA256  string    `json:"blob_sha256"`
	BlobSize    int64     `json:"blob_size"`
	ProducerRun string    `json:"producer_run,omitempty"`
	ProducerJob string    `json:"producer_job,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Envelope    []byte    `json:"envelope,omitempty"`
}

// CacheManifestStore persists signed shared-cache manifests so every HA
// replica resolves the same (namespace -> blob digest) mapping without
// node-local files.
type CacheManifestStore interface {
	PutCacheManifest(ctx context.Context, rec CacheManifestRecord) error
	GetCacheManifest(ctx context.Context, repo, trustDomain, logicalKey string) (CacheManifestRecord, bool, error)
}

// ArtifactSidecarStore is the durable artifact-sidecar contract:
// SetArtifactSidecars updates one artifact record's sidecar references
// (SBOM/sigstore digests) after the record was created (only non-empty
// values are written), and the pending-sidecar methods persist the
// upload window between a sidecar upload and its artifact payload
// (migration 0012: artifact_pending_sidecars), keyed by
// (job_id, artifact_name, kind):
//
//   - RememberPendingSidecar upserts the digest (a re-upload of the same
//     kind replaces the digest).
//   - PendingSidecar resolves it (ok=false when no row exists).
//   - ConsumePendingSidecar deletes the row ONLY when the stored digest
//     still equals the digested record's reference, so a newer re-upload
//     is never dropped by a stale consumer.
//   - DeletePendingSidecars clears the job's leftover rows once an
//     artifact record commits.
//   - PrunePendingSidecars drops rows older than the cutoff (the
//     maintenance tick prunes rows past the 7-day retention window).
//
// The digests are content-addressed: no method ever deletes a CAS blob,
// which may be referenced by other records.
type ArtifactSidecarStore interface {
	SetArtifactSidecars(ctx context.Context, id, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256 string) error
	RememberPendingSidecar(ctx context.Context, jobID, artifactName, kind, digest string) error
	PendingSidecar(ctx context.Context, jobID, artifactName, kind string) (digest string, ok bool, err error)
	ConsumePendingSidecar(ctx context.Context, jobID, artifactName, kind, digest string) error
	DeletePendingSidecars(ctx context.Context, jobID string) error
	PrunePendingSidecars(ctx context.Context, olderThan time.Time) (int, error)
}

// ArtifactSidecarKindSBOM and ArtifactSidecarKindSigstore are the canonical
// pending-sidecar kinds.
const (
	ArtifactSidecarKindSBOM     = "sbom"
	ArtifactSidecarKindSigstore = "sigstore"
)

// validatePendingSidecarKey checks the artifact_pending_sidecars primary-key
// components. The artifact name is the cleaned name the server addresses
// records by; the kind is one of the canonical kinds.
func validatePendingSidecarKey(jobID, artifactName, kind string) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	if strings.TrimSpace(artifactName) == "" {
		return fmt.Errorf("storage: empty pending sidecar artifact name")
	}
	switch kind {
	case ArtifactSidecarKindSBOM, ArtifactSidecarKindSigstore:
		return nil
	default:
		return fmt.Errorf("storage: invalid pending sidecar kind %q", kind)
	}
}

// validatePendingSidecarDigest checks the content-addressed digest stored
// for a pending sidecar: the canonical 64 lowercase hex sha256.
func validatePendingSidecarDigest(digest string) error {
	if len(digest) != 64 {
		return fmt.Errorf("storage: invalid pending sidecar digest length %d", len(digest))
	}
	for i := 0; i < len(digest); i++ {
		c := digest[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return fmt.Errorf("storage: invalid pending sidecar digest character %q at position %d", c, i)
	}
	return nil
}

// SecretClaimStore is the durable once-only secret delivery claim contract
// (SQL mode). ClaimSecretDelivery reserves the (job, lease generation,
// secret name) triple with INSERT ... ON CONFLICT DO NOTHING and reports
// whether this call made the claim; only a true result authorizes the
// caller to deliver the sealed value. A replayed or concurrent delivery of
// the same triple reports false. Errors are returned for persistence
// failures and must fail closed (no envelope is ever delivered without a
// durable claim).
type SecretClaimStore interface {
	ClaimSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) (bool, error)
}

// SecretClaimReleaser optionally releases a claimed secret delivery whose
// resolution subsequently failed, so a failed resolution never consumes the
// once-only claim.
type SecretClaimReleaser interface {
	ReleaseSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) error
}

// ProfileStore is the durable server-owned runner-profile contract
// (migration 0006). Profiles are the only source of a runner's scheduling
// attributes: registration applies the profile linked to the runner's
// certificate serial and ignores runner-supplied labels/region/capacity/
// cost/capabilities/repositories. GetProfile/ListProfiles return
// ErrNotFound for an unknown profile ID.
type ProfileStore interface {
	UpsertProfile(ctx context.Context, p model.RunnerProfile) error
	GetProfile(ctx context.Context, id string) (model.RunnerProfile, error)
	ListProfiles(ctx context.Context) ([]model.RunnerProfile, error)
	// BindCertProfile links a certificate serial to a profile. A serial
	// can only bind one profile; re-binding replaces the link.
	BindCertProfile(ctx context.Context, serial, profileID string) error
	// ProfileForSerial resolves the profile bound to a certificate serial
	// (false when nothing is linked).
	ProfileForSerial(ctx context.Context, serial string) (model.RunnerProfile, bool, error)
}

// RunnerTokenStore is the durable per-runner bearer credential contract
// (migration 0006: runner_bearer_tokens). Only the SHA-256 digest of a
// token is ever stored. RunnerIDForToken resolves a presented token digest
// to its bound runner ID (false when unknown); HasRunnerTokens reports
// whether any per-runner token exists (the server rejects the shared
// dev-only runner token on runner-tier routes once per-runner credentials
// are provisioned).
type RunnerTokenStore interface {
	UpsertRunnerToken(ctx context.Context, runnerID, tokenDigest string) error
	RunnerIDForToken(ctx context.Context, tokenDigest string) (string, bool, error)
	HasRunnerTokens(ctx context.Context) (bool, error)
}

// CertRevocationStore is the durable certificate revocation contract
// (migration 0006: cert_revocations). RevokeCert records the revocation
// transactionally so every replica rejects the serial; CertRevoked is the
// replica-side check behind the server's short-TTL cache.
type CertRevocationStore interface {
	RevokeCert(ctx context.Context, serial, runnerID, reason string) error
	CertRevoked(ctx context.Context, serial string) (bool, error)
}

// EnrollGrantRecord is the durable state of one single-use enrollment
// grant. Raw grant values are never stored (the digest is the key).
type EnrollGrantRecord struct {
	ExpiresAt   time.Time
	BoundLabels []string
	Consumed    bool
}

// EnrollGrantStore is the durable enrollment grant contract (migration
// 0006: enrollment_grants). PutEnrollGrant stores a fresh grant (digest is
// the SHA-256 of the raw grant); GetEnrollGrant reads its state;
// ConsumeEnrollGrant is the atomic single-use claim — the conditional
// UPDATE matches only rows with consumed_at IS NULL and expires_at in the
// future, so concurrent consumers yield exactly one winner. Unknown
// digests return ErrNotFound, consumed rows ErrGrantConsumed and expired
// rows ErrGrantExpired.
type EnrollGrantStore interface {
	PutEnrollGrant(ctx context.Context, digest string, expiresAt time.Time, boundLabels []string) error
	GetEnrollGrant(ctx context.Context, digest string) (EnrollGrantRecord, bool, error)
	ConsumeEnrollGrant(ctx context.Context, digest string, consumedBy string) (EnrollGrantRecord, error)
}

// TestHistoryStore is the SQL-backed test-intelligence history cache
// (migration 0008: test_history). The single-row cache stores the
// serialized per-test history aggregates (the same JSON shape the
// filesystem history file uses) with a monotonically increasing version:
// SaveTestHistory bumps the version atomically with the write, and
// LoadTestHistory returns the current version so replicas reload the cache
// when it advances and converge on identical sharding decisions. The
// canonical history is always re-derivable from the durable test_results
// reports; the cache is a read accelerator, never the source of truth.
type TestHistoryStore interface {
	LoadTestHistory(ctx context.Context) (version int64, stats []byte, err error)
	SaveTestHistory(ctx context.Context, stats []byte) (version int64, err error)
}

// TestHistoryEntry is one test outcome of an uploaded report, as folded into
// the per-repository aggregates.
type TestHistoryEntry struct {
	Suite    string
	Class    string
	Name     string
	Duration float64
	Passed   bool
	When     time.Time
}

// TestHistoryAggregate is one per-(repo, suite, class, name) aggregate row of
// the incremental test-history store (migration 0026). Its fields mirror
// internal/testintel.TestStat exactly; FoldTestHistoryAggregate is the single
// implementation of the fold and MUST stay equivalent to
// testintel.History.Record (pinned by the equivalence tests).
type TestHistoryAggregate struct {
	RepoID      string
	Suite       string
	Class       string
	Name        string
	Runs        int64
	Passes      int64
	Fails       int64
	EWMA        float64
	LastFailure *time.Time
	Outcomes    []bool
	FlakeProb   float64
}

// FoldTestHistoryAggregate folds one outcome into an aggregate row. It is the
// storage-side mirror of testintel.History.Record: the run/pass/fail
// counters, the duration EWMA (alpha 0.3, seeded by the first observation),
// the bounded 16-outcome window, the last failure time and the derived flake
// probability (minority share, clamped to 0 for a single-outcome window).
// Every constant and branch here is part of the persisted aggregation
// contract; equivalence with testintel is asserted by
// TestTestHistoryFoldMatchesTestintel.
func FoldTestHistoryAggregate(row TestHistoryAggregate, e TestHistoryEntry) TestHistoryAggregate {
	row.Runs++
	if e.Passed {
		row.Passes++
	} else {
		row.Fails++
		when := e.When.UTC()
		row.LastFailure = &when
	}
	if row.Runs == 1 {
		row.EWMA = e.Duration
	} else {
		row.EWMA = testHistoryEWMAAlpha*e.Duration + (1-testHistoryEWMAAlpha)*row.EWMA
	}
	row.Outcomes = append(row.Outcomes, e.Passed)
	if len(row.Outcomes) > testHistoryOutcomeWindow {
		row.Outcomes = row.Outcomes[len(row.Outcomes)-testHistoryOutcomeWindow:]
	}
	row.FlakeProb = testHistoryFlakeProbability(row.Outcomes)
	return row
}

// testHistoryEWMAAlpha / testHistoryOutcomeWindow mirror
// internal/testintel's unexported ewmaAlpha / outcomeWindow.
const (
	testHistoryEWMAAlpha     = 0.3
	testHistoryOutcomeWindow = 16
)

// testHistoryFlakeProbability mirrors internal/testintel.flakeProbability.
func testHistoryFlakeProbability(outcomes []bool) float64 {
	if len(outcomes) < 2 {
		return 0
	}
	var pass, fail int
	for _, ok := range outcomes {
		if ok {
			pass++
		} else {
			fail++
		}
	}
	minority := pass
	if fail < pass {
		minority = fail
	}
	return float64(minority) / float64(len(outcomes))
}

// TestHistoryAggregateStore is the incremental, repository-scoped
// test-history contract (migration 0026) that replaces the O(total history)
// per-upload rebuild:
//
//   - InsertTestReportWithHistory writes the durable report AND folds its
//     cases into the per-(repo, suite, class, name) aggregates AND bumps the
//     repository's version in ONE transaction, so per-upload work is
//     proportional to the report, never to the accumulated history, and a
//     canceled context commits nothing.
//   - LoadRepoTestHistory returns only the requested canonical repository's
//     aggregates (in the legacy stats JSON shape) with its version.
//   - ResolveTestHistoryRepoIDs resolves the query forms the API accepts
//     (human full name, canonical RepoID, legacy host-less canonical form) to
//     the canonical repository IDs they address, through a bounded,
//     set-based run-identity query — never by materializing reports.
//   - TestReportTotals and FlakyTestNames answer test-intelligence from the
//     requested repository's rows only.
//   - RebuildRepoTestHistory is the EXPLICIT bounded repair operation: it
//     recomputes one repository's aggregates from its durable reports. It is
//     never called per upload; the server invokes it once per repository as
//     lazy repair when aggregates predate the migration, and operators can
//     invoke it directly.
type TestHistoryAggregateStore interface {
	InsertTestReportWithHistory(ctx context.Context, rep model.TestReport, repoID string) (version int64, err error)
	LoadRepoTestHistory(ctx context.Context, repoID string) (version int64, stats []byte, err error)
	ResolveTestHistoryRepoIDs(ctx context.Context, query string, limit int) ([]string, error)
	TestReportTotals(ctx context.Context, repoIDs []string, repoQuery string) (reports, tests, failures int, err error)
	FlakyTestNames(ctx context.Context, repoIDs []string, limit int) ([]string, error)
	RebuildRepoTestHistory(ctx context.Context, repoID string) (version int64, err error)
	ListTestHistoryRepoIDs(ctx context.Context, limit int) ([]string, error)
}

// ValidateID checks the canonical control-plane identifier format produced
// by the server's crypto/rand ID generator: 32 lowercase hex characters.
// Runs, jobs, runners, artifacts, reports, and audit events all share it.
func ValidateID(id string) error {
	if len(id) != 32 {
		return fmt.Errorf("storage: invalid id length %d", len(id))
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return fmt.Errorf("storage: invalid id character %q at position %d", c, i)
	}
	return nil
}

// ValidateRunID validates a run identifier before it reaches SQL.
func ValidateRunID(id string) error { return ValidateID(id) }

// ValidateJobID validates a job identifier before it reaches SQL.
func ValidateJobID(id string) error { return ValidateID(id) }

// ValidateRunnerID validates a runner identifier before it reaches SQL.
func ValidateRunnerID(id string) error { return ValidateID(id) }
