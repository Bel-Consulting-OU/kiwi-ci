// Package storage holds the durable control-plane state contracts. The
// filesystem Repository in fs.go remains the zero-dependency dev/local store;
// PostgresStore in postgres.go implements Store for HA deployments. The
// server keeps using its in-memory maps and the fs Repository until the
// scheduler phase wires the SQL store in.
package storage

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
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
	// ErrApprovalNotRequired means ApproveJob addressed a job whose
	// ApprovalRequired flag is false: there is nothing to approve. The
	// handler maps it to 409.
	ErrApprovalNotRequired = errors.New("storage: job does not require approval")
	// ErrJobTerminal means ApproveJob addressed a job already in a terminal
	// state: approval can never move a terminal job. The handler maps it to
	// 409.
	ErrJobTerminal = errors.New("storage: job is already terminal")
	// ErrIdempotencyKeyReplay means a run-idempotency receipt already exists
	// for the same (repository, key) with the SAME request digest: the
	// enqueue transaction rolled back and the caller must return the
	// original run named by *IdempotentReplayError.
	ErrIdempotencyKeyReplay = errors.New("storage: idempotency key already recorded")
	// ErrIdempotencyKeyConflict means a run-idempotency receipt already
	// exists for the same (repository, key) with a DIFFERENT request digest:
	// the client reused one key for two different submissions. The handler
	// fails closed with 409 and never enqueues the second request.
	ErrIdempotencyKeyConflict = errors.New("storage: idempotency key reused with a different request")
)

// IdempotentReplayError is returned inside InsertCompiledRun when the
// request carries an idempotency claim whose (repository, key) already
// exists with the same digest. The transaction rolls back and the caller
// returns the run named by RunID: the durable receipt and the run row were
// committed together, so the original is authoritative.
type IdempotentReplayError struct {
	RunID string
}

func (e *IdempotentReplayError) Error() string {
	return "storage: idempotency key already recorded for run " + e.RunID
}

func (e *IdempotentReplayError) Unwrap() error { return ErrIdempotencyKeyReplay }

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
	// SchemaCompatibilityFloor returns the newest compatibility floor
	// recorded by applied migrations: the oldest binary schema allowed to
	// keep operating. In-memory stores have no migrations and return 0.
	SchemaCompatibilityFloor(ctx context.Context) (int, error)
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
	// HeartbeatLease extends a lease to an absolute expiry. DEPRECATED for
	// database-backed stores: the instant is a caller-supplied clock value
	// that can disagree with the database clock, so prefer
	// LeaseClockStore.HeartbeatLeaseWithTTL, which derives the extension from
	// the live database clock and is what the DB-mode scheduler uses.
	// PostgreSQL still bounds this legacy call (see legacyHeartbeatHorizonSQL)
	// as defense in depth, but TTL is the supported contract.
	HeartbeatLease(ctx context.Context, jobID string, runnerID string, generation int64, expiresAt time.Time) error
	// CompleteJob is the one transaction for a runner completion: lock the
	// job FOR UPDATE, verify generation+runner+status running, insert the
	// completion receipt ON CONFLICT DO NOTHING (idempotent replay), update
	// the job, update runner counters, recompute dependent jobs and the run
	// status, and insert the audit event. observed, when non-nil, is the
	// executor-captured runtime identity of the attempt and is persisted on
	// the job payload in the SAME transaction (additive evidence, never used
	// for authorization).
	CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt, observed *model.ObservedRuntime) error
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
	// FindDelivery returns the receipt for (forge, deliveryID): runID (empty
	// for an IGNORED terminal receipt), the stored PAYLOAD DIGEST (so callers
	// can distinguish a replay of the same authenticated body from a reused
	// delivery ID with different content) and whether a receipt exists.
	FindDelivery(ctx context.Context, forge, deliveryID string) (runID string, payloadDigest string, found bool, err error)

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

// QueuedBoostPromoter is the optional materialized-scheduling-key capability:
// PromoteQueuedJobBoosts recomputes jobs.queue_boost — the aged-wait term of
// the queued scheduling key (floor(max(0, now-created_at)/10min)) — for the
// queued rows whose stored value is stale, in bounded batches, and returns how
// many rows it promoted. The recomputation is ABSOLUTE and idempotent (any
// replica may run it any number of times), so it is safe to call from the DB
// leader's maintenance loop; stores without stored boosts (memory/fs) simply
// omit it.
type QueuedBoostPromoter interface {
	PromoteQueuedJobBoosts(ctx context.Context, now time.Time, batchLimit int) (int64, error)
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

	// OutboxKindExecutionAttest is the FINAL EXECUTION ATTESTATION intent: it
	// builds, signs and durably records the terminal attempt's execution
	// attestation. It is INTERNAL (marker-guarded by the
	// execution_attestations primary key, unbounded retries, never
	// dead-lettered), so a transient signing/CAS/store failure retries until
	// the evidence converges.
	OutboxKindExecutionAttest = "execution_attest"

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
// effect intents. Generation is the lease generation (attempt identity) of
// the completion the effects belong to, so a durable effect row names the
// exact attempt even after the job row's lease fields are cleared. Additive:
// rows persisted before the field decode as 0.
type CompletionEffectsPayload struct {
	JobID      string `json:"job_id"`
	RunID      string `json:"run_id"`
	Generation int64  `json:"generation,omitempty"`
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
// (completion_reconcile + forge_delivery + execution_attest). Legacy rows
// persist the five per-kind intents listed by CompletionEffectKinds.
const CompletionEffectIntentCount = 3

// NewCompletionEffectKinds is the ordered set of intents a NEW completion
// persists: ONE completion_reconcile row (internal consistency, unbounded
// retries), ONE forge_delivery row (external publication, bounded retries +
// dead-letter) and ONE execution_attest row (the final signed execution
// attestation, internal/unbounded retries until its row and event commit). It
// is the single source of truth for the SQL completion transaction, the
// memStore mirror and the server's fs/memory enqueue path, and its size is
// pinned by CompletionEffectIntentCount.
func NewCompletionEffectKinds() []string {
	return []string{
		OutboxKindCompletionReconcile,
		OutboxKindForgeDelivery,
		OutboxKindExecutionAttest,
	}
}

// IsCompletionEffectKind reports whether kind is a completion effect intent:
// the split reconcile/forge_delivery/execution_attest rows or a legacy
// per-kind row.
func IsCompletionEffectKind(kind string) bool {
	if kind == OutboxKindCompletionReconcile || kind == OutboxKindForgeDelivery || kind == OutboxKindExecutionAttest {
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
	// InsertDeploymentOnce inserts the deployment unless a row with the same
	// deterministic ID already exists, in which case it returns the STORED
	// canonical record with created=false. A duplicate key is therefore an
	// idempotent replay, not an error: the server caches the returned record
	// and audits deployment.started only when created is true, so two HA
	// replicas (or a retry after a restart with an empty local mirror)
	// converge on exactly one durable record and one audit event. The
	// existing row must agree on run/job/environment; a disagreement returns
	// an error wrapping ErrDeploymentIdentityConflict and writes nothing.
	//
	// This is the RAW non-audited primitive (seeding/tests). Lifecycle
	// writers must use StartDeployment, which commits the record and its
	// audit event in ONE transaction.
	InsertDeploymentOnce(ctx context.Context, d model.Deployment) (model.Deployment, bool, error)
	// StartDeployment is the transactional deployment-start authority: it
	// inserts the deployment with the same idempotent conflict semantics and,
	// ONLY when it creates the row, appends auditEvent in the SAME
	// transaction. A created deployment can therefore never exist without its
	// deployment.started audit (an audit failure rolls the insert back), a
	// replay returns the canonical stored record and appends nothing, and two
	// concurrent replicas converge on one row and one audit event. An empty
	// auditEvent.ID skips the audit append (repair paths that reconstruct a
	// record from job state).
	StartDeployment(ctx context.Context, d model.Deployment, audit model.AuditEvent) (model.Deployment, bool, error)
	// FinishDeploymentOnce locks the deployment row and, when it is not yet
	// finished, writes status/finishedAt and appends auditEvent in the SAME
	// transaction, returning changed=true. An already-finished row returns
	// changed=false and appends nothing (exactly-once completion audit across
	// replicas/restarts). A failure rolls both the marker and the audit back,
	// so the finish stays retryable.
	FinishDeploymentOnce(ctx context.Context, id string, status model.Status, finishedAt time.Time, audit model.AuditEvent) (bool, error)
	ListDeploymentsByRun(ctx context.Context, runID string) ([]model.Deployment, error)
	// UpdateDeploymentStatus is the RAW status primitive (seeding/tests and
	// non-lifecycle bookkeeping). Lifecycle completion must use
	// FinishDeploymentOnce so the state marker and its audit commit together.
	UpdateDeploymentStatus(ctx context.Context, id string, status model.Status, finishedAt *time.Time) error
}

// ErrDeploymentIdentityConflict reports that a deterministic deployment ID
// already names a different run/job/environment. The existing row is
// returned to no one and nothing is overwritten: the caller fails closed
// instead of silently adopting an unrelated deployment record.
var ErrDeploymentIdentityConflict = errors.New("storage: deployment id already names a different run, job or environment")

// SnapshotStore is the durable workspace snapshot record contract.
type SnapshotStore interface {
	InsertSnapshotRecord(ctx context.Context, rec model.SnapshotRecord) error
	// GetSnapshot resolves one record of runID by its id through a
	// (run_id, id) lookup. The bool reports whether the record exists; a
	// record of another run is reported as missing, so the download route
	// can never serve a cross-run snapshot. Implementations must not list
	// and scan the run's records: that read is O(records per run) for a
	// request that needs exactly one (see postgres_snapshot_get.go).
	GetSnapshot(ctx context.Context, runID, snapshotID string) (model.SnapshotRecord, bool, error)
	ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error)
}

// LogCursorStore reports a run's monotonic log high-water (migration 0052's
// log_cursors row in PostgreSQL; the maximum Seq among the run's durable
// journal and committed batch records in fs mode, where no per-run cursor
// exists). It is the value a stream/bootstrap consumer uses as "latest
// committed log seq": it never goes backwards, even when retention removes
// rows or a rollback frees an allocated range. Stores without the capability
// are simply skipped by consumers that report it as advisory metadata.
type LogCursorStore interface {
	LatestLogSeq(ctx context.Context, runID string) (int64, error)
}

// RunKeyIndexStore reports whether the run-scoped logical job key uniqueness
// index (migration 0048/0053 jobs_run_key_idx) is present. A false result
// means the database was dirty when 0048 ran and the operator has not yet
// repaired the duplicate (run_id, key) rows and re-migrated; readiness
// surfaces it as not-ready until then. In-memory/fs stores have no index and
// do not implement this contract.
type RunKeyIndexStore interface {
	RunKeyIndexPresent(ctx context.Context) (bool, error)
}

// Artifact provenance policy values. BestEffort (the default) keeps the
// historical post-commit provenance sidecar flow; Required makes a durable
// signed provenance envelope a PRECONDITION of the upload commit and of
// completion (a required artifact without ProvenanceSHA256 cannot satisfy a
// successful completion).
const (
	ArtifactProvenanceBestEffort = "best_effort"
	ArtifactProvenanceRequired   = "required"
)

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
	// Provenance is the artifact's provenance policy: "required" or
	// "best_effort" (empty means best_effort, the historical behavior).
	// Required uploads build+sign+store the envelope BEFORE the lease-fenced
	// record insert and fail closed when signing/storage fails, so a
	// committed record with an empty ProvenanceSHA256 can never satisfy the
	// contract's completion gate.
	Provenance string `json:"provenance,omitempty"`
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

// GeneratedJobVerifier is the transactional graph-only recheck closure for
// dynamic fragment insertion. The store owns the complete lease predicate:
// inside the transaction it locks the parent row, samples the STORAGE clock
// AFTER the lock, and rejects the fragment unless the locked parent is still
// running under the exact runner, lease generation and token hash of the
// request with a lease that is live at that storage clock (the same
// clock-domain rule secret/OIDC issuance use). Only then does it call the
// verifier with that locked state, the run's job count and the storage clock
// for graph-specific checks (the max-jobs-per-run bound, identity
// invariants). A returned error rolls the whole fragment back.
type GeneratedJobVerifier func(parent model.Job, runJobCount int, commitNow time.Time) error

// GeneratedFragmentChild is one created child of a generated fragment: the
// compiled fragment key (matrix/shard suffixes included) and the assigned
// job ID, in the order the admitting server reported them.
type GeneratedFragmentChild struct {
	Key string `json:"key"`
	ID  string `json:"id"`
}

// GeneratedFragmentMutationSlotDefault is the logical mutation slot of
// today's generated-fragment endpoint: exactly one generated output per
// parent job. The slot is the store-side constant, never client-supplied
// yet (a future generation may carry an explicit mutation key generalized to
// (parent, mutation_key, digest); see GeneratedFragmentRequest.MutationSlot).
const GeneratedFragmentMutationSlotDefault = "generated"

// GeneratedFragmentSlot returns the effective mutation slot of a fragment
// request or receipt: the explicit slot when set, the single-output default
// otherwise. An empty slot occurs only for direct storage callers and for
// receipts persisted before the slot existed (migration 0047), never on the
// server endpoint path.
func GeneratedFragmentSlot(slot string) string {
	if slot == "" {
		return GeneratedFragmentMutationSlotDefault
	}
	return slot
}

// ErrGeneratedMutationConflict marks a fragment upload whose mutation slot is
// already committed with a DIFFERENT fragment digest: the retry is a
// nondeterministic re-emission, and appending its graph would duplicate the
// logical generator output. Callers compare with errors.Is and read the two
// fragment ids from *GeneratedMutationConflictError.
var ErrGeneratedMutationConflict = errors.New("storage: generated fragment mutation conflict")

// ErrGeneratedJobKeyConflict marks a generated fragment whose child logical
// Job.Key already identifies a job in the same run. Key is the run-scoped
// logical node identity (matrix/shard suffix included, so matrix variants
// stay distinct), so inserting a second row for the same (run, key) would
// make key lookups ambiguous and duplicate the logical node. Callers compare
// with errors.Is and read the colliding key from *GeneratedJobKeyConflictError.
var ErrGeneratedJobKeyConflict = errors.New("storage: generated job key conflict")

// GeneratedJobKeyConflictError carries the run-scoped logical key that
// collided and the id of the existing run job it collides with. The handler
// maps it to HTTP 409 (reason GENERATED_JOB_KEY_CONFLICT) and the whole
// fragment transaction is rolled back: no partial child graph is ever
// inserted. The existing job is described by its id only.
type GeneratedJobKeyConflictError struct {
	RunID         string
	Key           string
	ExistingJobID string
}

func (e *GeneratedJobKeyConflictError) Error() string {
	return fmt.Sprintf("storage: generated job key %q already exists in run %s as job %s; Key is the run-scoped logical job identity, so a generated child cannot duplicate an existing node",
		e.Key, e.RunID, e.ExistingJobID)
}

// Unwrap makes errors.Is(err, ErrGeneratedJobKeyConflict) true.
func (e *GeneratedJobKeyConflictError) Unwrap() error { return ErrGeneratedJobKeyConflict }

// GeneratedJobKeyIndex builds the run-scoped logical identity index of a
// job map keyed by job id: Key -> existing job id for runID. Iteration order
// is sorted by job id and the first row wins, so a database that already
// carries bug-created duplicates still yields a deterministic index. The
// memory stores and the server's fs-mode maps call it; the SQL stores build
// the same index from a run-scoped SELECT.
func GeneratedJobKeyIndex(runID string, jobs map[string]model.Job) map[string]string {
	ids := make([]string, 0, len(jobs))
	for id := range jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	index := make(map[string]string, len(ids))
	for _, id := range ids {
		j := jobs[id]
		if j.RunID != runID {
			continue
		}
		if _, ok := index[j.Key]; !ok {
			index[j.Key] = j.ID
		}
	}
	return index
}

// CheckGeneratedJobKeyConflicts enforces the run-scoped logical identity rule
// shared by every admission path: every requested child job's Key must be
// free among the existingByKey index of the run. requested maps child job id
// -> job (the fragment about to be inserted) and existingByKey maps Key ->
// existing job id (GeneratedJobKeyIndex or the equivalent SQL projection).
// The requested jobs are inspected in sorted Key order, so the returned
// *GeneratedJobKeyConflictError is deterministic when several keys collide.
// An ordinary compiled run enqueued through InsertCompiledRun needs no
// advisory lock for this rule (compilation makes Keys unique per run and the
// run's jobs are always inserted before any dynamic child can exist), but the
// check is applied there too as defense in depth.
func CheckGeneratedJobKeyConflicts(runID string, requested map[string]model.Job, existingByKey map[string]string) error {
	if len(requested) == 0 || len(existingByKey) == 0 {
		return nil
	}
	ids := make([]string, 0, len(requested))
	for id := range requested {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		ki, kj := requested[ids[i]].Key, requested[ids[j]].Key
		if ki != kj {
			return ki < kj
		}
		return ids[i] < ids[j]
	})
	for _, id := range ids {
		key := requested[id].Key
		if existingID, ok := existingByKey[key]; ok {
			return &GeneratedJobKeyConflictError{RunID: runID, Key: key, ExistingJobID: existingID}
		}
	}
	return nil
}

// GeneratedMutationConflictError carries the committed fragment digest and
// the submitted one for a refused mutation-slot conflict. The handler maps it
// to HTTP 409 (reason GENERATED_MUTATION_CONFLICT) instead of appending a
// second child graph. No child IDs are carried: the conflict response must
// not leak the committed receipt beyond the explicit replay path.
type GeneratedMutationConflictError struct {
	ParentJobID         string
	MutationSlot        string
	ExistingFragmentID  string
	SubmittedFragmentID string
}

func (e *GeneratedMutationConflictError) Error() string {
	return fmt.Sprintf("storage: generated fragment mutation conflict for parent %s slot %q: committed fragment %s differs from submitted fragment %s; a nondeterministic generator retry cannot append a second graph",
		e.ParentJobID, e.MutationSlot, e.ExistingFragmentID, e.SubmittedFragmentID)
}

// Unwrap makes errors.Is(err, ErrGeneratedMutationConflict) true.
func (e *GeneratedMutationConflictError) Unwrap() error { return ErrGeneratedMutationConflict }

// GeneratedFragmentReceipt is the durable idempotency receipt of one
// generated fragment upload: the canonical generation-free mutation identity
// (parent job, mutation slot) maps to the fragment digest that admitted it
// and to the children created for it, in canonical (sorted-key) order, so a
// replay reconstructs the original response exactly. The lease generation is
// NOT part of the mutation identity: it authorizes the upload (the presenting
// lease must still be current) but an infrastructure retry of the same
// logical parent under a new generation re-submits the identical fragment and
// must replay THESE children instead of inserting a duplicate graph.
// FragmentID is the digest that won the slot: a submission with a different
// digest for the same slot is refused (ErrGeneratedMutationConflict) rather
// than admitted as a second logical output. LeaseGeneration records the
// generation that authorized the original admission. MutationSlot carries
// the slot (empty in pre-0047 persisted receipts, read as the default).
type GeneratedFragmentReceipt struct {
	ParentJobID     string                   `json:"parent_job_id"`
	LeaseGeneration int64                    `json:"lease_generation"`
	MutationSlot    string                   `json:"mutation_slot,omitempty"`
	FragmentID      string                   `json:"fragment_id"`
	Children        []GeneratedFragmentChild `json:"children"`
	CreatedAt       time.Time                `json:"created_at"`
}

// GeneratedFragmentRequest is the full transactional fragment payload: the
// presented lease identity, the canonical mutation identity and the
// already-compiled child jobs, their dependency edges and artifact
// contracts. The RUNNER/TOKEN/GENERATION fields are the lease the runner
// presented; the store verifies them and the lease expiry against the locked
// parent row at the storage clock, BEFORE any receipt replay. The generation
// AUTHORIZES the mutation but never defines it: the receipt identity is
// (ParentJobID, MutationSlot), so a retry under a new generation of the same
// logical parent replays the original children when it submits the SAME
// fragment digest, and fails closed with ErrGeneratedMutationConflict when a
// nondeterministic generator emits a different digest for the same slot. The
// verification closure and the receipt are evaluated inside the same
// transaction as the insertion. Children lists the created child key/ID
// pairs in canonical (sorted fragment key) order, matching the response the
// admitting server reported.
//
// MutationSlot is the logical mutation identity. Today's endpoint has exactly
// one generated output per parent job, so the server always fills the
// constant GeneratedFragmentMutationSlotDefault; it is never client-supplied
// yet. The documented future generalization is (ParentJobID, MutationSlot,
// FragmentID) with a client-supplied mutation key, at which point a slot may
// legitimately hold several distinct graphs; until then a differing digest in
// one slot is a conflict. An empty MutationSlot is read as the default by
// every store. Each job's Key is the run-scoped logical node identity and is
// admitted against the run's existing jobs (CheckGeneratedJobKeyConflicts);
// BaseKey is display/grouping only and is never used for uniqueness.
type GeneratedFragmentRequest struct {
	ParentJobID     string
	RunnerID        string
	LeaseGeneration int64
	LeaseTokenHash  []byte
	Depth           int
	MutationSlot    string
	FragmentID      string
	Jobs            map[string]model.Job
	Deps            map[string][]string
	Contracts       map[string]map[string]ArtifactContract
	Children        []GeneratedFragmentChild
}

// ValidateGeneratedParentLease is the complete storage-side lease predicate
// for dynamic fragment insertion, shared by the PostgreSQL transaction and
// the memory store: the locked parent must still be running under the exact
// runner, lease generation and token hash of the request, with a lease that
// is live at the storage clock. commitNow MUST be sampled after the parent
// row lock (or inside the memory store's critical section), so the decision
// is made in the same clock domain that persists the expiry — never by the
// request handler's clock, which a skewed replica could use to launder an
// expired lease.
func ValidateGeneratedParentLease(parent model.Job, req GeneratedFragmentRequest, commitNow time.Time) error {
	if parent.Status != model.StatusRunning {
		return fmt.Errorf("storage: parent job is not running")
	}
	if parent.LeaseRunnerID != req.RunnerID {
		return fmt.Errorf("storage: parent lease runner changed")
	}
	if parent.LeaseGeneration != req.LeaseGeneration {
		return fmt.Errorf("storage: parent lease generation changed")
	}
	if len(parent.LeaseTokenHash) == 0 || len(req.LeaseTokenHash) == 0 ||
		subtle.ConstantTimeCompare(parent.LeaseTokenHash, req.LeaseTokenHash) != 1 {
		return fmt.Errorf("storage: parent lease token changed")
	}
	if parent.LeaseExpiresAt == nil || !parent.LeaseExpiresAt.After(commitNow) {
		return fmt.Errorf("storage: parent lease expired")
	}
	return nil
}

// GeneratedFragmentStore reads the idempotency receipt of a previously
// admitted fragment by its canonical mutation key (parent job, mutation
// slot) so a replayed upload returns the same children without re-inserting
// anything, regardless of which lease generation admitted it, and a
// different fragment digest under the same slot is diagnosed as
// ErrGeneratedMutationConflict by the caller. Callers must have authorized
// the CURRENT lease before consulting the receipt; the receipt read itself
// carries no lease authority.
type GeneratedFragmentStore interface {
	GetGeneratedFragment(ctx context.Context, parentJobID, mutationSlot string) (GeneratedFragmentReceipt, bool, error)
}

// DynamicStoreTx is the transactional dynamic-fragment contract. The
// verification closure and the idempotency receipt are evaluated inside the
// same transaction as the fragment insertion, AFTER the storage layer has
// validated the complete parent lease predicate of the CURRENT request, so a
// stale lease or an over-cap run rejects the fragment atomically and a
// replayed fragment (same canonical mutation key parent+mutation slot with
// the same fragment digest) returns the ORIGINAL receipt with replayed=true
// and inserts nothing, while a DIFFERENT digest in the same slot fails
// closed with ErrGeneratedMutationConflict before any row is written. Before
// any child row is inserted, the requested child keys are admitted under the
// run-scoped logical identity rule (CheckGeneratedJobKeyConflicts): a Key
// that already identifies a job of the run fails closed with
// ErrGeneratedJobKeyConflict, also before any row is written. The
// fragment's artifact contracts commit in the SAME transaction as the jobs —
// a generated job with a required artifact has its contract row visible
// before any completion can run.
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
// (UpsertRunner(disabled), RevokeRunnerLeases, the certificate revocation,
// audit) and answered success even when the durable certificate revocation
// was never recorded: a disabled runner's still-valid certificate could then
// be replayed on another replica. DisableRunnerAndRevokeCert performs the
// whole disable in ONE transaction and the handler fails closed (no success
// response) when it cannot commit it.
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

// RunnerRegistrationStore is the ATOMIC re-registration swap: the new
// incarnation's runner row and the revocation of every lease the PREVIOUS
// incarnation held commit together. It exists because a plain profile write
// left the predecessor's leases live (capacity held) and let the superseded
// process keep reaching the lease-token-authenticated durable-write
// endpoints for the remaining TTL. Stores without this capability remain
// supported through the guarded profile write plus a separate best-effort
// RevokeRunnerLeases.
type RunnerRegistrationStore interface {
	// RegisterRunnerAndRevokeLeases writes the runner's new registration
	// (profile/admin fields merged under the runner row lock, lease-owned
	// fields preserved) and invalidates every running lease it holds
	// (requeue while the infrastructure-retry budget allows it, otherwise
	// terminal-cancel with reason; release resource reservations/capacity
	// slots and clear the lease columns; recompute dependents and affected
	// runs; write one audit event per revoked job) in the SAME transaction.
	// It returns the IDs of the revoked jobs.
	RegisterRunnerAndRevokeLeases(ctx context.Context, runner model.Runner, reason string) ([]string, error)
}

// RunnerProfileUpdateStore is the guarded runner-profile write contract.
//
// A runner row mixes two owners:
//
//   - PROFILE/ADMIN fields (name, labels, region, repository allowlist,
//     capabilities, capacity, resource capacity, costs, certificate serial,
//     profile marker, registered/last_seen, disabled/draining) are written by
//     registration and admin actions;
//   - LEASE-OWNED fields (active_jobs, busy, current_job) and the counters
//     (completed, failed) are written ONLY by the lease/transition
//     transactions (AcquireLeaseAtomic, CompleteJob, ReleaseRunnerJob,
//     recovery), under the runner row lock.
//
// A whole-row UpsertRunner from a caller's stale model used to overwrite the
// lease-owned fields: a re-registration (or drain/enable) that raced a
// concurrent claim could drop the just-appended slot and then admit a second
// job beyond capacity. Both implementations now merge the profile/admin
// fields under the runner row lock and preserve the lease-owned fields, so a
// stale caller can never shrink or clear the active set; a fresh runner row
// is the only path that seeds those fields.
// ClockStore is the durable clock capability: the store's own notion of now.
// Database-backed callers use it for policy decisions whose deadline must be
// shared across replicas (schedule due evaluation and similar), so a skewed
// serving replica cannot fire early or postpone a due occurrence. It is a
// read, never a lease: single-use/TTL operations must still derive their
// timestamps inside their own transaction.
type ClockStore interface {
	Now(ctx context.Context) (time.Time, error)
}

// RunnerProfileUpdateStore updates only the profile/admin fields of an
// EXISTING runner, preserving active_jobs/busy/current_job/completed/failed
// from the locked row. A missing runner returns ErrNotFound: a profile edit
// never creates a runner (use UpsertRunner to register).
type RunnerProfileUpdateStore interface {
	UpdateRunnerProfileFields(ctx context.Context, runner model.Runner) error
}

// RunnerHeartbeatStore is the NARROW runner liveness refresh a heartbeat is
// allowed to perform: update the advisory last-seen instant and nothing else.
//
// Heartbeat used to compose GetRunner -> LastSeen=now -> UpsertRunner, which
// is a read-modify-write of the whole runner row: a heartbeat that read the
// runner before a concurrent admin disable/drain/profile edit would write the
// stale snapshot back after the admin transaction committed, silently undoing
// the disable (and the same for draining, capacity, labels, capabilities,
// repository ACLs, resource capacity and profile state). The generic
// UpsertRunner contract deliberately treats the caller as authoritative for
// profile/admin fields, so it must never be the heartbeat's write path.
// Implementations touch ONLY last_seen (PostgreSQL: clock_timestamp()) and
// report ErrNotFound for a missing runner; the scheduler skips the refresh
// entirely for stores without this capability rather than falling back to the
// read-modify-write.
type RunnerHeartbeatStore interface {
	TouchRunnerLastSeen(ctx context.Context, runnerID string) error
}

// JobApprovalStore is the transactional approval contract for
// environment-gated jobs. approveJobDB previously did GetJob then a whole-row
// UpdateJob: a caller that read a waiting_approval job and then wrote after a
// concurrent approve+claim could reset status/lease from its stale model,
// leaving the runner slot, quota reservation and resource reservation held
// while the job looked re-queued. ApproveJob locks the job row FOR UPDATE and
// writes ONLY the approval-owned payload fields (and the waiting_approval ->
// queued status transition); it never touches a lease column.
type JobApprovalStore interface {
	// ApproveJob records actor as the approver of jobID and, while the job is
	// waiting_approval, moves it to queued. A job that does not require
	// approval returns ErrApprovalNotRequired; a terminal job returns
	// ErrJobTerminal. A job already approved (queued or running) keeps its
	// status and lease: only the approver is (re)recorded. The updated job is
	// returned.
	ApproveJob(ctx context.Context, jobID, actor string) (model.Job, error)
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
	Run            model.Run
	Jobs           map[string]model.Job
	Deps           map[string][]string
	Contracts      map[string]map[string]ArtifactContract
	CancelPrevious []string
	Supersede      *SupersedePolicy
	WebhookClaim   *WebhookClaim
	// BodyClaim is the strict body-replay receipt: the authenticated webhook
	// body digest under a synthetic forge key, claimed in the SAME
	// transaction as the run so two concurrent deliveries of the same
	// authenticated body (even with different delivery headers) converge on
	// one run. A conflict rolls the enqueue back with ErrDeliveryDuplicate.
	BodyClaim        *WebhookClaim
	Quota            *QuotaReservation
	ScheduleClaim    *ScheduleClaim
	DownstreamLaunch *DownstreamLaunchClaim
	// Idempotency, when set, records the durable (repository, key) receipt
	// in the SAME transaction as the run: a commit whose response was lost
	// is replayed to the original run instead of a duplicate. A conflicting
	// digest rolls the enqueue back with ErrIdempotencyKeyConflict, and an
	// equal-digest replay rolls back with *IdempotentReplayError carrying
	// the original run ID.
	Idempotency *RunIdempotencyClaim
}

// RunIdempotencyClaim is the durable client-operation identity of one run
// submission. RepoID scopes the key to the canonical CHECKOUT repository
// (storage.RepoIDForRun), Digest is the canonical request digest the key is
// bound to, and RunID is the run this submission will create.
type RunIdempotencyClaim struct {
	RepoID string
	Key    string
	Digest string
	RunID  string
	// CreatedAt is the receipt timestamp. The SQL store stamps its own
	// created_at DEFAULT now(); memory stores persist this value so pruning
	// has a stable age. A zero value is treated as oldest by prune.
	CreatedAt time.Time
}

// RunIdempotencyStore is the durable idempotency contract: the receipt is
// written atomically with the run by InsertCompiledRun (see
// InsertCompiledRunRequest.Idempotency), and FindRunIdempotency re-reads it
// for the pre-compile replay fast path and for concurrent races that lose
// the in-transaction claim. A missing row is (found=false, nil error), never
// ErrNotFound, because "no receipt yet" is the normal first-submission
// state.
type RunIdempotencyStore interface {
	FindRunIdempotency(ctx context.Context, repoID, key string) (runID, digest string, found bool, err error)
	// PruneRunIdempotency deletes up to limit receipts created before
	// olderThan, oldest first, and reports how many rows were removed. A
	// receipt is small but unbounded in count, so leader maintenance ages
	// them out independently of run retention.
	PruneRunIdempotency(ctx context.Context, olderThan time.Time, limit int) (int64, error)
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
//   - CPURequest/MemoryRequest/DiskRequest/PIDsRequest are the candidate
//     job's requested resources (model.Job.ResourceRequest) and
//     ServiceEnvelopeRequest its aggregate service request
//     (model.Job.ServiceEnvelopeRequest). The claim reserves their SUM
//     against the runner's remaining resource capacity in the same
//     transaction (see postgres_resource_reservation.go); a rejected
//     admission rolls the lease back with ErrResourceCapacity. A job
//     without services (or a legacy payload, which decodes with an empty
//     envelope) leaves the envelope zero, so the claim's reservation is
//     byte-identical to the pre-envelope behavior. The promoted-leader
//     reconcile charges a legacy services-without-envelope payload
//     conservatively (its own request as the envelope) instead of zero, so a
//     rolling upgrade cannot under-reserve it (see
//     ReconcileResourceReservations).
//
// The runner's capacity is NOT carried on the claim: every claim path reads
// the runner's live capacity itself (the SQL claim from the locked runner row
// plus its resolved profile's max_* columns, the mem claim from its stored
// runner), so a capacity resolved by the caller could only go stale.
type LeaseClaim struct {
	JobID      string
	RunnerID   string
	TokenHash  []byte
	Generation int64
	// ExpiresAt is the caller-computed absolute expiry. It remains for
	// stores without a live database clock (the in-memory store) and for
	// legacy callers; a LeaseClockStore IGNORES it in favor of TTL.
	ExpiresAt time.Time
	// TTL is the lease lifetime. When positive, a LeaseClockStore derives
	// the stored expiry from its own live wall clock
	// (clock_timestamp() + TTL) inside the claim transaction, so
	// cross-replica application-clock skew cannot shorten or lengthen the
	// real lease.
	TTL time.Duration

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

	CPURequest    float64
	MemoryRequest int64
	DiskRequest   int64
	PIDsRequest   int

	// ServiceEnvelopeRequest is the candidate job's aggregate service
	// request (model.Job.ServiceEnvelopeRequest). The claim reserves the sum
	// of the job request and this envelope (RequestedResources), so a runner
	// without room for the aggregate never takes the job.
	ServiceEnvelopeRequest model.ResourceCapacity

	// IgnoreServiceEnvelope relaxes the reservation to the job's OWN request
	// when the runner can establish a job-scoped parent cgroup
	// (model.CapabilityJobCgroup / Runner.JobCgroup): the kernel then bounds
	// the main container and every service together, so the union is not
	// needed as the cross-replica capacity bound. Unset (false) keeps the
	// historical job+envelope union, so every existing caller and ledger
	// stays byte-identical.
	IgnoreServiceEnvelope bool

	// Quarantined mirrors model.Job.RepoIdentityQuarantined: the claim's job
	// carries the durable repo_identity_quarantined flag, so no runner may
	// lease it (ClaimAllowsRunner denies independent of the repository ACL).
	Quarantined bool
}

// RequestedResources returns the resources the claim reserves against the
// runner: the job's own declared request plus its aggregate service envelope
// (disabled by IgnoreServiceEnvelope, i.e. when the runner's job-scoped cgroup
// already bounds the aggregate at the kernel). It is model.Job.ReservedResources
// through one shared summation (model.AddResourceCapacity), so every admission
// and ledger path charges exactly the same total.
func (c LeaseClaim) RequestedResources() model.ResourceCapacity {
	job := model.ResourceCapacity{CPU: c.CPURequest, Memory: c.MemoryRequest, Disk: c.DiskRequest, PIDs: c.PIDsRequest}
	if c.IgnoreServiceEnvelope {
		return job
	}
	return model.AddResourceCapacity(job, c.ServiceEnvelopeRequest)
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

// LeaseClockStore is the database-clock-authoritative lease lifetime
// capability. A store implementing it computes initial expiry and heartbeat
// extensions from its own live wall clock (clock_timestamp()), and refuses to
// renew a lease that has already expired at that clock; TTL is the only
// lifetime input, so application clocks on any replica cannot alter the real
// lease duration. DB mode prefers it when available; the in-memory store is
// single-process and keeps its monotonic application clock.
type LeaseClockStore interface {
	// AcquireLeaseWithTTL is AcquireLeaseAtomic with the TTL required: the
	// stored expiry is derived from the database clock inside the claim
	// transaction (claim.ExpiresAt is ignored).
	AcquireLeaseWithTTL(ctx context.Context, claim LeaseClaim) (model.Job, error)
	// HeartbeatLeaseWithTTL extends a RUNNING lease by ttl from the live
	// database clock, but only while the stored lease has not already
	// expired at that clock. It returns the authoritative stored expiry.
	HeartbeatLeaseWithTTL(ctx context.Context, jobID, runnerID string, generation int64, ttl time.Duration) (time.Time, error)
}

// LiveLeaseStore is the authoritative lease-liveness predicate in the
// store's own clock domain. DB mode uses it so the HTTP lease gate cannot
// reject a database-live lease (or admit a database-expired one) because of a
// serving replica's application-clock skew; single-process stores implement
// it with their monotonic clock for parity. Mutation paths still re-check
// liveness under their own transaction lock (LeaseCommitStore, CompleteJob),
// because an initial check cannot stay true through a blocking commit.
type LiveLeaseStore interface {
	LeaseLive(ctx context.Context, jobID, runnerID string, generation int64) (bool, error)
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
// identity: the canonical forge host plus the owner segment. The identity is
// classified with the shared typed positional rule (auth.ParseStoredRepoID,
// never a dot heuristic), so a DOTLESS host ("gitlab/acme/widget") derives
// the same host+owner pair as a dotted one, and the host is canonicalized
// (auth.CanonicalHost) exactly as the rest of storage does — a legacy
// host:port URL and a bracketed IPv6 literal cannot be misread. A bare
// "owner/name" (or a shorter name) has no host and therefore no distinct team
// key, and the exact identity string stays the caller's first quota key.
//
// Legacy URL inputs ("https://github.com/acme/backend.git") keep deriving
// host + first path segment so pre-canonical counters stay addressable.
func repoTeamKey(repo string) string {
	if u, err := url.Parse(repo); err == nil && u.Host != "" {
		host := auth.CanonicalHost(u.Host)
		if host == "" {
			return repo
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) > 0 && parts[0] != "" {
			return host + "/" + parts[0]
		}
		return host
	}
	grant, err := auth.ParseStoredRepoID(repo)
	if err != nil {
		return repo
	}
	id, ok := grant.Identity()
	if !ok {
		return repo
	}
	owner, _, ok := strings.Cut(id.FullName, "/")
	if !ok || owner == "" {
		return repo
	}
	return id.Host + "/" + owner
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

// ArtifactSidecarKindSBOM and ArtifactSidecarKindSigstore are the canonical
// pending-sidecar kinds. The generation-qualified ArtifactSidecarStore
// contract lives in postgres_sidecars.go.
const (
	ArtifactSidecarKindSBOM     = "sbom"
	ArtifactSidecarKindSigstore = "sigstore"
)

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

// CertRevocationStore is the durable certificate revocation READ contract
// (migration 0006: cert_revocations). A revocation is never a standalone
// operation: the only production path that records one is
// RunnerDisableStore.DisableRunnerAndRevokeCert, which writes
// cert_revocations, the runner's disabled state, the revoked lease set and
// the audit evidence in ONE transaction. CertRevoked is the replica-side
// check behind the server's short-TTL cache.
type CertRevocationStore interface {
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
// 0006: enrollment_grants). PutEnrollGrantWithTTL stores a fresh grant
// (digest is the SHA-256 of the raw grant) whose expiry is generated by the
// STORE's own clock — PostgreSQL: clock_timestamp() + TTL — and returns that
// authoritative instant, so a serving replica's skewed application clock can
// never extend or pre-expire an enrollment credential. EnrollGrantLive
// reports liveness (known, unconsumed, unexpired) in the same clock domain,
// so the DB-mode gate performs no application-clock expiry decision.
// GetEnrollGrant reads its state; ConsumeEnrollGrant is the atomic single-use
// claim — the conditional UPDATE matches only rows with consumed_at IS NULL
// and expires_at after the live database clock evaluated AT UPDATE TIME (so a
// consumer that waited on the row lock past expiry loses), and records
// consumed_at from that same clock. Unknown digests return ErrNotFound,
// consumed rows ErrGrantConsumed and expired rows ErrGrantExpired.
type EnrollGrantStore interface {
	PutEnrollGrantWithTTL(ctx context.Context, digest string, ttl time.Duration, boundLabels []string) (time.Time, error)
	EnrollGrantLive(ctx context.Context, digest string) (bool, error)
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
