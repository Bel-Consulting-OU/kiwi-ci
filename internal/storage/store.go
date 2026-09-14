// Package storage holds the durable control-plane state contracts. The
// filesystem Repository in fs.go remains the zero-dependency dev/local store;
// PostgresStore in postgres.go implements Store for HA deployments. The
// server keeps using its in-memory maps and the fs Repository until the
// scheduler phase wires the SQL store in.
package storage

import (
	"context"
	"errors"
	"fmt"
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
	// ListJobsByEnvironment returns all jobs holding the given
	// repository-scoped environment, for environment concurrency accounting.
	ListJobsByEnvironment(ctx context.Context, repoURL, environment string) ([]model.Job, error)
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
type OutboxItem struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Payload   []byte    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}

// OutboxStore is the durable outbox contract. OutboxAppend enqueues an item,
// OutboxAck removes a successfully dispatched item, and OutboxPending returns
// the unacked items in FIFO order.
type OutboxStore interface {
	OutboxAppend(ctx context.Context, e OutboxItem) error
	OutboxAck(ctx context.Context, id string) error
	OutboxPending(ctx context.Context) ([]OutboxItem, error)
}

// Schedule is one cron-triggered pipeline schedule.
type Schedule struct {
	ID         string     `json:"id"`
	Repository string     `json:"repository"`
	Spec       string     `json:"spec"`
	Enabled    bool       `json:"enabled"`
	LastRun    *time.Time `json:"last_run,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
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
	ClaimScheduleOccurrence(ctx context.Context, scheduleID string, nominal time.Time, runID string) (bool, error)
	ListOccurrences(ctx context.Context, scheduleID string) ([]Occurrence, error)
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
// exactly-once claim: ReserveDownstreamLaunch atomically reserves the link
// BEFORE the child run is enqueued, and a link whose ChildRunID is set is
// never launched twice. TargetForge/TargetBaseURL/TargetRepoID persist the
// forge identity coordinates so dispatch never re-derives hosts from
// hard-coded public endpoints.
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
	CreatedAt     time.Time  `json:"created_at"`
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

// DynamicStoreTx is the transactional dynamic-fragment contract: the
// verification closure runs inside the same transaction as the fragment
// insertion, so a stale lease or an over-cap run rejects the fragment
// atomically.
type DynamicStoreTx interface {
	InsertGeneratedJobsTx(ctx context.Context, parentJobID string, depth int, jobs map[string]model.Job, deps map[string][]string, verify GeneratedJobVerifier) error
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
type DownstreamStore interface {
	InsertDownstreamLink(ctx context.Context, l DownstreamLink) error
	GetDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (DownstreamLink, bool, error)
	ReserveDownstreamLaunch(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error)
	MarkDownstreamLaunched(ctx context.Context, parentJobID, targetRepo, targetRef, childRunID string) error
	ReleaseDownstreamReservation(ctx context.Context, parentJobID, targetRepo, targetRef string) error
	ExpireDownstreamReservations(ctx context.Context, olderThan time.Time) (int, error)
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

// RunnerJobStore lists the currently running jobs leased by one runner. It
// backs the runner disable kill switch: the control plane invalidates every
// active lease the runner holds in one atomic pass.
type RunnerJobStore interface {
	ListJobsByRunner(ctx context.Context, runnerID string) ([]model.Job, error)
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
// locked values, closing the check-then-reserve race. Zero/negative limits
// are unlimited.
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

// InsertCompiledRunRequest is the full atomic-enqueue payload: one run, its
// compiled jobs, dependency edges, artifact contracts, superseded job IDs,
// and the optional webhook-dedupe, quota-reservation and schedule-occurrence
// claims. Everything commits in a single transaction or nothing does.
type InsertCompiledRunRequest struct {
	Run            model.Run
	Jobs           map[string]model.Job
	Deps           map[string][]string
	Contracts      map[string]map[string]ArtifactContract
	CancelPrevious []string
	WebhookClaim   *WebhookClaim
	Quota          *QuotaReservation
	ScheduleClaim  *ScheduleClaim
}

// RunEnqueueStore is the atomic enqueue contract: InsertCompiledRun persists
// the run, its jobs, dependencies and artifact contracts, cancels superseded
// jobs, and claims the delivery/quota/schedule reservations in ONE
// transaction. On a webhook-dedupe conflict it returns ErrDeliveryDuplicate
// (the caller re-reads the original run via FindDelivery); on a quota limit
// it returns *QuotaExceededError; on a schedule-occurrence conflict it
// returns ErrScheduleClaimLost.
type RunEnqueueStore interface {
	InsertCompiledRun(ctx context.Context, req InsertCompiledRunRequest) error
}

// AtomicLeaseStore acquires a job lease and reserves the runner capacity
// slot in the SAME transaction: the job UPDATE claims the lease, then the
// runner UPDATE appends the job to active_jobs guarded by a capacity check;
// a runner at capacity rolls the job lease back and returns ErrNoCapacity.
// Postgres only; single-lock memory mode keeps its separate operations.
type AtomicLeaseStore interface {
	AcquireLeaseAtomic(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time, runnerCapacity int) (model.Job, error)
}

// QuotaCounterStore adjusts the reserved running/queued counters for a
// repository/team key pair (deltas may be negative; counters clamp at 0)
// and reads the current reservation state. Completion, cancellation and
// lease-recovery paths keep the counters in sync with job state.
type QuotaCounterStore interface {
	AdjustQuotaCounter(ctx context.Context, repoKey, teamKey string, runningDelta, queuedDelta int) error
	QuotaCounts(ctx context.Context, repoKey, teamKey string) (running, queued int, err error)
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

// ArtifactSidecarStore updates one artifact record's sidecar references
// (SBOM/sigstore digests) after the record was created. Only non-empty
// values are written.
type ArtifactSidecarStore interface {
	SetArtifactSidecars(ctx context.Context, id, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256 string) error
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
