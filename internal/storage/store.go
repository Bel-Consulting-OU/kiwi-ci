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
)

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
// exactly-once claim: MarkDownstreamLaunched records the child run ID, and a
// link whose ChildRunID is already set is never launched twice.
type DownstreamLink struct {
	ParentJobID string    `json:"parent_job_id"`
	TargetRepo  string    `json:"target_repo"`
	TargetRef   string    `json:"target_ref"`
	LaunchToken string    `json:"launch_token"`
	ChildRunID  string    `json:"child_run_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// DynamicStore persists atomically generated child jobs uploaded by a
// runner under an active lease (dynamic pipeline generation). The jobs are
// already fully compiled (IDs, needs resolved); the transaction makes the
// whole fragment visible or nothing.
type DynamicStore interface {
	InsertGeneratedJobs(ctx context.Context, parentJobID string, depth int, jobs map[string]model.Job, deps map[string][]string) error
}

// DownstreamStore is the durable cross-repo dispatch claim contract.
// InsertDownstreamLink records a launch intent (the link row is the claim);
// GetDownstreamLink reads it; MarkDownstreamLaunched atomically sets the
// child run ID only when it is not already set (idempotent exactly-once
// launch).
type DownstreamStore interface {
	InsertDownstreamLink(ctx context.Context, l DownstreamLink) error
	GetDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (DownstreamLink, bool, error)
	MarkDownstreamLaunched(ctx context.Context, parentJobID, targetRepo, targetRef, childRunID string) error
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
