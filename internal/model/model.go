package model

import (
	"strconv"
	"time"
)

type Status string

const (
	StatusPending         Status = "pending"
	StatusQueued          Status = "queued"
	StatusWaitingApproval Status = "waiting_approval"
	StatusRunning         Status = "running"
	StatusSuccess         Status = "success"
	StatusFailure         Status = "failure"
	StatusCancelled       Status = "cancelled"
	StatusSkipped         Status = "skipped"
	StatusBlocked         Status = "blocked"
)

func (s Status) Terminal() bool {
	switch s {
	case StatusSuccess, StatusFailure, StatusCancelled, StatusSkipped, StatusBlocked:
		return true
	default:
		return false
	}
}

// CapabilityJobCgroup is the runner capability name for a job-scoped parent
// cgroup: a runner that can establish one bounds the main container and every
// service together by the job's declared envelope at the kernel, so its lease
// may reserve the job's own request instead of the job+services union
// (storage.LeaseClaim.IgnoreServiceEnvelope). The capability travels through
// RunnerProfile.JobCgroup and Runner.JobCgroup.
const CapabilityJobCgroup = "job-cgroup"

// RunnerProtocolVersion is the current WIRE-SEMANTIC protocol version of the
// runner/control-plane protocol. It versions REQUIREMENTS, not fields: every
// v2 participant must implement all of the following, so a v1 runner must
// never be leased new work:
//
//   - lease-generation fencing on every runner-originated mutation: a
//     completion, log append, artifact/cache/snapshot commit, secret
//     issuance or OIDC issuance re-validates (holder, generation, token,
//     expiry) against the locked durable row at COMMIT time, so a
//     superseded generation can never mutate authoritative state;
//   - typed/scoped event cursors: execution-event reads carry an explicit
//     scope and a typed cursor, and a cursor below the retention watermark
//     is refused (410 cursor_expired) instead of silently truncating;
//   - execution attestation: completion carries the executor-observed
//     runtime evidence (model.ObservedRuntime) bound to the attempt;
//   - checkpoint phases: checkpoint publication carries its explicit phase;
//   - artifact commit fencing: artifact publication is fenced by the live
//     lease at commit time, not merely authenticated when the upload starts.
//
// Any new wire-semantic requirement MUST bump this constant. The server
// refuses a registration below its configured minimum
// (server.min_runner_protocol, default RunnerProtocolVersion; 400) and
// refuses to lease to a registered runner whose negotiated version is below
// JobRequiresProtocol (409 RUNNER_PROTOCOL_UNSUPPORTED). A legacy
// registration that omits protocol_version is version 1.
const RunnerProtocolVersion = 2

// JobRequiresProtocol is the wire-semantic protocol version a leased task
// requires: the semantics of this binary's /next response. It currently
// equals RunnerProtocolVersion; a runner whose registration negotiated a
// lower version is refused a lease (409 RUNNER_PROTOCOL_UNSUPPORTED) before
// any claim or reservation mutation.
const JobRequiresProtocol = RunnerProtocolVersion

// ExecutionSemanticsVersion is the SEMANTIC compatibility version of the
// execution engine: the version of the rules by which the scheduler, the
// runner and the executor INTERPRET durable state and compiled jobs. It is
// deliberately NOT the wire/serialization schema (that is
// RunnerProtocolVersion plus the per-record schemaVersion fields): two builds
// can speak the same wire while interpreting a lease, a cursor, a checkpoint
// phase or a compiled job differently.
//
// v2 covers: lease-generation fencing, scoped event cursors, execution
// attestation, checkpoint phases, artifact commit fencing and runner protocol
// negotiation. Every run and job created by the server is stamped with the
// value in effect at creation, and the stamp travels with the durable record,
// the execution attestation and the artifact provenance.
//
// Bump rule: ANY change to how the scheduler, the runner or the executor
// interprets durable state or compiled jobs — not a field addition that the
// existing semantics safely ignore, but a changed MEANING of existing state —
// MUST bump this constant. Exact replay reinterprets recorded history under
// the CURRENT engine, so it refuses a record stamped with a different
// non-empty value: a historical execution reproduced by a different
// interpreter is not the same execution. A record persisted before stamping
// (empty value) predates this boundary; replay proceeds with a warning.
// v3: changed-file unknown ≠ empty; native service exec/lifecycle
// (fail-closed PATH, ledger+cgroup ownership, transactional start);
// local freeze-before-compile run identity. v2 records must not replay
// under this interpreter (documented in ExecutionSemanticsVersion comment).
const ExecutionSemanticsVersion = "kiwi.execution.v3"

// LegacyExecutionSemanticsVersion is the engine version a runner implements
// when it never advertised supported_execution_semantics (pre-field binaries).
const LegacyExecutionSemanticsVersion = "kiwi.execution.v2"

// SupportsExecutionSemantics reports whether this runner's registration
// claims it can INTERPRET jobSemantics. An empty advertisement is the
// legacy contract: only kiwi.execution.v2 (the last wire-compatible engine
// before supported_execution_semantics existed). An empty job stamp
// (pre-stamp legacy records) is always admitted; the decision table for
// those lives in replay, not the lease.
func SupportsExecutionSemantics(supported []string, jobSemantics string) bool {
	if jobSemantics == "" {
		return true
	}
	if len(supported) == 0 {
		return jobSemantics == LegacyExecutionSemanticsVersion
	}
	for _, s := range supported {
		if s == jobSemantics {
			return true
		}
	}
	return false
}

type Run struct {
	ID string `json:"id"`
	// RepoID is the immutable canonical repository identity, derived ONCE at
	// ingress from the forge host plus the forge-native repository identity
	// (e.g. "github.com/owner/repo", "gitlab.company.com/group/sub/proj").
	// Every identity decision (policy lookup, RBAC, OIDC, quotas, cache
	// namespace, downstream authorization, schedule ownership, runner ACLs)
	// uses RepoID. Repo and RepoFullName are display/clone fields only: they
	// may be a URL or a bare owner/name. Additive: records persisted before
	// RepoID default to empty and consumers derive the identity from
	// Repo + RepoFullName (see the repoIDFor helpers).
	RepoID       string `json:"repo_id,omitempty"`
	Repo         string `json:"repo,omitempty"`
	RepoFullName string `json:"repo_full_name,omitempty"`
	// PolicyRepoID is the canonical repository identity every AUTHORIZATION
	// decision uses (policy lookup, RBAC, OIDC, quotas, cache namespace,
	// downstream authorization, schedule ownership, runner ACLs, audit). For
	// a PR from a fork it is the BASE repository's canonical ID, never the
	// head's. It is additive: records persisted before it default to empty
	// and consumers fall back to the derived RepoID (see repoIDForRun).
	PolicyRepoID string `json:"policy_repo_id,omitempty"`
	// CheckoutRepoURL is the clone URL the run's jobs check out: the fork
	// HEAD repository's clone URL for cross-repo PRs. It is additive;
	// legacy records default to empty and the runner falls back to Repo.
	CheckoutRepoURL string `json:"checkout_repo_url,omitempty"`
	// ForgeKind/ForgeHost are the explicit forge identity resolved once at
	// ingress (github | gitlab | forgejo plus the instance host). Check
	// publication routes by these fields; a run with no forge identity is
	// never published anywhere.
	ForgeKind        string            `json:"forge_kind,omitempty"`
	ForgeHost        string            `json:"forge_host,omitempty"`
	Ref              string            `json:"ref,omitempty"`
	SHA              string            `json:"sha,omitempty"`
	Event            string            `json:"event,omitempty"`
	Status           Status            `json:"status"`
	Trusted          bool              `json:"trusted,omitempty"`
	ConcurrencyGroup string            `json:"concurrency_group,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	StartedAt        *time.Time        `json:"started_at,omitempty"`
	FinishedAt       *time.Time        `json:"finished_at,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	// DownstreamRuns lists the child runs launched by this run's downstream
	// dispatches (cross-repo triggering). Non-empty only for runs whose jobs
	// declare downstream with wait=true; the run's aggregation keeps those
	// child runs in view until they finish. Additive.
	DownstreamRuns []string `json:"downstream_runs,omitempty"`
	// RepoIdentityQuarantined is the durable marker set by the operator
	// repository-identity repair on a run whose stored identity could not be
	// proven. Its queued/running jobs are cancelled in the same statement and
	// the shared lease predicate denies them independently of repository ACLs
	// (see Job.RepoIdentityQuarantined). Additive.
	RepoIdentityQuarantined bool `json:"repo_identity_quarantined,omitempty"`
	// ExecutionSemantics is the execution-engine semantic version (see
	// ExecutionSemanticsVersion) in effect when this run was created. The
	// server stamps it on every run it enqueues — every ingress (submit,
	// webhook, rerun, schedule, downstream dispatch) enters through the same
	// enqueue path — and every job of the run inherits the run's value.
	// Additive: records persisted before the field existed carry the empty
	// string and predate semantics stamping (exact replay warns and assumes
	// current semantics for them).
	ExecutionSemantics string `json:"execution_semantics,omitempty"`
}

// Job is the control-plane representation of one compiled job. It deliberately
// carries the pipeline text so a restarted control plane and its runners can
// recompile deterministically without an external store.
type Job struct {
	ID    string `json:"id"`
	RunID string `json:"run_id"`
	// Key is the RUN-SCOPED logical node identity: the compiled job id with
	// its matrix/shard suffix (e.g. build[os=linux]) and unique within one
	// run, so matrix variants stay distinct. Uniqueness is enforced on
	// (run_id, key) — the jobs_run_key_idx unique index where the database
	// was clean when migration 0048 ran, and always by the generated-fragment
	// admission checks (storage.CheckGeneratedJobKeyConflicts), which fail
	// closed with *storage.GeneratedJobKeyConflictError. Never key identity
	// on BaseKey.
	Key string `json:"key"`
	// BaseKey is the DECLARED pipeline job key the compiled variant came from
	// (pipeline.CompiledJob.BaseID). It is grouping/display only and
	// INTENTIONALLY repeats across matrix/shard variants of one job, so it is
	// deliberately NOT unique within a run: address a specific node by Key
	// (or ID), never by BaseKey.
	BaseKey string `json:"base_key,omitempty"`
	// RepoID is the immutable canonical repository identity, copied from the
	// run at job creation (never re-derived from the possibly changed clone
	// URL). It is the identity every authorization, policy, quota, cache and
	// scheduling decision uses; RepoURL/RepoFullName are display/clone
	// fields only. Additive: empty on legacy records, where consumers derive
	// the identity from RepoURL + RepoFullName.
	RepoID       string `json:"repo_id,omitempty"`
	RepoURL      string `json:"repo_url"`
	RepoFullName string `json:"repo_full_name,omitempty"`
	// PolicyRepoID is the canonical repository identity every authorization,
	// policy, quota, cache and scheduling decision uses; for fork PRs it is
	// the BASE repository (copied from the run), never the head. Additive:
	// empty on legacy records, where consumers derive the identity from
	// RepoID/RepoURL + RepoFullName.
	PolicyRepoID string `json:"policy_repo_id,omitempty"`
	// CheckoutRepoURL is the clone URL the runner must check out (the fork
	// head URL for cross-repo PRs). It is delivered on the task's RepoURL;
	// additive, defaults to RepoURL.
	CheckoutRepoURL  string   `json:"checkout_repo_url,omitempty"`
	Ref              string   `json:"ref,omitempty"`
	SHA              string   `json:"sha,omitempty"`
	Event            string   `json:"event,omitempty"`
	Condition        string   `json:"condition,omitempty"`
	DependencyStatus Status   `json:"dependency_status"`
	Pipeline         string   `json:"pipeline"`
	Trusted          bool     `json:"trusted"`
	ChangedFiles     []string `json:"changed_files,omitempty"`
	// ChangedFilesKnown records whether the ChangedFiles list is the
	// authoritative forge-fetched diff (complete=true). When set, an EMPTY
	// list stays empty: the runner must not fall back to a local git diff.
	// Additive: jobs persisted by older control planes default to false and
	// keep the legacy fallback.
	ChangedFilesKnown      bool     `json:"changed_files_known,omitempty"`
	Needs                  []string `json:"needs,omitempty"`
	RequiredLabels         []string `json:"required_labels,omitempty"`
	Network                string   `json:"network,omitempty"`
	Environment            string   `json:"environment,omitempty"`
	ApprovalRequired       bool     `json:"approval_required,omitempty"`
	EnvironmentBranches    []string `json:"environment_branches,omitempty"`
	EnvironmentConcurrency int      `json:"environment_concurrency,omitempty"`
	// ConcurrencyGroup/ConcurrencyLimit serialize runs of one group: at
	// most Limit jobs of the group run at once, the rest wait (FIFO). Limit
	// 0 is unlimited. Copied from spec.concurrency at enqueue.
	ConcurrencyGroup string   `json:"concurrency_group,omitempty"`
	ConcurrencyLimit int      `json:"concurrency_limit,omitempty"`
	OIDCAllowed      bool     `json:"oidc_allowed,omitempty"`
	OIDCAudiences    []string `json:"oidc_audiences,omitempty"`
	// DeclaredSecrets is the deduplicated union of the run's global secrets
	// and every step secret of this job, compiled at enqueue time. It is the
	// per-step scoping allowlist the control plane enforces when a runner
	// requests a secret value.
	DeclaredSecrets []string `json:"declared_secrets,omitempty"`
	Status          Status   `json:"status"`
	Priority        int      `json:"priority,omitempty"`
	// QueueBoost is the MATERIALIZED aged-wait term of the scheduling key:
	// floor(max(0, now-created_at)/10min), recomputed by the bounded
	// PromoteQueuedJobBoosts sweep into the jobs.queue_boost column. The
	// aged order is (priority + queue_boost) DESC, created_at ASC, id ASC,
	// which the jobs_queued_aged_idx expression index serves directly, so
	// the page walk stops at limit+1 index entries instead of sorting the
	// whole queued population. Memory stores leave it zero and compute the
	// same term on the fly (BoostKnown false); SQL rows are scanned with
	// BoostKnown true and the stored value authoritative.
	QueueBoost int `json:"queue_boost,omitempty"`
	// BoostKnown reports whether QueueBoost was read from a materialized
	// store column. It is never persisted (json:"-") and memory stores
	// leave it false, so consumers compute the aged term from CreatedAt
	// instead.
	BoostKnown      bool                         `json:"-"`
	MaxInfraRetries int                          `json:"max_infra_retries,omitempty"`
	CreatedAt       time.Time                    `json:"created_at"`
	StartedAt       *time.Time                   `json:"started_at,omitempty"`
	FinishedAt      *time.Time                   `json:"finished_at,omitempty"`
	Error           string                       `json:"error,omitempty"`
	Outputs         map[string]string            `json:"outputs,omitempty"`
	NeedsOutputs    map[string]map[string]string `json:"needs_outputs,omitempty"`
	Attempts        int                          `json:"attempts"`
	LeaseRunnerID   string                       `json:"lease_runner_id,omitempty"`
	// LeaseTokenHash is the HMAC-SHA256 of the raw lease token under the
	// server's lease key. The raw token is never persisted anywhere.
	LeaseTokenHash  []byte     `json:"lease_token_hash,omitempty"`
	LeaseGeneration int64      `json:"lease_generation,omitempty"`
	LeaseExpiresAt  *time.Time `json:"lease_expires_at,omitempty"`
	ApprovedBy      string     `json:"approved_by,omitempty"`
	// ForgeKind/ForgeHost carry the run's forge identity (copied at job
	// creation) so job-level publication and audit can never guess a forge.
	ForgeKind string `json:"forge_kind,omitempty"`
	ForgeHost string `json:"forge_host,omitempty"`
	// QueueReason records why a queued job has not been leased yet. It is
	// a queue.QueueReason code (e.g. WAITING_DEPENDENCY, NO_COMPATIBLE_RUNNER)
	// set by the control plane's scheduling pass; empty means no reason.
	QueueReason string `json:"queue_reason,omitempty"`
	// PlacementRegions is the job's placement.regions list resolved at
	// enqueue; scheduling filters runners by it (see [71]).
	PlacementRegions []string `json:"placement_regions,omitempty"`
	// ComponentDigest records the content digest of the resolved component
	// the job was built from, when the job was declared via
	// `component: name@sha256:...`. Empty for regular jobs.
	ComponentDigest string `json:"component_digest,omitempty"`
	// CompiledJobPayload carries the deterministic enqueue-time compilation
	// record for this job: pipeline and job digests, the effective compiled
	// job JSON, and the effective policy capabilities. Additive: runners
	// that predate it simply ignore it.
	CompiledJobPayload *CompiledJobPayload `json:"compiled_job_payload,omitempty"`
	// WaitingSince records when an approval-gated job entered the waiting
	// state; approval metrics derive the wait duration from it. Additive.
	WaitingSince *time.Time `json:"waiting_since,omitempty"`
	// DynamicDepth is the generation depth of a dynamically generated job:
	// 0 for compiled pipeline jobs, parent depth+1 for generated children.
	// The control plane bounds it (maxDynamicDepth) so a runner cannot grow
	// a run's job graph without limit. Additive.
	DynamicDepth int `json:"dynamic_depth,omitempty"`
	// CostRate and PowerWatts are the runner's registered rates frozen into
	// the job at lease time; completion multiplies them by the wall-clock
	// duration to derive Cost and EnergyWh via quotas.ComputeUsage.
	// Additive.
	CostRate   float64 `json:"cost_rate,omitempty"`
	PowerWatts float64 `json:"power_watts,omitempty"`
	// Cost and EnergyWh are the usage recorded at completion. Additive.
	Cost     float64 `json:"cost,omitempty"`
	EnergyWh float64 `json:"energy_wh,omitempty"`
	// UsageRecorded marks that completion usage accounting has been applied
	// to this job. The completion usage_account effect sets it after
	// recording cost/energy, so replayed reconciliations (outbox flush,
	// receipt replay) can never double-account. Additive.
	UsageRecorded bool `json:"usage_recorded,omitempty"`
	// CPURequest/MemoryRequest/DiskRequest/PIDsRequest carry the job's
	// declared resource requirements (pipeline Job.Resources), persisted in
	// the job payload so scheduling and backend enforcement can read them
	// without recompiling. Additive.
	CPURequest    float64 `json:"cpu_request,omitempty"`
	MemoryRequest int64   `json:"memory_request,omitempty"`
	DiskRequest   int64   `json:"disk_request,omitempty"`
	PIDsRequest   int     `json:"pids_request,omitempty"`
	// JobTimeout is the resolved job lifetime stamped at enqueue (the
	// compiled job's timeout, else the pipeline's defaults.timeout), the same
	// way CPU/memory/disk/PIDs are persisted. The distributed runner starts
	// this deadline at the very beginning of execute — before workspace
	// setup, checkout, dependency restore and every other pre-execution
	// phase — so local and distributed execution agree on what the declared
	// job timeout covers, and a stalled clone cannot outlive the job budget.
	// Zero means no declared timeout; the runner then applies its own setup
	// phase ceiling. Additive.
	JobTimeout time.Duration `json:"job_timeout,omitempty"`
	// ServiceEnvelopeRequest is the AGGREGATE CPU/memory/PIDs the job's
	// declared service containers may consume. It is stamped at enqueue from
	// the effective compiled job through the executor's ONE fair-split
	// planner (executor.ServiceEnvelopeRequest), for trusted and untrusted
	// jobs alike. Disk is never part of it: service containers are read-only
	// with a tmpfs and carry no workspace bound.
	//
	// Reservation semantics: a lease reserves the job's own request PLUS this
	// aggregate (see ReservedResources). Where the runner can establish a
	// job-scoped parent cgroup, the kernel additionally bounds the main
	// container and every service together by the job's declared envelope;
	// where it cannot (non-Linux, cgroup v1, no delegation, systemd driver —
	// probed and logged by the runner), the per-container caps plus the fair
	// split are the only enforcement, and this reservation is the bound that
	// keeps aggregate host usage within the runner's capacity across
	// replicas. The scheduler cannot probe the runner's host, so the
	// aggregate is charged either way and is never double-counted against
	// the job's own envelope.
	//
	// Additive: jobs persisted before this field default to the zero value,
	// which reserves exactly what the pre-envelope ledger reserved.
	ServiceEnvelopeRequest ResourceCapacity `json:"service_envelope_request,omitempty"`
	// QueueDeadline is the absolute queue-residence deadline derived from
	// the job's queue_timeout at enqueue (CreatedAt + queue_timeout). The
	// scheduler skips candidates past the deadline and RecoverExpired
	// cancels them with reason "queue timeout". Nil means no timeout.
	// Additive; payload-based, no dedicated storage column.
	QueueDeadline *time.Time `json:"queue_deadline,omitempty"`
	// RepoIdentityQuarantined is the durable marker set by the operator
	// repository-identity repair on a row whose stored identity could not be
	// proven. A quarantined job is operationally inert: the shared lease
	// predicate (storage.LeasePredicate.Allows / ClaimAllowsRunner) denies it
	// independently of every repository allowlist or policy grant, so an
	// allow-everything ACL cannot admit unprovable work. Additive.
	RepoIdentityQuarantined bool `json:"repo_identity_quarantined,omitempty"`
	// ObservedRuntime is the executor-captured runtime identity of the
	// attempt that completed this job (see ObservedRuntime). It is persisted
	// by the completion transaction from the runner's completion payload;
	// nil for jobs completed by runners that captured nothing. Additive.
	ObservedRuntime *ObservedRuntime `json:"observed_runtime,omitempty"`
	// UsageLeaseGeneration is the lease generation whose completion recorded
	// this job's usage (usage_recorded/cost/energy_wh). It binds the durable
	// usage accounting to the exact attempt that incurred it. 0 for records
	// persisted before the field existed. Additive.
	UsageLeaseGeneration int64 `json:"usage_lease_generation,omitempty"`
	// AttemptRunnerID is the runner identity that COMPLETED the job's current
	// attempt, persisted by the completion transaction before the lease
	// fields are cleared (LeaseRunnerID is owned by the live lease and must
	// not survive it). It is the durable runner identity the final execution
	// attestation binds; additive and empty for records completed before the
	// field existed.
	AttemptRunnerID string `json:"attempt_runner_id,omitempty"`
	// ExecutionSemantics is the execution-engine semantic version (see
	// ExecutionSemanticsVersion) the job is interpreted under: copied from
	// the owning run at creation. Dynamically generated children inherit the
	// parent run's value, so one run's graph is never half-stamped. Additive:
	// empty for records persisted before the field existed (see
	// Run.ExecutionSemantics).
	ExecutionSemantics string `json:"execution_semantics,omitempty"`
	// ObservedExecutionSemantics is the interpreter version the completing
	// runner actually used. The server requires equality with
	// ExecutionSemantics (or fills it from the stamp when the runner omits
	// the field) before accepting a completion, so requested and observed
	// can never diverge on a signed record. Additive: empty when no
	// completion has been observed or when the completing binary predates
	// the field.
	ObservedExecutionSemantics string `json:"observed_execution_semantics,omitempty"`
	// CreatedByNode, CreatedByMutation and ExternalContext record the graph
	// causality of a dynamically generated job. CreatedByNode is the
	// generating parent job ID; CreatedByMutation is the canonical
	// generation-free mutation receipt identity ("<parentID>:<mutationSlot>",
	// see storage.GeneratedFragmentReceipt); ExternalContext is the bounded
	// opaque correlation context the generating fragment request attached
	// (api/v1.GeneratedFragment.ExternalContext), echoed verbatim and never
	// interpreted by Kiwi. All three are empty for jobs enqueued through
	// ordinary admission: generated children are stamped by the fragment
	// admission path only. ExternalContext is caller-supplied correlation
	// data, never secrets; it is bounded (<= 256 printable bytes) at
	// admission. Additive: records persisted before the fields existed carry
	// the empty string.
	CreatedByNode     string `json:"created_by_node,omitempty"`
	CreatedByMutation string `json:"created_by_mutation,omitempty"`
	ExternalContext   string `json:"external_context,omitempty"`
}

// ExecutionAttestationRecord is the durable index row of one signed final
// execution attestation. The signed DSSE envelope itself lives in the CAS
// (EnvelopeRef "cas:<sha256>") or, in fs dev mode, in a durable sidecar file
// whose path EnvelopeRef records. The primary key is (JobID, Generation): one
// attempt has exactly one attestation, so an idempotent replay can never
// append a second row or a second event.
type ExecutionAttestationRecord struct {
	JobID      string `json:"job_id"`
	Generation int64  `json:"generation"`
	RunID      string `json:"run_id"`
	Status     string `json:"status"`
	// StatementSHA256 is the SHA-256 of the canonical statement JSON the
	// envelope payload carries (the signed bytes before DSSE wrapping).
	StatementSHA256 string `json:"statement_sha256"`
	// EnvelopeRef locates the signed envelope: "cas:<sha256>" in CAS mode or
	// the durable sidecar file path in fs mode.
	EnvelopeRef string    `json:"envelope_ref"`
	CreatedAt   time.Time `json:"created_at"`
}

// AttestationKey derives the canonical map key of one execution attestation
// record: "<jobID>:<generation>" (model.AttemptID), matching the row's
// primary key identity.
func (r ExecutionAttestationRecord) Key() string {
	return AttemptID(r.JobID, r.Generation)
}

// ObservedRuntime is the executor-observed runtime identity of one job
// attempt: the platform, the runtime software, and the image digests the
// attempt actually started from. It is evidence, not configuration: every
// field is captured best-effort at execution time and omitted when it cannot
// be determined.
//
// Digest contract: MainImageDigest and ServiceImageDigests come from
// `docker image inspect --format '{{index .RepoDigests 0}}' <ref>` when the
// reference is resolvable on the runner; when inspect fails, times out, or
// reports no RepoDigests entry the digest is OMITTED — it is never
// fabricated from the tag or guessed. A reference that is already pinned by
// an @sha256: digest records that pinned digest even when inspect fails,
// because the pin proves what was requested and the image was required to
// match it. Components maps a resolved component/material name to the
// content digest the control plane resolved at enqueue (read from the
// persisted job at completion, not from the runner).
type ObservedRuntime struct {
	OS                  string            `json:"os,omitempty"`
	Arch                string            `json:"arch,omitempty"`
	RuntimeName         string            `json:"runtime_name,omitempty"`
	RuntimeVersion      string            `json:"runtime_version,omitempty"`
	MainImage           string            `json:"main_image,omitempty"`
	MainImageDigest     string            `json:"main_image_digest,omitempty"`
	ServiceImages       map[string]string `json:"service_images,omitempty"`
	ServiceImageDigests map[string]string `json:"service_image_digests,omitempty"`
	Components          map[string]string `json:"components,omitempty"`
	CapturedAt          time.Time         `json:"captured_at,omitempty"`
	// Control is the executor-observed ENFORCEMENT receipt of the attempt
	// (see ExecutionControlReceipt): what the concrete runtime actually
	// entered when it started, as opposed to what the effective policy
	// requested. Nil when the backend captured no receipt (legacy records,
	// runtimes without capture); it is never fabricated.
	Control *ExecutionControlReceipt `json:"control,omitempty"`
}

type Runner struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Labels     []string          `json:"labels,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Capacity   int               `json:"capacity,omitempty"`
	Registered time.Time         `json:"registered,omitempty"`
	Completed  int64             `json:"completed,omitempty"`
	Failed     int64             `json:"failed,omitempty"`
	LastSeen   time.Time         `json:"last_seen"`
	// Incarnation is the newest registration session for this stable runner
	// ID: a later registration replaces it, and polling/heartbeat requests
	// carrying an older incarnation are refused so two processes sharing one
	// identity cannot both operate.
	Incarnation string   `json:"incarnation,omitempty"`
	ActiveJobs  []string `json:"active_jobs,omitempty"`
	CurrentJob  string   `json:"current_job,omitempty"`
	Busy        bool     `json:"busy"`

	// ResourceCapacity is the runner's effective resource capacity (CPU,
	// memory, disk, PIDs). It is overlaid from the runner's linked profile
	// at registration and at lease time (ResolveRunnerProfile); a runner
	// without a linked profile uses its registration snapshot, and a zero
	// dimension is UNCONSTRAINED. Additive: deployments that predate it
	// keep the count-only behavior. The effective values are persisted with
	// the registration payload and re-resolved live from the profile on
	// every lease.
	ResourceCapacity ResourceCapacity `json:"resource_capacity,omitempty"`

	// JobCgroup is the resolved job-scoped cgroup capability (see
	// CapabilityJobCgroup): copied from the runner's linked profile by
	// storage.ResolveRunnerProfile, so an unlinked runner stays false.
	// When true, a lease on this runner may reserve only the job's own
	// request because the kernel bounds the main container and every
	// service together. Additive: false keeps the job+services union
	// reservation.
	JobCgroup bool `json:"job_cgroup,omitempty"`

	// Admission control.
	Disabled bool `json:"disabled,omitempty"`
	Draining bool `json:"draining,omitempty"`

	// Descriptive and protocol metadata reported at registration.
	Region      string `json:"region,omitempty"`
	Version     string `json:"version,omitempty"`
	ProtocolMin int    `json:"protocol_min,omitempty"`
	ProtocolMax int    `json:"protocol_max,omitempty"`
	// ProtocolVersion is the WIRE-SEMANTIC protocol version negotiated at
	// registration: the runner's declared value (RunnerProtocolVersion or
	// below), or 1 when a legacy registration omitted protocol_version. A
	// stored 0 is a row persisted before this field existed and is treated
	// as legacy v1 by lease admission. Additive: no migration, the value
	// rides the runner payload in every store.
	ProtocolVersion int `json:"protocol_version,omitempty"`
	// SupportedExecutionSemantics lists the execution-engine semantic
	// versions this runner's BINARY implements (see
	// ExecutionSemanticsVersion). Registration populates it from the local
	// constant. An empty list means a legacy runner that has never
	// advertised semantics: it is treated as implementing only the
	// pre-v3 engine (`kiwi.execution.v2`) so a v3 job is never leased to
	// a v2 interpreter. Additive: old servers ignore the field; old
	// runners omit it and therefore never receive stamped v3 work.
	SupportedExecutionSemantics []string `json:"supported_execution_semantics,omitempty"`
	// Capabilities is the EFFECTIVE runtime capability set the scheduler
	// decides on. When CapabilitiesEnforced is true it is the hardware claim
	// (ReportedCapabilities) intersected with the linked profile's ceiling;
	// when false it is the runner's own self-reported set and an empty list
	// keeps the historical "unrestricted" meaning. Backward compatible:
	// deployments that predate the split persist this field unchanged and
	// decode CapabilitiesEnforced as false.
	Capabilities []string `json:"capabilities,omitempty"`
	// ReportedCapabilities is the runner's normalized hardware capability
	// claim exactly as it reported it at registration (the hardware it
	// actually provides, e.g. ["native","container"]). It is the ONLY input
	// the live profile intersection narrows: ResolveRunnerProfile recomputes
	// Capabilities from this claim plus the live profile, so a profile edit
	// can never re-widen a runner past the hardware registration proved.
	// An explicit empty claim is authoritative (intersecting to nothing).
	ReportedCapabilities []string `json:"reported_capabilities,omitempty"`
	// CapabilitiesEnforced reports whether Capabilities is an authoritative
	// (profile-derived) set: true means an empty set denies every runtime,
	// false means legacy self-reported semantics (an empty set is
	// unrestricted). The server sets it at registration and on every live
	// profile resolution; a client-asserted value never survives.
	CapabilitiesEnforced bool     `json:"capabilities_enforced,omitempty"`
	AllowedRepositories  []string `json:"allowed_repositories,omitempty"`

	// Cost accounting.
	CostPerHour float64 `json:"cost_per_hour,omitempty"`
	PowerWatts  float64 `json:"power_watts,omitempty"`

	// ProfileID records the runner profile whose scheduling attributes were
	// COPIED onto this row at registration ("" when the row carries only the
	// runner's own self-reported attributes, e.g. legacy dev-mode
	// registration). It is the revocation marker of the runner-ID binding
	// model: while it is set, every scheduling attribute below is
	// profile-derived, and unlinking the runner (UnlinkRunnerProfile, the
	// admin DELETE endpoint) clears the marked attributes in the SAME store
	// operation so a removed profile cannot keep applying through the
	// registration snapshot. It is server-owned: the registration handler
	// overwrites it with the resolved profile's ID (or clears it when no
	// profile applies), so a client-asserted profile_id never survives.
	ProfileID string `json:"profile_id,omitempty"`

	// Runner certificate state.
	CertSerial string     `json:"cert_serial,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// RunnerProfile is the server-owned runner identity profile. Every
// scheduling-relevant runner attribute (labels, region, repository scope,
// capabilities, capacity, resource capacities, cost/energy rates) is
// server-owned: runners may not self-report any of it at registration — the
// profile supplies it, and a runner without a linked profile registers empty
// (capacity 0, no labels/region, no rates). Repositories holds canonical
// repo IDs ("<forgeHost>/<owner>/<name>"); empty means any repository.
//
// MaxCPU/MaxMemory/MaxDisk/MaxPIDs are the profile's resource capacities:
// the ceiling against which the LIVE sum of the runner's reserved running
// jobs is checked at lease time. A zero dimension is UNCONSTRAINED (the
// documented default; pre-0030 behavior is the count-only max_capacity).
type RunnerProfile struct {
	ID           string    `json:"id"`
	Labels       []string  `json:"labels,omitempty"`
	Region       string    `json:"region,omitempty"`
	Repositories []string  `json:"repositories,omitempty"`
	Capabilities []string  `json:"capabilities,omitempty"`
	MaxCapacity  int       `json:"max_capacity,omitempty"`
	MaxCPU       float64   `json:"max_cpu,omitempty"`
	MaxMemory    int64     `json:"max_memory,omitempty"`
	MaxDisk      int64     `json:"max_disk,omitempty"`
	MaxPIDs      int       `json:"max_pids,omitempty"`
	CostPerHour  float64   `json:"cost_per_hour,omitempty"`
	PowerWatts   float64   `json:"power_watts,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	// JobCgroup is the profile's job-scoped cgroup capability (see
	// CapabilityJobCgroup): when set, ResolveRunnerProfile copies it onto
	// the effective runner and a lease on that runner may reserve the job
	// request alone instead of the job+services union. Additive: false
	// keeps the union reservation.
	JobCgroup bool `json:"job_cgroup,omitempty"`
}

// ResourceCapacity is one entity's resource quantities: a runner's
// remaining/effective capacity or a set of resource requests, in the same
// additive order as the job request fields. A zero dimension means
// "unconstrained" when read as a CAPACITY and "no request" when read as a
// request; ResourceAdmission decides which dimensions bind.
type ResourceCapacity struct {
	CPU    float64 `json:"cpu,omitempty"`
	Memory int64   `json:"memory,omitempty"`
	Disk   int64   `json:"disk,omitempty"`
	PIDs   int     `json:"pids,omitempty"`
}

// ResourceCapacityFromProfile returns the profile's resource capacities.
func ResourceCapacityFromProfile(p RunnerProfile) ResourceCapacity {
	return ResourceCapacity{CPU: p.MaxCPU, Memory: p.MaxMemory, Disk: p.MaxDisk, PIDs: p.MaxPIDs}
}

// ResourceRequest returns the job's declared resource requests as a
// ResourceCapacity.
func (j Job) ResourceRequest() ResourceCapacity {
	return ResourceCapacity{CPU: j.CPURequest, Memory: j.MemoryRequest, Disk: j.DiskRequest, PIDs: j.PIDsRequest}
}

// AddResourceCapacity returns a+b dimension by dimension. It is the ONE
// summation the job/service reservation shares: Job.ReservedResources and
// LeaseClaim.RequestedResources both call it, so the scheduler's pre-filter,
// the SQL claim and its reservation row, the memory-store claim, the fs/dev
// admission in server.next and the leader-promotion reconciliation always
// agree on the reserved total.
func AddResourceCapacity(a, b ResourceCapacity) ResourceCapacity {
	return ResourceCapacity{CPU: a.CPU + b.CPU, Memory: a.Memory + b.Memory, Disk: a.Disk + b.Disk, PIDs: a.PIDs + b.PIDs}
}

// ReservedResources returns the TOTAL resources a lease on this job reserves
// against its runner: the job's own declared request plus its aggregate
// service envelope (ServiceEnvelopeRequest). A job without services — or a
// legacy payload persisted before the envelope field — reserves exactly its
// own request, the pre-envelope behavior.
func (j Job) ReservedResources() ResourceCapacity {
	return AddResourceCapacity(j.ResourceRequest(), j.ServiceEnvelopeRequest)
}

// CompiledJobPayloadSchemaVersion is the schema version stamped on every
// CompiledJobPayload. version.ContractVersions binds its compiled_job_schema
// row to this constant.
const CompiledJobPayloadSchemaVersion = 1

// CompiledJobPayload is the enqueue-time compilation record persisted on a
// job. PipelineDigest and JobDigest are content addresses the runner can
// verify against its own recompilation; EffectiveJob is the canonical JSON
// of the pipeline.CompiledJob and EffectivePolicy the effective capability
// set JSON the job was admitted under.
type CompiledJobPayload struct {
	SchemaVersion   int    `json:"schema_version"`
	CompilerVersion string `json:"compiler_version"`
	PipelineDigest  string `json:"pipeline_digest"`
	JobDigest       string `json:"job_digest"`
	EffectiveJob    any    `json:"effective_job,omitempty"`
	EffectivePolicy any    `json:"effective_policy,omitempty"`
}

// AttemptID returns the canonical identity of one job execution attempt:
// "<jobID>:<leaseGeneration>". Job IDs are opaque and never contain ":"
// while the generation is a decimal integer, so the encoding is unambiguous.
// Every statement about an attempt must carry this identity rather than a
// bare job ID so a re-leased job's evidence can never be confused with an
// earlier generation's.
func AttemptID(jobID string, generation int64) string {
	return jobID + ":" + strconv.FormatInt(generation, 10)
}

type ArtifactRecord struct {
	ID               string     `json:"id"`
	RunID            string     `json:"run_id"`
	JobID            string     `json:"job_id"`
	JobKey           string     `json:"job_key"`
	Name             string     `json:"name"`
	Path             string     `json:"path,omitempty"`
	Size             int64      `json:"size"`
	SHA256           string     `json:"sha256"`
	ContentType      string     `json:"content_type,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	ProvenancePath   string     `json:"provenance_path,omitempty"`
	ProvenanceSHA256 string     `json:"provenance_sha256,omitempty"`
	// LeaseGeneration is the job lease generation the artifact was uploaded
	// under; upload idempotency is scoped to (job, generation, name).
	LeaseGeneration int64 `json:"lease_generation,omitempty"`
	// SBOMPath/SBOMSHA256 locate the attached SBOM document validated
	// against the job's artifact contract.
	SBOMPath   string `json:"sbom_path,omitempty"`
	SBOMSHA256 string `json:"sbom_sha256,omitempty"`
	// SigstorePath/SigstoreSHA256 locate the verified Sigstore bundle
	// attestation for this artifact.
	SigstorePath   string `json:"sigstore_path,omitempty"`
	SigstoreSHA256 string `json:"sigstore_sha256,omitempty"`
}

type TestResult struct {
	Name     string  `json:"name"`
	Class    string  `json:"class,omitempty"`
	Duration float64 `json:"duration,omitempty"`
	Passed   bool    `json:"passed"`
	Skipped  bool    `json:"skipped,omitempty"`
	Message  string  `json:"message,omitempty"`
}

type TestReport struct {
	ID        string       `json:"id"`
	RunID     string       `json:"run_id"`
	JobID     string       `json:"job_id"`
	JobKey    string       `json:"job_key"`
	Path      string       `json:"path"`
	Tests     int          `json:"tests"`
	Failures  int          `json:"failures"`
	Errors    int          `json:"errors,omitempty"`
	Skipped   int          `json:"skipped,omitempty"`
	Duration  float64      `json:"duration,omitempty"`
	Cases     []TestResult `json:"cases,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
	// LeaseGeneration is the lease generation (attempt identity) the report
	// was delivered under, stamped by the lease-fenced insert from the
	// verified lease — never from client input. 0 for legacy records.
	// Additive (payload JSON only).
	LeaseGeneration int64 `json:"lease_generation,omitempty"`
}

type LogEntry struct {
	Seq       int64     `json:"seq"`
	RunID     string    `json:"run_id"`
	JobID     string    `json:"job_id"`
	JobKey    string    `json:"job_key"`
	Step      string    `json:"step"`
	Line      string    `json:"line"`
	CreatedAt time.Time `json:"created_at"`
	// LeaseGeneration is the lease generation (attempt identity) the log line
	// was delivered under. The runner already sends it on the wire; the
	// server stamps it here so fs/memory log reads can attribute a line to an
	// attempt. Additive: legacy entries decode as 0.
	LeaseGeneration int64 `json:"lease_generation,omitempty"`
}

type AuditEvent struct {
	ID        string            `json:"id"`
	Action    string            `json:"action"`
	Actor     string            `json:"actor,omitempty"`
	RunID     string            `json:"run_id,omitempty"`
	JobID     string            `json:"job_id,omitempty"`
	Message   string            `json:"message,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// Semantic execution event types: the durable companion to the "<scope>.
// <status>" transition vocabulary. The transition types describe the mutable
// lifecycle resource changing state; these describe the significant ACTS a
// controller cannot reconstruct from the resource snapshot (a graph mutation
// committed, an artifact published, a secret/credential issued, a deployment
// started). They are emitted in the same transaction as the act they
// describe (PostgreSQL), so a rolled-back act never leaves an event, and
// their payloads stay small and non-secret: ids, names, generations, digests
// and claim KEY names only, never a secret value, token or plaintext claim.
const (
	// EventAttemptCreated records a job attempt (lease generation) being
	// created: one attempt.created per successful claim, Attempt = the new
	// lease generation, Actor = the runner.
	EventAttemptCreated = "attempt.created"
	// EventGraphMutationCommitted records a dynamic pipeline fragment being
	// committed for a (parent job, mutation slot).
	EventGraphMutationCommitted = "graph.mutation_committed"
	// EventGraphMutationReplayed records an idempotent replay of an already
	// committed fragment: no new mutation happened, the original children
	// are returned.
	EventGraphMutationReplayed = "graph.mutation_replayed"
	// EventArtifactPublished records a new artifact record committed under a
	// lease. An idempotent duplicate upload does NOT emit it again.
	EventArtifactPublished = "artifact.published"
	// EventCheckpointPublished records a workspace snapshot (checkpoint)
	// record committed under a lease.
	EventCheckpointPublished = "checkpoint.published"
	// EventApprovalGranted records an environment-gated job approval.
	EventApprovalGranted = "approval.granted"
	// EventSecretIssued records a secret delivery commit (secret NAME and
	// generation only; the sealed value never appears).
	EventSecretIssued = "secret.issued"
	// EventOIDCIssued records an OIDC id_token issuance (audience, kid and
	// claim key names only; the token and claim values never appear).
	EventOIDCIssued = "oidc.issued"
	// EventDeploymentStarted records a deployment lifecycle record being
	// created for a running environment job.
	EventDeploymentStarted = "deployment.started"
	// EventDeploymentCompleted records a deployment lifecycle record being
	// finished (exactly once).
	EventDeploymentCompleted = "deployment.completed"
	// EventExecutionAttested is RESERVED for the completion-attestation /
	// observed-runtime follow-up. The constant is declared so consumers can
	// already ignore the name safely; no emitter exists yet.
	EventExecutionAttested = "execution.attested"
)

// ExecutionEvent is one record of the canonical ordered execution event
// stream. Seq is the durable cursor: it is assigned by the durable store
// (the commit-ordered PostgreSQL cursor, the fs/memory journal's monotonic
// counter) and is the only ordering external controllers may rely on. Event
// types are either "<scope>.<status>" transition names (job.queued,
// job.running, job.succeeded, job.failed, job.cancelled, job.requeued,
// run.running, run.succeeded, ...) or the semantic Event* vocabularies
// above; FromStatus and ToStatus carry the transition so consumers never
// diff mutable resources to infer what happened. RepoID is the repository
// dimension the event belongs to (the owning run's immutable RepoID,
// propagated at append time; empty when the owning run is unknown), so the
// stream can be scoped and authorized per repository. Attempt is the lease
// generation of the attempt the event belongs to (0 when none). Actor is
// the runner name or principal that drove the event when known. Payload is
// small and non-secret by contract. Additive and self-describing: unknown
// fields/event types must be ignored by consumers.
// ExecutionEventSchemaVersion is the schema version stamped on every
// ExecutionEvent. version.ContractVersions binds its event_schema row to
// this constant.
const ExecutionEventSchemaVersion = 1

type ExecutionEvent struct {
	Seq           int64             `json:"seq"`
	SchemaVersion int               `json:"schema_version"`
	RunID         string            `json:"run_id,omitempty"`
	JobID         string            `json:"job_id,omitempty"`
	RepoID        string            `json:"repo_id,omitempty"`
	Attempt       int64             `json:"attempt,omitempty"`
	Type          string            `json:"type"`
	FromStatus    string            `json:"from_status,omitempty"`
	ToStatus      string            `json:"to_status,omitempty"`
	Actor         string            `json:"actor,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	Payload       map[string]string `json:"payload,omitempty"`
}

type JobResult struct {
	JobID      string            `json:"job_id"`
	Status     Status            `json:"status"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Duration   time.Duration     `json:"duration"`
	Attempts   int               `json:"attempts"`
	Error      string            `json:"error,omitempty"`
	Outputs    map[string]string `json:"outputs,omitempty"`
	// ObservedRuntime carries the executor-captured runtime identity of this
	// attempt (nil when nothing could be captured: a native execution with no
	// runtime surface, a failure before the runtime started, capture errors).
	// The distributed runner forwards it on the completion wire; the control
	// plane persists it on the job. Additive.
	ObservedRuntime *ObservedRuntime `json:"observed_runtime,omitempty"`
}

// CompletionReceipt deduplicates runner completion requests so a retried
// complete() after a lost response is idempotent for the same generation.
// ResultHash is the SHA-256 of the canonicalized completion payload.
//
// ResultHashVersion tags how ResultHash was computed, so replay resolution can
// compare like with like across a rolling upgrade:
//
//   - 2: storage.CompletionResultDigestV2 over status, error digest, outputs
//     and the observed runtime evidence. New completions always write this.
//   - 1 (or 0, a record persisted before the field existed): the legacy
//     computation over status, error and outputs only. A stored v1 receipt can
//     replay only when the retry's legacy digest matches AND the runtime
//     evidence is nil-or-equal (see storage.CompletionReceiptReplayMatches):
//     a v2-evidence-bearing retry must never masquerade as the legacy identity.
type CompletionReceipt struct {
	JobID             string `json:"job_id"`
	Generation        int64  `json:"generation"`
	RunnerID          string `json:"runner_id"`
	ResultHash        string `json:"result_hash"`
	ResultHashVersion int    `json:"result_hash_version,omitempty"`
	// ObservedExecutionSemantics is the interpreter stamp the completion
	// reported (validated for equality against the job stamp by the server
	// before the receipt is built). It rides the receipt so the DB
	// completion transaction can persist Job.ObservedExecutionSemantics
	// without a second API. Additive: empty on legacy receipts; a job with
	// a requested stamp still records requested == observed when this is
	// empty. It is NOT part of the idempotency key or the result hash.
	ObservedExecutionSemantics string `json:"observed_execution_semantics,omitempty"`
}

// Deployment is the server-side record of one environment deployment. It is
// created when a job targeting an environment starts (or explicitly via
// POST /api/v1/jobs/{id}/deployments) and follows the job's lifecycle.
type Deployment struct {
	ID          string     `json:"id"`
	RunID       string     `json:"run_id"`
	JobID       string     `json:"job_id"`
	Repository  string     `json:"repository,omitempty"`
	Environment string     `json:"environment,omitempty"`
	URL         string     `json:"url,omitempty"`
	Commit      string     `json:"commit,omitempty"`
	Status      Status     `json:"status"`
	ApprovedBy  string     `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	// LeaseGeneration is the lease generation (attempt identity) of the job
	// attempt that started this deployment, stamped at start and preserved
	// across the finish. 0 for legacy records. Additive (payload JSON only).
	LeaseGeneration int64 `json:"lease_generation,omitempty"`
}

// SnapshotEntry is one regular file in a workspace snapshot manifest.
type SnapshotEntry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Snapshot phase values. A snapshot is captured either BEFORE a job attempt
// executes (pre_job: the pre-execution checkpoint, the state a replay must
// start from) or AFTER it finished (post_job: the outcome workspace, which
// already contains the attempt's mutations).
const (
	SnapshotPhasePreJob  = "pre_job"
	SnapshotPhasePostJob = "post_job"
)

// SnapshotRecord is the server-side record of an uploaded workspace
// snapshot: the archive location, its digest, and the entry manifest.
type SnapshotRecord struct {
	ID         string          `json:"id"`
	RunID      string          `json:"run_id"`
	JobID      string          `json:"job_id"`
	JobKey     string          `json:"job_key"`
	Path       string          `json:"path,omitempty"`
	Size       int64           `json:"size"`
	SHA256     string          `json:"sha256"`
	Version    int             `json:"version"`
	RootSHA256 string          `json:"root_sha256"`
	Entries    []SnapshotEntry `json:"entries,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	// Phase records when the snapshot was captured relative to the attempt's
	// execution: SnapshotPhasePreJob or SnapshotPhasePostJob. Legacy records
	// persisted before the field existed carry the empty string and mean
	// SnapshotPhasePostJob (they were outcome captures); exact replay refuses
	// to use such a record unless --allow-post-job-snapshot is passed.
	Phase string `json:"phase,omitempty"`
	// LeaseGeneration is the lease generation (attempt identity) the
	// snapshot was uploaded under: the addressable "snapshot from attempt
	// N" of a retried job (model.AttemptID pairs it with JobID). Zero for
	// records persisted before the field existed; additive, no migration.
	LeaseGeneration int64 `json:"lease_generation,omitempty"`
	// Attempts is the job's attempt counter when the snapshot was uploaded.
	// Additive; zero for legacy records.
	Attempts int `json:"attempts,omitempty"`
	// ExecutionSemantics is the execution-engine semantic version (see
	// ExecutionSemanticsVersion) of the run the snapshot was captured for,
	// stamped from the uploading job at commit, so a restored workspace
	// declares which engine semantics produced it. Additive; empty for
	// legacy records (exact replay warns and assumes current semantics).
	ExecutionSemantics string `json:"execution_semantics,omitempty"`
}
