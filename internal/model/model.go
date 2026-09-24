package model

import "time"

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
}

// Job is the control-plane representation of one compiled job. It deliberately
// carries the pipeline text so a restarted control plane and its runners can
// recompile deterministically without an external store.
type Job struct {
	ID      string `json:"id"`
	RunID   string `json:"run_id"`
	Key     string `json:"key"`
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
	OIDCAllowed            bool     `json:"oidc_allowed,omitempty"`
	OIDCAudiences          []string `json:"oidc_audiences,omitempty"`
	// DeclaredSecrets is the deduplicated union of the run's global secrets
	// and every step secret of this job, compiled at enqueue time. It is the
	// per-step scoping allowlist the control plane enforces when a runner
	// requests a secret value.
	DeclaredSecrets []string                     `json:"declared_secrets,omitempty"`
	Status          Status                       `json:"status"`
	Priority        int                          `json:"priority,omitempty"`
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
	ActiveJobs []string          `json:"active_jobs,omitempty"`
	CurrentJob string            `json:"current_job,omitempty"`
	Busy       bool              `json:"busy"`

	// ResourceCapacity is the runner's effective resource capacity (CPU,
	// memory, disk, PIDs). It is overlaid from the runner's linked profile
	// at registration and at lease time (ResolveRunnerProfile); a runner
	// without a linked profile uses its registration snapshot, and a zero
	// dimension is UNCONSTRAINED. Additive: deployments that predate it
	// keep the count-only behavior. The effective values are persisted with
	// the registration payload and re-resolved live from the profile on
	// every lease.
	ResourceCapacity ResourceCapacity `json:"resource_capacity,omitempty"`

	// Admission control.
	Disabled bool `json:"disabled,omitempty"`
	Draining bool `json:"draining,omitempty"`

	// Descriptive and protocol metadata reported at registration.
	Region              string   `json:"region,omitempty"`
	Version             string   `json:"version,omitempty"`
	ProtocolMin         int      `json:"protocol_min,omitempty"`
	ProtocolMax         int      `json:"protocol_max,omitempty"`
	Capabilities        []string `json:"capabilities,omitempty"`
	AllowedRepositories []string `json:"allowed_repositories,omitempty"`

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
}

type LogEntry struct {
	Seq       int64     `json:"seq"`
	RunID     string    `json:"run_id"`
	JobID     string    `json:"job_id"`
	JobKey    string    `json:"job_key"`
	Step      string    `json:"step"`
	Line      string    `json:"line"`
	CreatedAt time.Time `json:"created_at"`
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

type JobResult struct {
	JobID      string            `json:"job_id"`
	Status     Status            `json:"status"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Duration   time.Duration     `json:"duration"`
	Attempts   int               `json:"attempts"`
	Error      string            `json:"error,omitempty"`
	Outputs    map[string]string `json:"outputs,omitempty"`
}

// CompletionReceipt deduplicates runner completion requests so a retried
// complete() after a lost response is idempotent for the same generation.
// ResultHash is the SHA-256 of the canonicalized completion payload.
type CompletionReceipt struct {
	JobID      string `json:"job_id"`
	Generation int64  `json:"generation"`
	RunnerID   string `json:"runner_id"`
	ResultHash string `json:"result_hash"`
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
}

// SnapshotEntry is one regular file in a workspace snapshot manifest.
type SnapshotEntry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

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
}
