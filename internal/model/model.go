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
	ID               string            `json:"id"`
	Repo             string            `json:"repo,omitempty"`
	RepoFullName     string            `json:"repo_full_name,omitempty"`
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
}

// Job is the control-plane representation of one compiled job. It deliberately
// carries the pipeline text so a restarted control plane and its runners can
// recompile deterministically without an external store.
type Job struct {
	ID                     string                       `json:"id"`
	RunID                  string                       `json:"run_id"`
	Key                    string                       `json:"key"`
	BaseKey                string                       `json:"base_key,omitempty"`
	RepoURL                string                       `json:"repo_url"`
	Ref                    string                       `json:"ref,omitempty"`
	SHA                    string                       `json:"sha,omitempty"`
	Event                  string                       `json:"event,omitempty"`
	Condition              string                       `json:"condition,omitempty"`
	DependencyStatus       Status                       `json:"dependency_status"`
	Pipeline               string                       `json:"pipeline"`
	Trusted                bool                         `json:"trusted"`
	ChangedFiles           []string                     `json:"changed_files,omitempty"`
	Needs                  []string                     `json:"needs,omitempty"`
	RequiredLabels         []string                     `json:"required_labels,omitempty"`
	Network                string                       `json:"network,omitempty"`
	Environment            string                       `json:"environment,omitempty"`
	ApprovalRequired       bool                         `json:"approval_required,omitempty"`
	EnvironmentBranches    []string                     `json:"environment_branches,omitempty"`
	EnvironmentConcurrency int                          `json:"environment_concurrency,omitempty"`
	OIDCAllowed            bool                         `json:"oidc_allowed,omitempty"`
	OIDCAudiences          []string                     `json:"oidc_audiences,omitempty"`
	Status                 Status                       `json:"status"`
	Priority               int                          `json:"priority,omitempty"`
	MaxInfraRetries        int                          `json:"max_infra_retries,omitempty"`
	CreatedAt              time.Time                    `json:"created_at"`
	StartedAt              *time.Time                   `json:"started_at,omitempty"`
	FinishedAt             *time.Time                   `json:"finished_at,omitempty"`
	Error                  string                       `json:"error,omitempty"`
	Outputs                map[string]string            `json:"outputs,omitempty"`
	NeedsOutputs           map[string]map[string]string `json:"needs_outputs,omitempty"`
	Attempts               int                          `json:"attempts"`
	LeaseRunnerID          string                       `json:"lease_runner_id,omitempty"`
	// LeaseTokenHash is the HMAC-SHA256 of the raw lease token under the
	// server's lease key. The raw token is never persisted anywhere.
	LeaseTokenHash  []byte     `json:"lease_token_hash,omitempty"`
	LeaseGeneration int64      `json:"lease_generation,omitempty"`
	LeaseExpiresAt  *time.Time `json:"lease_expires_at,omitempty"`
	ApprovedBy      string     `json:"approved_by,omitempty"`
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
}

type TestResult struct {
	Name     string  `json:"name"`
	Class    string  `json:"class,omitempty"`
	Duration float64 `json:"duration,omitempty"`
	Passed   bool    `json:"passed"`
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
