// Package v1 holds the public API representation types served by the
// control plane and the mapper from the internal model. The DTOs exist so
// redaction and shape decisions for the JSON API live in exactly one place
// instead of being re-implemented per handler.
//
// Field names intentionally mirror the historical redacted responses byte
// for byte (for example jobs keep a `pipeline` key that is always empty,
// and lease_token_hash is never present) so existing runner/app clients
// are unaffected.
package v1

import (
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// JobDTO is the redacted job shape returned by list/status endpoints.
// It is model.Job without the lease token hash; the pipeline text is
// deliberately emptied (kept as a key, matching the legacy response).
type JobDTO struct {
	ID                     string                       `json:"id"`
	RunID                  string                       `json:"run_id"`
	Key                    string                       `json:"key"`
	BaseKey                string                       `json:"base_key,omitempty"`
	RepoURL                string                       `json:"repo_url"`
	Ref                    string                       `json:"ref,omitempty"`
	SHA                    string                       `json:"sha,omitempty"`
	Event                  string                       `json:"event,omitempty"`
	Condition              string                       `json:"condition,omitempty"`
	DependencyStatus       model.Status                 `json:"dependency_status"`
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
	DeclaredSecrets        []string                     `json:"declared_secrets,omitempty"`
	Status                 model.Status                 `json:"status"`
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
	LeaseGeneration        int64                        `json:"lease_generation,omitempty"`
	LeaseExpiresAt         *time.Time                   `json:"lease_expires_at,omitempty"`
	ApprovedBy             string                       `json:"approved_by,omitempty"`
	QueueReason            string                       `json:"queue_reason,omitempty"`
	PlacementRegions       []string                     `json:"placement_regions,omitempty"`
	ComponentDigest        string                       `json:"component_digest,omitempty"`
	CompiledJobPayload     *model.CompiledJobPayload    `json:"compiled_job_payload,omitempty"`
	WaitingSince           *time.Time                   `json:"waiting_since,omitempty"`
}

// RunDTO is the run shape returned by list/status endpoints. It mirrors
// model.Run exactly (runs are not redacted today).
type RunDTO struct {
	ID               string            `json:"id"`
	Repo             string            `json:"repo,omitempty"`
	RepoFullName     string            `json:"repo_full_name,omitempty"`
	Ref              string            `json:"ref,omitempty"`
	SHA              string            `json:"sha,omitempty"`
	Event            string            `json:"event,omitempty"`
	Status           model.Status      `json:"status"`
	Trusted          bool              `json:"trusted,omitempty"`
	ConcurrencyGroup string            `json:"concurrency_group,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	StartedAt        *time.Time        `json:"started_at,omitempty"`
	FinishedAt       *time.Time        `json:"finished_at,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// RunnerDTO mirrors model.Runner.
type RunnerDTO struct {
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

	Disabled bool `json:"disabled,omitempty"`
	Draining bool `json:"draining,omitempty"`

	Region              string   `json:"region,omitempty"`
	Version             string   `json:"version,omitempty"`
	ProtocolMin         int      `json:"protocol_min,omitempty"`
	ProtocolMax         int      `json:"protocol_max,omitempty"`
	Capabilities        []string `json:"capabilities,omitempty"`
	AllowedRepositories []string `json:"allowed_repositories,omitempty"`

	CostPerHour float64 `json:"cost_per_hour,omitempty"`
	PowerWatts  float64 `json:"power_watts,omitempty"`

	CertSerial string     `json:"cert_serial,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// ArtifactDTO mirrors the redacted artifact record returned by listing:
// server-local filesystem paths are always stripped.
type ArtifactDTO struct {
	ID               string     `json:"id"`
	RunID            string     `json:"run_id"`
	JobID            string     `json:"job_id"`
	JobKey           string     `json:"job_key"`
	Name             string     `json:"name"`
	Size             int64      `json:"size"`
	SHA256           string     `json:"sha256"`
	ContentType      string     `json:"content_type,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	ProvenanceSHA256 string     `json:"provenance_sha256,omitempty"`
	LeaseGeneration  int64      `json:"lease_generation,omitempty"`
	SBOMSHA256       string     `json:"sbom_sha256,omitempty"`
	SigstoreSHA256   string     `json:"sigstore_sha256,omitempty"`
}

// JobDTOFrom maps a model.Job into the redacted public DTO.
func JobDTOFrom(j model.Job) JobDTO {
	return JobDTO{
		ID: j.ID, RunID: j.RunID, Key: j.Key, BaseKey: j.BaseKey, RepoURL: j.RepoURL,
		Ref: j.Ref, SHA: j.SHA, Event: j.Event, Condition: j.Condition,
		DependencyStatus: j.DependencyStatus, Pipeline: "",
		Trusted: j.Trusted, ChangedFiles: j.ChangedFiles, Needs: j.Needs,
		RequiredLabels: j.RequiredLabels, Network: j.Network, Environment: j.Environment,
		ApprovalRequired: j.ApprovalRequired, EnvironmentBranches: j.EnvironmentBranches,
		EnvironmentConcurrency: j.EnvironmentConcurrency, OIDCAllowed: j.OIDCAllowed,
		OIDCAudiences: j.OIDCAudiences, DeclaredSecrets: j.DeclaredSecrets,
		Status: j.Status, Priority: j.Priority, MaxInfraRetries: j.MaxInfraRetries,
		CreatedAt: time.Time(j.CreatedAt), StartedAt: jsonTimePtr(j.StartedAt),
		FinishedAt: jsonTimePtr(j.FinishedAt), Error: j.Error, Outputs: j.Outputs,
		NeedsOutputs: j.NeedsOutputs, Attempts: j.Attempts, LeaseRunnerID: j.LeaseRunnerID,
		LeaseGeneration: j.LeaseGeneration, LeaseExpiresAt: jsonTimePtr(j.LeaseExpiresAt),
		ApprovedBy: j.ApprovedBy, QueueReason: j.QueueReason,
		PlacementRegions: j.PlacementRegions, ComponentDigest: j.ComponentDigest,
		CompiledJobPayload: j.CompiledJobPayload, WaitingSince: jsonTimePtr(j.WaitingSince),
	}
}

// RunDTOFrom maps a model.Run into the public DTO.
func RunDTOFrom(r model.Run) RunDTO {
	return RunDTO{
		ID: r.ID, Repo: r.Repo, RepoFullName: r.RepoFullName, Ref: r.Ref, SHA: r.SHA,
		Event: r.Event, Status: r.Status, Trusted: r.Trusted,
		ConcurrencyGroup: r.ConcurrencyGroup, CreatedAt: time.Time(r.CreatedAt),
		StartedAt: jsonTimePtr(r.StartedAt), FinishedAt: jsonTimePtr(r.FinishedAt),
		Metadata: r.Metadata,
	}
}

// RunnerDTOFrom maps a model.Runner into the public DTO.
func RunnerDTOFrom(rn model.Runner) RunnerDTO {
	return RunnerDTO{
		ID: rn.ID, Name: rn.Name, Labels: rn.Labels, Metadata: rn.Metadata,
		Capacity: rn.Capacity, Registered: time.Time(rn.Registered), Completed: rn.Completed,
		Failed: rn.Failed, LastSeen: time.Time(rn.LastSeen), ActiveJobs: rn.ActiveJobs,
		CurrentJob: rn.CurrentJob, Busy: rn.Busy, Disabled: rn.Disabled, Draining: rn.Draining,
		Region: rn.Region, Version: rn.Version, ProtocolMin: rn.ProtocolMin,
		ProtocolMax: rn.ProtocolMax, Capabilities: rn.Capabilities,
		AllowedRepositories: rn.AllowedRepositories, CostPerHour: rn.CostPerHour,
		PowerWatts: rn.PowerWatts, CertSerial: rn.CertSerial, RevokedAt: jsonTimePtr(rn.RevokedAt),
	}
}

// ArtifactDTOFrom maps a model.ArtifactRecord into the redacted public DTO.
func ArtifactDTOFrom(a model.ArtifactRecord) ArtifactDTO {
	return ArtifactDTO{
		ID: a.ID, RunID: a.RunID, JobID: a.JobID, JobKey: a.JobKey, Name: a.Name,
		Size: a.Size, SHA256: a.SHA256, ContentType: a.ContentType,
		CreatedAt: time.Time(a.CreatedAt), ExpiresAt: jsonTimePtr(a.ExpiresAt),
		ProvenanceSHA256: a.ProvenanceSHA256, LeaseGeneration: a.LeaseGeneration,
		SBOMSHA256: a.SBOMSHA256, SigstoreSHA256: a.SigstoreSHA256,
	}
}

// jsonTimePtr deep-copies a time pointer so the DTO never aliases caller
// state.
func jsonTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}
