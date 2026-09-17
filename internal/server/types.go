package server

import (
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

type SubmitRun struct {
	RepoURL      string `json:"repo_url"`
	RepoFullName string `json:"repo_full_name,omitempty"`
	// RepoID is the canonical repository identity. It is never accepted
	// from client JSON: direct API submissions derive it at ingress from
	// repo_url (with repo_full_name REQUIRED to match that URL's repository
	// path), while internal ingresses (webhook handlers, schedules,
	// downstream children, reruns) set the derived or persisted identity
	// here.
	RepoID string `json:"-"`
	// PolicyRepoID is the canonical identity every authorization decision
	// uses: the BASE repository for a fork PR (RepoID is kept for
	// compatibility). Internal ingresses set it; it is never accepted from
	// client JSON.
	PolicyRepoID string `json:"-"`
	// CheckoutRepoURL is the clone URL the run's jobs check out (the fork
	// head URL for cross-repo PRs). Internal ingresses set it; it is never
	// accepted from client JSON.
	CheckoutRepoURL string `json:"-"`
	// identityBound marks a submission whose identity was resolved
	// server-side at an internal ingress (webhook, schedule, downstream
	// dispatch, rerun). Such submissions skip the direct-submission
	// repo_url/repo_full_name binding check, because a fork PR's base full
	// name legitimately differs from its head clone URL. It is never
	// accepted from client JSON.
	identityBound bool   `json:"-"`
	Ref           string `json:"ref"`
	SHA           string `json:"sha,omitempty"`
	Event         string `json:"event,omitempty"`
	Pipeline      string `json:"pipeline"`
	// Trusted is deliberately never accepted from client JSON: direct API
	// submissions are untrusted. Only forge webhook handlers and internal
	// reruns (which copy the previous run's trust) set it in Go code.
	Trusted      bool     `json:"-"`
	ChangedFiles []string `json:"changed_files,omitempty"`
	// ChangedFilesKnown marks the ChangedFiles list as the authoritative
	// forge-fetched diff: the enqueue persists it on every job so the
	// runner keeps a known-empty list empty instead of falling back to a
	// local git diff.
	ChangedFilesKnown bool              `json:"changed_files_known,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	// scheduleClaim, when set, claims the (schedule, nominal) occurrence
	// atomically with the enqueue (DB mode: inside InsertCompiledRun;
	// memory mode: under s.mu after the run is inserted). It is never
	// accepted from client JSON.
	ScheduleClaim *storage.ScheduleClaim `json:"-"`
	// DownstreamLaunch, when set, folds the downstream child launch claim
	// into the enqueue: the child run and the downstream link update
	// (ChildRunID + StableChildID) commit atomically. It is never accepted
	// from client JSON.
	DownstreamLaunch *storage.DownstreamLaunchClaim `json:"-"`
}

type Task struct {
	Job             model.Job `json:"job"`
	LeaseToken      string    `json:"lease_token"`
	LeaseGeneration int64     `json:"lease_generation"`
	LeaseExpiresAt  time.Time `json:"lease_expires_at"`
}

// RunnerInfo carries the registration fields validated server-side by
// validateRunnerRegistration before a runner record is accepted.
type RunnerInfo struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Labels   []string  `json:"labels,omitempty"`
	LastSeen time.Time `json:"last_seen"`
	Busy     bool      `json:"busy"`

	Region      string  `json:"region,omitempty"`
	Capacity    int     `json:"capacity,omitempty"`
	ProtocolMin int     `json:"protocol_min,omitempty"`
	ProtocolMax int     `json:"protocol_max,omitempty"`
	CostPerHour float64 `json:"cost_per_hour,omitempty"`
	PowerWatts  float64 `json:"power_watts,omitempty"`
}

type Heartbeat struct {
	RunnerID        string `json:"runner_id"`
	LeaseToken      string `json:"lease_token"`
	LeaseGeneration int64  `json:"lease_generation"`
}

type HeartbeatResponse struct {
	Cancel         bool      `json:"cancel"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

type LogLine struct {
	RunnerID        string `json:"runner_id"`
	LeaseToken      string `json:"lease_token"`
	LeaseGeneration int64  `json:"lease_generation"`
	JobKey          string `json:"job_key"`
	Step            string `json:"step"`
	Line            string `json:"line"`
}

type Complete struct {
	RunnerID        string            `json:"runner_id"`
	LeaseToken      string            `json:"lease_token"`
	LeaseGeneration int64             `json:"lease_generation"`
	Status          model.Status      `json:"status"`
	Error           string            `json:"error,omitempty"`
	Outputs         map[string]string `json:"outputs,omitempty"`
	Results         any               `json:"results,omitempty"`
}

// EnrollRequest asks the control plane to sign a runner's certificate
// request. The caller authenticates with the enrollment token or a
// single-use enrollment grant; CSR is the PEM certificate request base64
// (standard) encoded. Labels are the enrollment's requested runner
// metadata, advisory only: a grant with an allowed-label set permits the
// request only when every requested label is in that set, and the labels
// are discarded afterwards (scheduling labels come from the registration
// profile, never from enrollment). The CSR's identity fields are ignored:
// the server synthesizes the certificate identity from RunnerID.
type EnrollRequest struct {
	RunnerID string   `json:"runner_id"`
	CSR      string   `json:"csr"`
	Labels   []string `json:"labels,omitempty"`
}

// EnrollResponse carries the freshly issued runner certificate, the CA
// certificate that signed it, and the certificate lifetime. RunnerID is
// the server-synthesized identity bound into the certificate.
type EnrollResponse struct {
	RunnerID      string `json:"runner_id"`
	Certificate   string `json:"certificate"`
	CACertificate string `json:"ca_certificate"`
	TTLSeconds    int64  `json:"ttl_seconds"`
}
