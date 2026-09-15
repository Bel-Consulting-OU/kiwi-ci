package server

import (
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

type SubmitRun struct {
	RepoURL      string `json:"repo_url"`
	RepoFullName string `json:"repo_full_name,omitempty"`
	Ref          string `json:"ref"`
	SHA          string `json:"sha,omitempty"`
	Event        string `json:"event,omitempty"`
	Pipeline     string `json:"pipeline"`
	// Trusted is deliberately never accepted from client JSON: direct API
	// submissions are untrusted. Only forge webhook handlers and internal
	// reruns (which copy the previous run's trust) set it in Go code.
	Trusted      bool              `json:"-"`
	ChangedFiles []string          `json:"changed_files,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	// scheduleClaim, when set, claims the (schedule, nominal) occurrence
	// atomically with the enqueue (DB mode: inside InsertCompiledRun;
	// memory mode: under s.mu after the run is inserted). It is never
	// accepted from client JSON.
	ScheduleClaim *storage.ScheduleClaim `json:"-"`
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
// metadata; a label-bound grant requires every bound label to be present.
// The CSR's identity fields are ignored: the server synthesizes the
// certificate identity from RunnerID.
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
