package server

import (
	"time"

	"github.com/kiwici/kiwi/internal/model"
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
}

type Task struct {
	Job             model.Job `json:"job"`
	LeaseToken      string    `json:"lease_token"`
	LeaseGeneration int64     `json:"lease_generation"`
	LeaseExpiresAt  time.Time `json:"lease_expires_at"`
}

type RunnerInfo struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Labels   []string  `json:"labels,omitempty"`
	LastSeen time.Time `json:"last_seen"`
	Busy     bool      `json:"busy"`
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
