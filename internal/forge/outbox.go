package forge

import (
	"encoding/json"
	"time"
)

// Outbox item kinds. Only the first two are dispatched today; the rest are
// reserved for later phases.
const (
	OutboxKindGitHubCheck  = "github_check"
	OutboxKindGitHubStatus = "github_status"
	OutboxKindDownstream   = "downstream"
	OutboxKindWebhookCall  = "webhook_callback"
)

// OutboxItem is one durable intent queued by the control plane. Dispatch is
// idempotent by ID.
type OutboxItem struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
}

// CheckPayload carries the arguments for a github_check intent.
type CheckPayload struct {
	RepoFullName string            `json:"repo_full_name"`
	SHA          string            `json:"sha"`
	Name         string            `json:"name"`
	Status       string            `json:"status"`
	Conclusion   string            `json:"conclusion,omitempty"`
	DetailsURL   string            `json:"details_url,omitempty"`
	Summary      string            `json:"summary,omitempty"`
	Annotations  []CheckAnnotation `json:"annotations,omitempty"`
}

// StatusPayload carries the arguments for the legacy github_status intent
// (commit status API).
type StatusPayload struct {
	RepoFullName string `json:"repo_full_name"`
	SHA          string `json:"sha"`
	State        string `json:"state"`
	Description  string `json:"description,omitempty"`
	Context      string `json:"context,omitempty"`
	TargetURL    string `json:"target_url,omitempty"`
}
