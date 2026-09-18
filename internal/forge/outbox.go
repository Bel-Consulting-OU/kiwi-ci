package forge

import (
	"encoding/json"
	"time"
)

// Outbox item kinds. Only the first two are dispatched today; the rest are
// reserved for later phases.
const (
	OutboxKindGitHubCheck  = "github_check"
	OutboxKindGitLabCheck  = "gitlab_check"
	OutboxKindForgejoCheck = "forgejo_check"
	OutboxKindGitHubStatus = "github_status"
	OutboxKindDownstream   = "downstream"
	OutboxKindWebhookCall  = "webhook_callback"
)

// OutboxItem is one durable intent queued by the control plane. Dispatch is
// idempotent by ID.
//
// LogicalKey/StateVersion are set for versioned forge-check intents: the
// stable logical identity of one remote check plus the monotonic rank of the
// logical state carried by this intent (queued=1, in_progress=2,
// completed=3). They mirror the durable outbox columns (migration 0018) and
// drive supersede and the dispatcher's durable version guard.
type OutboxItem struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	Payload      json.RawMessage `json:"payload"`
	CreatedAt    time.Time       `json:"created_at"`
	LogicalKey   string          `json:"logical_key,omitempty"`
	StateVersion int64           `json:"state_version,omitempty"`
}

// CheckPayload carries the arguments for a forge check intent. ForgeKind
// records which forge the run belongs to so dispatch can never route one
// forge's run to another's API. LogicalKey/StateVersion carry the delivery
// identity INSIDE the payload as well, so a replayed or operator-inspected
// row is self-describing.
type CheckPayload struct {
	RunID        string            `json:"run_id,omitempty"`
	ForgeKind    string            `json:"forge_kind,omitempty"`
	ForgeHost    string            `json:"forge_host,omitempty"`
	RepoFullName string            `json:"repo_full_name"`
	SHA          string            `json:"sha"`
	Name         string            `json:"name"`
	Status       string            `json:"status"`
	Conclusion   string            `json:"conclusion,omitempty"`
	DetailsURL   string            `json:"details_url,omitempty"`
	Summary      string            `json:"summary,omitempty"`
	Annotations  []CheckAnnotation `json:"annotations,omitempty"`
	LogicalKey   string            `json:"logical_key,omitempty"`
	StateVersion int64             `json:"state_version,omitempty"`
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
