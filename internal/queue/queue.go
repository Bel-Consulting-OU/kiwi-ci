// Package queue defines the reason codes the control plane attaches to
// queued jobs to explain why they have not been leased. The codes are the
// contract between the scheduler, the explain engine, and the UI.
package queue

// ReasonCode identifies why a queued job is waiting.
type ReasonCode string

const (
	// None means no reason has been recorded.
	None ReasonCode = ""
	// NoCompatibleRunner means no registered runner satisfies the job's
	// required labels.
	NoCompatibleRunner ReasonCode = "NO_COMPATIBLE_RUNNER"
	// RunnerCapacity means every compatible runner is at capacity.
	RunnerCapacity ReasonCode = "RUNNER_CAPACITY"
	// RegionUnavailable means no runner in a required region is usable.
	RegionUnavailable ReasonCode = "REGION_UNAVAILABLE"
	// WaitingDependency means at least one upstream job has not completed
	// (or did not succeed and the condition blocks).
	WaitingDependency ReasonCode = "WAITING_DEPENDENCY"
	// WaitingApproval means the job needs an environment approval before
	// it can run.
	WaitingApproval ReasonCode = "WAITING_APPROVAL"
	// EnvironmentLocked means the job's environment concurrency limit is
	// already reached.
	EnvironmentLocked ReasonCode = "ENVIRONMENT_LOCKED"
	// RepoQuota means the repository's concurrency/queue quota is reached.
	RepoQuota ReasonCode = "REPO_QUOTA"
	// TeamQuota means the owning team's quota is reached.
	TeamQuota ReasonCode = "TEAM_QUOTA"
	// ConcurrencyGroup means the run's concurrency group is already active
	// and the job must wait its turn.
	ConcurrencyGroup ReasonCode = "CONCURRENCY_GROUP"
)

// Reason is a code plus a human-readable message.
type QueueReason struct {
	Code    ReasonCode `json:"code"`
	Message string     `json:"message,omitempty"`
}

// New builds a QueueReason with a default message when msg is empty.
func New(code ReasonCode, msg string) QueueReason {
	if msg == "" {
		msg = defaultMessage(code)
	}
	return QueueReason{Code: code, Message: msg}
}

// String renders the reason as "CODE: message" (or just the code).
func (q QueueReason) String() string {
	if q.Message == "" {
		return string(q.Code)
	}
	return string(q.Code) + ": " + q.Message
}

func defaultMessage(code ReasonCode) string {
	switch code {
	case NoCompatibleRunner:
		return "no registered runner satisfies the job's required labels"
	case RunnerCapacity:
		return "all compatible runners are at capacity"
	case RegionUnavailable:
		return "no runner in a required region is available"
	case WaitingDependency:
		return "waiting for upstream jobs to complete"
	case WaitingApproval:
		return "waiting for environment approval"
	case EnvironmentLocked:
		return "environment concurrency limit reached"
	case RepoQuota:
		return "repository quota reached"
	case TeamQuota:
		return "team quota reached"
	case ConcurrencyGroup:
		return "concurrency group is already active"
	default:
		return "waiting to be scheduled"
	}
}
