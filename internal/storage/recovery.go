package storage

// Queue-timeout recovery helpers shared by the storage implementations and
// the scheduler (which delegates its exported QueueDeadlineFor here, so every
// lease/recovery path applies one queue-timeout rule).

import (
	"encoding/json"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Corruption reasons the emergency recovery transactions stamp when a job's
// persisted payload cannot be decoded. Malformed metadata may sacrifice the
// job, but it must never keep a runner active slot, a lease or a quota
// reservation: the reason states exactly what was done to the job and why the
// retry policy could not be honored (MaxInfraRetries lives in the payload and
// cannot be trusted, so the forced transition is TERMINAL failure, never a
// re-queue).
const (
	// CorruptLeaseRecoveryReason is the terminal error of an expired running
	// lease whose payload could not be decoded (the job is failed, the lease
	// columns cleared, and the runner slot plus running quota released).
	CorruptLeaseRecoveryReason = "failure: persisted job payload is corrupt; lease forcibly recovered"
	// CorruptQueueExpiryReason is the terminal error of a queue-timed-out job
	// whose payload could not be decoded (the job is cancelled and the queued
	// quota reservation released).
	CorruptQueueExpiryReason = "queue timeout: persisted job payload is corrupt; queued reservation forcibly released"
)

// QueueDeadlineFor returns the job's queue deadline: the persisted
// QueueDeadline field when present, otherwise the deadline derived from the
// compiled payload's queue_timeout (CreatedAt + timeout). Jobs without either
// have no deadline and never expire. The payload fallback keeps rows
// persisted before the QueueDeadline field existed expiring correctly.
func QueueDeadlineFor(j model.Job) *time.Time {
	if j.QueueDeadline != nil {
		return j.QueueDeadline
	}
	to := queueTimeoutFromPayload(j)
	if to <= 0 {
		return nil
	}
	dl := j.CreatedAt.Add(to)
	return &dl
}

// queueTimeoutFromPayload extracts the compiled job's queue_timeout from the
// stored compiled payload (CompiledJobPayload.EffectiveJob), so queue
// deadlines are payload-based and need no dedicated storage column.
func queueTimeoutFromPayload(j model.Job) time.Duration {
	if j.CompiledJobPayload == nil || j.CompiledJobPayload.EffectiveJob == nil {
		return 0
	}
	var b []byte
	switch v := j.CompiledJobPayload.EffectiveJob.(type) {
	case json.RawMessage:
		b = v
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		var err error
		if b, err = json.Marshal(v); err != nil {
			return 0
		}
	}
	var cj pipeline.CompiledJob
	if err := json.Unmarshal(b, &cj); err != nil {
		return 0
	}
	if cj.Job.QueueTimeout.Duration <= 0 {
		return 0
	}
	return cj.Job.QueueTimeout.Duration
}
