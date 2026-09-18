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
