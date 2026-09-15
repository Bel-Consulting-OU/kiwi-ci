package server

import (
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// jobResourceRequests maps the compiled job's pipeline resources onto the
// additive model.Job request fields (cpu_request, memory_request,
// disk_request, pids_request) persisted in the job payload, so scheduling
// and backend enforcement can read them without recompiling. The compiler
// already parsed and range-validated the Resources at admission.
func jobResourceRequests(cj pipeline.CompiledJob) (cpu float64, memory, disk int64, pids int) {
	r := cj.Job.Resources
	return r.CPU, int64(r.Memory), int64(r.Disk), r.PIDs
}

// jobQueueDeadline computes the queue deadline for a compiled job whose
// queue_timeout is set: enqueue time plus the timeout. Nil means no
// timeout and therefore no expiry.
func jobQueueDeadline(cj pipeline.CompiledJob, now time.Time) *time.Time {
	if cj.Job.QueueTimeout.Duration <= 0 {
		return nil
	}
	dl := now.Add(cj.Job.QueueTimeout.Duration)
	return &dl
}

// applyCompiledJobFields populates the additive resource-request and queue
// deadline fields of a model.Job from its effective compiled job at
// enqueue. The scheduler's queue-timeout expiry reads QueueDeadline
// (payload-based; see internal/scheduler queueDeadlineFor).
func applyCompiledJobFields(j *model.Job, cj pipeline.CompiledJob, now time.Time) {
	j.CPURequest, j.MemoryRequest, j.DiskRequest, j.PIDsRequest = jobResourceRequests(cj)
	j.QueueDeadline = jobQueueDeadline(cj, now)
}
