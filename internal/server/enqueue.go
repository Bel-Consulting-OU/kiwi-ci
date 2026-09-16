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

// applyUntrustedResourceCeilings sets the server-side resource ceilings on
// the compiled job of an UNTRUSTED run whenever the job declares no request
// of its own: the executor then always applies CPU/memory/PID limits to
// untrusted work, even for pipelines that never mention resources. Only
// fields the job's runtime backend can actually enforce are filled (see
// pipeline.ResourceCapabilities); trusted jobs and jobs with explicit
// requests are untouched.
func (s *Server) applyUntrustedResourceCeilings(cj pipeline.CompiledJob, trusted bool) pipeline.CompiledJob {
	if trusted {
		return cj
	}
	cpu, mem, _, pids := pipeline.ResourceCapabilities(cj.Job.Runtime)
	if cpu && cj.Job.Resources.CPU == 0 && s.UntrustedCPUCeiling > 0 {
		cj.Job.Resources.CPU = s.UntrustedCPUCeiling
	}
	if mem && cj.Job.Resources.Memory == 0 && s.UntrustedMemoryCeiling > 0 {
		cj.Job.Resources.Memory = pipeline.ByteSize(s.UntrustedMemoryCeiling)
	}
	if pids && cj.Job.Resources.PIDs == 0 && s.UntrustedPIDCeiling > 0 {
		cj.Job.Resources.PIDs = s.UntrustedPIDCeiling
	}
	return cj
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
