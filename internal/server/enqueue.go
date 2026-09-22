package server

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
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

// applyUntrustedResourceCeilings applies the server-side resource CEILINGS
// to the compiled job of an UNTRUSTED run: an explicit request in any
// dimension above the configured ceiling is REJECTED (never clamped — a
// silently reduced request would still be executable but misrepresented),
// and a dimension the job leaves unset is filled with the ceiling value so
// the executor always applies limits to untrusted work, even for pipelines
// that never mention resources. The offending field, the requested value and
// the ceiling travel in the returned admission error so the API can answer
// an opaque 4xx naming the field and both values.
//
// Only fields the job's runtime backend can actually enforce are filled (see
// pipeline.ResourceCapabilities), with one documented exception: the disk
// ceiling is filled for container jobs, whose backend enforces
// resources.disk as a hard workspace-content bound (tart/native disk and pid
// declarations are rejected by pipeline validation, so they are never
// filled). A ceiling of 0 disables that dimension entirely (no rejection, no
// fill).
//
// Trusted jobs are UNCONSTRAINED by these ceilings: they keep their declared
// resources exactly, including requests above every untrusted ceiling.
func (s *Server) applyUntrustedResourceCeilings(cj pipeline.CompiledJob, trusted bool) (pipeline.CompiledJob, error) {
	if trusted {
		return cj, nil
	}
	cpu, mem, _, pids := pipeline.ResourceCapabilities(cj.Job.Runtime)
	if err := s.checkUntrustedCeiling("cpu", cj.Job.Resources.CPU, s.UntrustedCPUCeiling); err != nil {
		return cj, err
	}
	if err := s.checkUntrustedCeiling("memory", float64(cj.Job.Resources.Memory), float64(s.UntrustedMemoryCeiling)); err != nil {
		return cj, err
	}
	if err := s.checkUntrustedCeiling("disk", float64(cj.Job.Resources.Disk), float64(s.UntrustedDiskCeiling)); err != nil {
		return cj, err
	}
	if err := s.checkUntrustedCeiling("pids", float64(cj.Job.Resources.PIDs), float64(s.UntrustedPIDCeiling)); err != nil {
		return cj, err
	}
	if cpu && cj.Job.Resources.CPU == 0 && s.UntrustedCPUCeiling > 0 {
		cj.Job.Resources.CPU = s.UntrustedCPUCeiling
	}
	if mem && cj.Job.Resources.Memory == 0 && s.UntrustedMemoryCeiling > 0 {
		cj.Job.Resources.Memory = pipeline.ByteSize(s.UntrustedMemoryCeiling)
	}
	if pids && cj.Job.Resources.PIDs == 0 && s.UntrustedPIDCeiling > 0 {
		cj.Job.Resources.PIDs = s.UntrustedPIDCeiling
	}
	if untrustedDiskBound(cj.Job.Runtime) && cj.Job.Resources.Disk == 0 && s.UntrustedDiskCeiling > 0 {
		cj.Job.Resources.Disk = pipeline.ByteSize(s.UntrustedDiskCeiling)
	}
	return cj, nil
}

// untrustedDiskBound reports whether the runtime's backend enforces
// resources.disk as a hard workspace bound. Only the container backend does
// (see internal/executor: workspaceMaxBytes/enforceWorkspaceBound); tart and
// native disk declarations are rejected by pipeline validation, so the
// untrusted disk ceiling is never stamped on them.
func untrustedDiskBound(runtime string) bool {
	return runtime == "container"
}

// checkUntrustedCeiling rejects one explicit untrusted resource request that
// exceeds its configured ceiling. A zero ceiling disables the dimension; a
// non-positive request is not an explicit request. field is the pipeline
// spelling (cpu/memory/disk/pids) and both values are reported so the client
// can correct the declaration.
func (s *Server) checkUntrustedCeiling(field string, requested, ceiling float64) error {
	if ceiling <= 0 || requested <= 0 || requested <= ceiling {
		return nil
	}
	return &admissionError{
		Status: http.StatusBadRequest,
		Reason: "untrusted_resource_ceiling_exceeded",
		Msg:    fmt.Sprintf("untrusted job resources.%s %s exceeds the ceiling %s", field, formatResourceValue(requested), formatResourceValue(ceiling)),
	}
}

// formatResourceValue renders a resource quantity without a trailing ".0" so
// the rejection message reads "4" instead of "4.000000" for whole numbers.
// The int64 conversion is guarded (integers beyond 2^53 are not exactly
// representable and fall back to the float rendering), so no value can
// overflow the conversion.
func formatResourceValue(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1<<53 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
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
// (payload-based; see internal/scheduler queueDeadlineFor), and the lease
// reservation reads ReservedResources — the job's own request plus
// ServiceEnvelopeRequest — so a job's declared services are charged to the
// runner too.
func applyCompiledJobFields(j *model.Job, cj pipeline.CompiledJob, now time.Time) {
	j.CPURequest, j.MemoryRequest, j.DiskRequest, j.PIDsRequest = jobResourceRequests(cj)
	j.QueueDeadline = jobQueueDeadline(cj, now)
	j.ServiceEnvelopeRequest = serviceEnvelopeRequest(cj)
}

// serviceEnvelopeRequest derives the aggregate service-container request of a
// compiled job through the executor's ONE fair-split planner
// (executor.ServiceEnvelopeRequest), so the aggregate the control plane
// reserves is exactly the aggregate the executor allocates — admission and
// execution can never disagree. The envelope is derived from the EFFECTIVE
// compiled job, i.e. after the untrusted ceilings have been applied, which is
// also what the runner executes (the signed CompiledJobPayload.EffectiveJob).
//
// A job without services gets the zero value (the reservation is then exactly
// its own request, the pre-envelope behavior). An oversubscribed envelope —
// the planner fails when a service's fair share rounds to zero — also gets
// the zero value: the executor fails that job closed before starting any
// container, so no service consumes host resources and reserving a partial
// sum would misstate the job. The envelope is stamped for trusted and
// untrusted jobs alike.
func serviceEnvelopeRequest(cj pipeline.CompiledJob) model.ResourceCapacity {
	if len(cj.Job.Services) == 0 {
		return model.ResourceCapacity{}
	}
	req, err := executor.ServiceEnvelopeRequest(cj.Job.Resources, cj.Job.Services)
	if err != nil {
		return model.ResourceCapacity{}
	}
	return model.ResourceCapacity{CPU: req.CPU, Memory: int64(req.Memory), PIDs: req.PIDs}
}
