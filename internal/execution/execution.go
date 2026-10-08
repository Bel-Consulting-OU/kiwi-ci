// Package execution materializes the effective execution of a verified
// compiled job: the single shared implementation of every execution-affecting
// value the distributed runner derives after payload verification (effective
// network, persisted resource requests, service envelope, sandbox
// requirements, workspace bounds). The runner maps the result onto
// executor.Options; exact replay maps the same result so a replayed job can
// never run under weaker network, sandbox or resource restrictions than the
// distributed run the control plane recorded.
//
// The package is deliberately free of runner/executor dependencies: its
// inputs are persisted control-plane records (model.Job, the compiled payload)
// and pure pipeline/policy values, so it can be imported by replay, the
// artifact provenance path and tests without an import cycle.
package execution

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// DefaultUntrustedWorkspaceMaxBytes is the mandatory workspace disk budget for
// an untrusted container job whose pipeline does not declare resources.disk.
// It mirrors executor.DefaultUntrustedWorkspaceMaxBytes (10 GiB); the two are
// pinned equal by a cross-package test. The materializer cannot import the
// executor package (it must stay importable from executor), so the value is
// duplicated here with the executor's constant as the reference.
const DefaultUntrustedWorkspaceMaxBytes int64 = 10 << 30

// EffectiveExecution is the complete set of execution-affecting values
// derived for one job. Every field is a pure function of the verified
// compiled job, the compiled payload and the persisted job record.
type EffectiveExecution struct {
	// CompiledJob is the verified compiled job with every effective overlay
	// applied: the effective network policy, the persisted resource requests
	// and the effective-policy sandbox requirements. This is the job the
	// executor must run.
	CompiledJob pipeline.CompiledJob

	// Trusted/Untrusted are the persisted trust state; Untrusted is exactly
	// !Trusted and is carried explicitly because every backend and option
	// keys off it.
	Trusted   bool
	Untrusted bool

	// PolicyPresent reports whether the payload carried an effective policy
	// (and its ceiling therefore participated in the network intersection).
	PolicyPresent bool
	// Capabilities is the effective capability set the caller supplied
	// (already trust-floor applied by the caller's verification step).
	Capabilities policy.Capabilities

	// RequestedNetwork is the network the job itself asked for (before the
	// policy ceiling intersection); Network is the effective one written into
	// CompiledJob.Job.Sandbox.Network.
	RequestedNetwork pipeline.NetworkPolicy
	Network          pipeline.NetworkPolicy

	// Sandbox and Resources are the effective values after overlays.
	Sandbox   pipeline.Sandbox
	Resources pipeline.Resources

	// DeclaredDiskBytes is the effective resources.disk in bytes (persisted
	// override first, then the compiled declaration).
	DeclaredDiskBytes int64
	// WorkspaceMaxBytes is the workspace content bound handed to the executor.
	WorkspaceMaxBytes int64
	// WorkspaceQuotaLimit is the hard OS-level bound the runner installs
	// BEFORE the workspace is populated (0 = none requested).
	WorkspaceQuotaLimit int64

	// ServiceEnvelope is the persisted aggregate service request the
	// scheduler reserved for this job (zero when the job has no services).
	ServiceEnvelope model.ResourceCapacity

	// RequireImmutableImages is the untrusted floor: unpinned images are
	// rejected for untrusted jobs.
	RequireImmutableImages bool
}

// MaterializeEffectiveExecution derives the effective execution of one job
// from its verified compiled job, the (optional) persisted compilation
// payload and the persisted job record.
//
// It is behavior-identical to the distributed runner's post-verification
// materialization: the effective network is the job's request intersected with
// the payload policy's ceiling (an explicit job request above the ceiling is
// refused), the persisted relational resource requests are re-applied over
// the verified payload, the effective policy's sandbox requirements are ORed
// onto the job's own requirements, the workspace bound follows the persisted
// disk request with the mandatory untrusted default, and the untrusted floor
// toggles image immutability.
//
// The caller is responsible for digest/binding verification
// (pipeline.VerifyCompiledJobBinding) and for applying the trust floor to
// declared (execution.EffectivePolicyCapabilities does both the decode and the
// floor). A nil payload selects the legacy path: the persisted job's network
// field is authoritative and no policy/ceiling can be applied.
func MaterializeEffectiveExecution(verified pipeline.CompiledJob, payload *model.CompiledJobPayload, persisted model.Job, declared policy.Capabilities) (EffectiveExecution, error) {
	e := EffectiveExecution{
		Trusted:                persisted.Trusted,
		Untrusted:              !persisted.Trusted,
		PolicyPresent:          payload != nil && payload.EffectivePolicy != nil,
		Capabilities:           declared,
		RequireImmutableImages: !persisted.Trusted,
		ServiceEnvelope:        persisted.ServiceEnvelopeRequest,
	}
	cj := verified
	if payload != nil {
		// The requested network is the job's own pre-intersection request; it
		// must be captured before ApplyEffectiveNetwork overwrites
		// sandbox.network with the effective value.
		e.RequestedNetwork = RequestedNetworkPolicy(cj.Job)
		if e.PolicyPresent {
			if err := ApplyEffectiveNetwork(&cj, declared); err != nil {
				return EffectiveExecution{}, fmt.Errorf("compiled payload network admission: %w", err)
			}
		}
		// The signed payload records the spec-deterministic compile; the
		// server fills untrusted zero-declared requests with its configured
		// ceilings only in the PERSISTED relational fields (the payload
		// cannot carry them: the runner cannot reproduce operator
		// configuration). Re-apply the persisted values so execution bounds
		// and the scheduler's reservations agree.
		ApplyPersistedResourceRequests(&cj, persisted)
	} else {
		// Legacy path: the control plane did not attach a compilation
		// record, so the job-level network field is authoritative.
		cj.Job.Network = persisted.Network
		e.RequestedNetwork = RequestedNetworkPolicy(cj.Job)
	}
	reqs, err := PayloadSandboxRequirements(payload)
	if err != nil {
		return EffectiveExecution{}, fmt.Errorf("compiled payload sandbox requirements: %w", err)
	}
	ApplyEffectiveSandbox(&cj, reqs)

	e.CompiledJob = cj
	e.Network = cj.Job.Sandbox.Network
	e.Sandbox = cj.Job.Sandbox
	e.Resources = cj.Job.Resources

	declaredDisk := WorkspaceMaxBytesForResources(cj.Job.Resources)
	if persisted.DiskRequest > 0 {
		declaredDisk = persisted.DiskRequest
	}
	e.DeclaredDiskBytes = declaredDisk
	e.WorkspaceMaxBytes = WorkspaceBoundBytes(declaredDisk, e.Untrusted, DefaultUntrustedWorkspaceMaxBytes)
	e.WorkspaceQuotaLimit = WorkspaceBoundBytes(persisted.DiskRequest, e.Untrusted, DefaultUntrustedWorkspaceMaxBytes)
	return e, nil
}

// PolicySandbox is the runner-side extension of the compiled payload's
// effective policy: policy.Capabilities carries the capability intersection,
// and the daemon-level sandbox requirements (rootless, read_only_rootfs,
// non_root) ride the same policy JSON as additive fields emitted by the
// control plane's policy compilation. Absent fields decode as false, so
// legacy payloads that carry no sandbox requirements are no-ops.
type PolicySandbox struct {
	Rootless       bool `json:"rootless"`
	ReadOnlyRootFS bool `json:"read_only_rootfs"`
	// NonRoot demands the job run as an unprivileged user; the executor's
	// container backend enforces it (rootful: --user=65534:65534; rootless:
	// userns-mapped container UID 0, documented in pipeline.Sandbox) and
	// refuses runtimes that cannot enforce it.
	NonRoot bool `json:"non_root"`
}

// PayloadSandboxRequirements decodes the sandbox requirements the effective
// policy demands. A nil payload or a payload without an effective policy
// yields no requirements (the local legacy compile path is authoritative for
// those). The re-encode step matches the verification path byte for byte, so
// a policy value that fails to round-trip fails here too (never silently
// dropping a requirement).
func PayloadSandboxRequirements(p *model.CompiledJobPayload) (PolicySandbox, error) {
	var out PolicySandbox
	if p == nil || p.EffectivePolicy == nil {
		return out, nil
	}
	raw, err := json.Marshal(p.EffectivePolicy)
	if err != nil {
		return out, fmt.Errorf("encode effective policy: %w", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("decode effective policy: %w", err)
	}
	return out, nil
}

// ApplyEffectiveSandbox copies the effective policy's sandbox requirements
// into the compiled job before execution. Requirements can only strengthen:
// a job that did not request rootless gains the requirement when the
// effective policy demands it, and an explicit job-level request is never
// weakened.
func ApplyEffectiveSandbox(cj *pipeline.CompiledJob, req PolicySandbox) {
	cj.Job.Sandbox.Rootless = cj.Job.Sandbox.Rootless || req.Rootless
	cj.Job.Sandbox.ReadOnlyRootFS = cj.Job.Sandbox.ReadOnlyRootFS || req.ReadOnlyRootFS
	cj.Job.Sandbox.NonRoot = cj.Job.Sandbox.NonRoot || req.NonRoot
}

// EffectivePolicyCapabilities decodes the compiled payload's effective policy
// into a capability set and applies the trust floor: an untrusted job whose
// recorded policy is not already a subset of the untrusted floor is a
// mismatch (never silently narrowed). policyOK is false when the payload
// carries no policy (legacy compiler). This is the exact decoding and floor
// logic the distributed runner's payload verification applies, shared so
// exact replay and the artifact provenance path derive identical
// capabilities.
func EffectivePolicyCapabilities(p *model.CompiledJobPayload, trusted bool) (caps policy.Capabilities, policyOK bool, err error) {
	if p == nil || p.EffectivePolicy == nil {
		return caps, false, nil
	}
	policyRaw, err := json.Marshal(p.EffectivePolicy)
	if err != nil {
		return caps, false, fmt.Errorf("compiled payload: encode effective policy: %w", err)
	}
	if err := json.Unmarshal(policyRaw, &caps); err != nil {
		return caps, false, fmt.Errorf("compiled payload: decode effective policy: %w", err)
	}
	if !trusted {
		// The untrusted hard floor must hold: an effective policy that is
		// not already a subset of the floor is a mismatch, not something
		// the runner silently narrows.
		eff := caps.Effective(false)
		if !reflect.DeepEqual(eff, caps) {
			return caps, false, fmt.Errorf("compiled payload policy exceeds the untrusted capability floor")
		}
		caps = eff
	}
	return caps, true, nil
}

// ApplyEffectiveNetwork computes the minimal network policy for a payload
// compiled job: the job's own request (sandbox.network, or network "none")
// intersected with the payload's effective policy ceiling. A request that
// exceeds the ceiling is refused; a default request (no explicit egress
// declaration) inherits the ceiling. The result is written into the
// compiled job's sandbox.network, which the executor backend derives
// isolation from.
func ApplyEffectiveNetwork(cj *pipeline.CompiledJob, caps policy.Capabilities) error {
	requested := RequestedNetworkPolicy(cj.Job)
	ceiling := caps.Network
	if ceiling == pipeline.NetworkPolicyDefault {
		ceiling = pipeline.NetworkPolicyInternet
	}
	if requested != pipeline.NetworkPolicyDefault && NetworkPolicyStrength(requested) > NetworkPolicyStrength(ceiling) {
		return fmt.Errorf("job requests network %s which exceeds the compiled policy ceiling %s", NetworkPolicyName(requested), NetworkPolicyName(ceiling))
	}
	effective := pipeline.NetworkPolicyDefault
	if NetworkPolicyStrength(requested) < NetworkPolicyStrength(ceiling) {
		effective = requested
	} else if ceiling != pipeline.NetworkPolicyInternet {
		effective = ceiling
	}
	if effective != pipeline.NetworkPolicyDefault {
		cj.Job.Sandbox.Network = effective
	}
	return nil
}

// ApplyPersistedResourceRequests overlays the persisted relational request
// fields onto the verified compiled job. The payload records the
// spec-deterministic compile (untrusted zero-declared requests are NOT
// filled there, because the fill depends on operator ceilings the runner
// cannot reproduce); the persisted fields carry the values the scheduler
// reserved, so execution bounds and reservations stay identical.
func ApplyPersistedResourceRequests(cj *pipeline.CompiledJob, j model.Job) {
	if j.CPURequest > 0 {
		cj.Job.Resources.CPU = j.CPURequest
	}
	if j.MemoryRequest > 0 {
		cj.Job.Resources.Memory = pipeline.ByteSize(j.MemoryRequest)
	}
	if j.DiskRequest > 0 {
		cj.Job.Resources.Disk = pipeline.ByteSize(j.DiskRequest)
	}
	if j.PIDsRequest > 0 {
		cj.Job.Resources.PIDs = j.PIDsRequest
	}
}

// RequestedNetworkPolicy mirrors the policy engine's derivation of the
// network a job requests: an explicit sandbox.network declaration,
// NetworkPolicyNone for network "none", and NetworkPolicyDefault otherwise.
func RequestedNetworkPolicy(j pipeline.Job) pipeline.NetworkPolicy {
	if j.Network == "none" {
		return pipeline.NetworkPolicyNone
	}
	return j.Sandbox.Network
}

// NetworkPolicyStrength orders network policies for least-privilege
// comparison: None < ServicesOnly < Internet, with Default compared as
// Internet.
func NetworkPolicyStrength(p pipeline.NetworkPolicy) int {
	switch p {
	case pipeline.NetworkPolicyNone:
		return 0
	case pipeline.NetworkPolicyServicesOnly:
		return 1
	default:
		return 2
	}
}

// NetworkPolicyName renders a network policy for diagnostics.
func NetworkPolicyName(p pipeline.NetworkPolicy) string {
	switch p {
	case pipeline.NetworkPolicyNone:
		return "none"
	case pipeline.NetworkPolicyServicesOnly:
		return "services-only"
	case pipeline.NetworkPolicyInternet:
		return "internet"
	default:
		return "default"
	}
}

// WorkspaceMaxBytesForResources converts a job's declared resources.disk
// request into the workspace bound handed to the executor. The unit is bytes:
// pipeline.ByteSize is the pipeline decoder's canonical byte count ("2Gi" is
// 2<<30 because the binary suffixes Ki/Gi/Ti are 1024-based; a plain integer
// is bytes), so the value only needs widening to int64, never re-parsing. An
// undeclared disk (zero) yields zero, the documented default: no workspace
// bound is derived and pipelines without a disk declaration keep their
// previous behavior.
func WorkspaceMaxBytesForResources(res pipeline.Resources) int64 {
	if res.Disk <= 0 {
		return 0
	}
	return int64(res.Disk)
}

// WorkspaceBoundBytes derives the workspace content bound for one job with
// the single shared precedence:
//
//  1. a declared resources.disk request (any job), then
//  2. for an untrusted job, the per-executor override when set, otherwise
//     DefaultUntrustedWorkspaceMaxBytes, then
//  3. trusted jobs without a declaration: zero (unbounded), the documented
//     historical default.
//
// It is the pure twin of executor.WorkspaceBoundBytes; a cross-package test
// pins the two tables equal.
func WorkspaceBoundBytes(declaredDisk int64, untrusted bool, untrustedDefault int64) int64 {
	if declaredDisk > 0 {
		return declaredDisk
	}
	if untrusted {
		if untrustedDefault > 0 {
			return untrustedDefault
		}
		return DefaultUntrustedWorkspaceMaxBytes
	}
	return 0
}
