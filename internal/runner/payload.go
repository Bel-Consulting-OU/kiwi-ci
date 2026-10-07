package runner

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// verifyCompiledPayload checks the enqueue-time compilation record the
// control plane attached to the task and returns the effective compiled job
// the runner must execute. The schema, pipeline-digest, job-digest and
// local-recompilation binding checks are delegated to the shared
// pipeline.VerifyCompiledJobBinding verifier — the same code the exact replay
// path runs — so a payload the runner accepts can never be rejected (or
// silently differ) on replay, and vice versa. What stays runner-local is the
// TRUST policy: the effective capabilities and the untrusted floor. The
// returned caps are the effective policy capabilities to re-check admission
// against; policyOK is false when the payload carries no policy (legacy
// compiler) and the caller keeps only the baseline admission check.
//
// Any mismatch refuses execution: the runner never runs bytes the control
// plane did not compile deterministically.
// payloadLocalBindingCheck gates the local-recompilation binding. It is a
// test seam for fixtures that deliberately construct a mutated compiled job
// to exercise downstream executor logic; production runs with binding ON.
var payloadLocalBindingCheck = true

func verifyCompiledPayload(spec *pipeline.Spec, key string, p *model.CompiledJobPayload, trusted bool) (cj pipeline.CompiledJob, caps policy.Capabilities, policyOK bool, err error) {
	if p == nil {
		return cj, caps, false, nil
	}
	if payloadLocalBindingCheck {
		cj, err = pipeline.VerifyCompiledJobBinding(spec, key, p)
	} else {
		// Seam: a fixture deliberately serves a mutated effective job; keep
		// the digest binding but skip the local-recompilation equality.
		cj, err = pipeline.VerifyCompiledJobDigests(spec, key, p)
	}
	if err != nil {
		return cj, caps, false, err
	}
	if p.EffectivePolicy == nil {
		return cj, caps, false, nil
	}
	policyRaw, err := json.Marshal(p.EffectivePolicy)
	if err != nil {
		return cj, caps, false, fmt.Errorf("compiled payload: encode effective policy: %w", err)
	}
	if err := json.Unmarshal(policyRaw, &caps); err != nil {
		return cj, caps, false, fmt.Errorf("compiled payload: decode effective policy: %w", err)
	}
	if !trusted {
		// The untrusted hard floor must hold: an effective policy that is
		// not already a subset of the floor is a mismatch, not something
		// the runner silently narrows.
		eff := caps.Effective(false)
		if !reflect.DeepEqual(eff, caps) {
			return cj, caps, false, fmt.Errorf("compiled payload policy exceeds the untrusted capability floor")
		}
		caps = eff
	}
	return cj, caps, true, nil
}

// effectivePolicySandbox is the runner-side extension of the compiled
// payload's effective policy: policy.Capabilities carries the capability
// intersection, and the daemon-level sandbox requirements (rootless,
// read_only_rootfs, non_root) ride the same policy JSON as additive fields
// emitted by the control plane's policy compilation. Absent fields decode
// as false, so legacy payloads that carry no sandbox requirements are
// no-ops.
type effectivePolicySandbox struct {
	Rootless       bool `json:"rootless"`
	ReadOnlyRootFS bool `json:"read_only_rootfs"`
	// NonRoot demands the job run as an unprivileged user; the executor's
	// container backend enforces it (rootful: --user=65534:65534; rootless:
	// userns-mapped container UID 0, documented in pipeline.Sandbox) and
	// refuses runtimes that cannot enforce it.
	NonRoot bool `json:"non_root"`
}

// payloadSandboxRequirements decodes the sandbox requirements the effective
// policy demands. A nil payload or a payload without an effective policy
// yields no requirements (the local legacy compile path is authoritative
// for those).
func payloadSandboxRequirements(p *model.CompiledJobPayload) (effectivePolicySandbox, error) {
	var out effectivePolicySandbox
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

// applyEffectiveSandbox copies the effective policy's sandbox requirements
// into the compiled job before execution. Requirements can only strengthen:
// a job that did not request rootless gains the requirement when the
// effective policy demands it, and an explicit job-level request is never
// weakened.
func applyEffectiveSandbox(cj *pipeline.CompiledJob, req effectivePolicySandbox) {
	cj.Job.Sandbox.Rootless = cj.Job.Sandbox.Rootless || req.Rootless
	cj.Job.Sandbox.ReadOnlyRootFS = cj.Job.Sandbox.ReadOnlyRootFS || req.ReadOnlyRootFS
	cj.Job.Sandbox.NonRoot = cj.Job.Sandbox.NonRoot || req.NonRoot
}
