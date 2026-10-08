package runner

import (
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/execution"
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
// TRUST policy seam (payloadLocalBindingCheck); the capability decode and the
// untrusted floor are the shared execution.EffectivePolicyCapabilities, which
// exact replay and the artifact provenance path run too. policyOK is false
// when the payload carries no policy (legacy compiler) and the caller keeps
// only the baseline admission check.
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
	caps, policyOK, err = execution.EffectivePolicyCapabilities(p, trusted)
	if err != nil {
		return cj, caps, false, err
	}
	return cj, caps, policyOK, nil
}

// effectivePolicySandbox and the payloadSandboxRequirements/applyEffectiveSandbox
// helpers are thin runner-side aliases of the shared execution package, kept so
// the runner keeps its package-local seam surface; the implementation (and the
// exact decode semantics the distributed runner and replay share) lives in
// internal/execution.
type effectivePolicySandbox = execution.PolicySandbox

// payloadSandboxRequirements decodes the sandbox requirements the effective
// policy demands. A nil payload or a payload without an effective policy
// yields no requirements (the local legacy compile path is authoritative
// for those).
func payloadSandboxRequirements(p *model.CompiledJobPayload) (effectivePolicySandbox, error) {
	return execution.PayloadSandboxRequirements(p)
}

// applyEffectiveSandbox copies the effective policy's sandbox requirements
// into the compiled job before execution. Requirements can only strengthen.
func applyEffectiveSandbox(cj *pipeline.CompiledJob, req effectivePolicySandbox) {
	execution.ApplyEffectiveSandbox(cj, req)
}
