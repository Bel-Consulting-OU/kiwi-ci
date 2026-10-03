package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// verifyCompiledPayload checks the enqueue-time compilation record the
// control plane attached to the task and returns the effective compiled job
// the runner must execute. The pipeline digest is recomputed from the
// already-trusted job pipeline the runner parsed itself; the job digest is
// recomputed by round-tripping EffectiveJob through pipeline.CompiledJob
// and re-marshalling (struct field order makes this deterministic). The
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
	if p.SchemaVersion != 1 {
		return cj, caps, false, fmt.Errorf("compiled payload: unsupported schema version %d (want 1)", p.SchemaVersion)
	}
	wantPipeline, err := pipeline.PipelineDigest(spec)
	if err != nil {
		return cj, caps, false, fmt.Errorf("compiled payload: pipeline digest: %w", err)
	}
	if wantPipeline != p.PipelineDigest {
		return cj, caps, false, fmt.Errorf("compiled payload digest mismatch: pipeline digest %q does not match %q", p.PipelineDigest, wantPipeline)
	}
	raw, err := json.Marshal(p.EffectiveJob)
	if err != nil {
		return cj, caps, false, fmt.Errorf("compiled payload: encode effective job: %w", err)
	}
	if err := json.Unmarshal(raw, &cj); err != nil {
		return cj, caps, false, fmt.Errorf("compiled payload: decode effective job: %w", err)
	}
	cjJSON, err := json.Marshal(cj)
	if err != nil {
		return cj, caps, false, fmt.Errorf("compiled payload: re-encode effective job: %w", err)
	}
	sum := sha256.Sum256(cjJSON)
	if got := hex.EncodeToString(sum[:]); got != p.JobDigest {
		return cj, caps, false, fmt.Errorf("compiled payload digest mismatch: job digest %q does not match %q", p.JobDigest, got)
	}
	if payloadLocalBindingCheck {
		// The job digest above only proves the payload is internally consistent.
		// Bind the payload to a LOCAL recompilation of the digest-verified
		// pipeline spec: a malicious control plane could otherwise serve a benign
		// spec (digest passes) alongside an arbitrary compiled job (steps, image,
		// sandbox/network, env) whose self-hash it also controls.
		recompiled, cerr := pipeline.Compile(spec)
		if cerr != nil {
			return cj, caps, false, fmt.Errorf("compiled payload: recompile pipeline: %w", cerr)
		}
		local, ok := recompiled.Jobs[key]
		if !ok {
			return cj, caps, false, fmt.Errorf("compiled payload: pipeline has no job %q", key)
		}
		localRaw, err := json.Marshal(local)
		if err != nil {
			return cj, caps, false, fmt.Errorf("compiled payload: encode local job: %w", err)
		}
		var localNorm pipeline.CompiledJob
		if err := json.Unmarshal(localRaw, &localNorm); err != nil {
			return cj, caps, false, fmt.Errorf("compiled payload: decode local job: %w", err)
		}
		localJSON, err := json.Marshal(localNorm)
		if err != nil {
			return cj, caps, false, fmt.Errorf("compiled payload: re-encode local job: %w", err)
		}
		if !bytes.Equal(localJSON, cjJSON) {
			return cj, caps, false, fmt.Errorf("compiled payload does not match the digest-verified pipeline's local compilation")
		}
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
