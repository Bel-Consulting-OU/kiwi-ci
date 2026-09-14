package runner

import (
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
func verifyCompiledPayload(spec *pipeline.Spec, p *model.CompiledJobPayload, trusted bool) (cj pipeline.CompiledJob, caps policy.Capabilities, policyOK bool, err error) {
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
