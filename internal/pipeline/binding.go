package pipeline

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// VerifyCompiledJobBinding checks the enqueue-time compilation record
// (model.CompiledJobPayload) against the pipeline spec it claims to describe
// and returns the effective compiled job the record carries. It is the ONE
// digest/binding verifier shared by the distributed runner (which executes
// the payload after verifying it against the signed job pipeline) and the
// exact replay path (which executes the persisted pipeline's recorded job),
// so both agree byte for byte on what a valid binding is.
//
// The checks are pure and deterministic:
//   - the payload schema version must be the supported one (1);
//   - the recomputed PipelineDigest(spec) must equal payload.PipelineDigest;
//   - payload.EffectiveJob must round-trip through CompiledJob and its
//     canonical JSON must hash to payload.JobDigest;
//   - EffectiveJob must normalize-equal a LOCAL Compile(spec) of the
//     digest-verified spec for key. The self-referential digest alone only
//     proves the payload is internally consistent; this final check binds it
//     to the pipeline the caller actually parsed, so a digest-verified spec
//     can never be paired with an unrelated effective job whose hash the
//     payload also controls.
//
// A nil payload is an error: callers that allow a legacy payload-less job
// must check for nil before calling. Policy capabilities are NOT part of this
// function: the runner keeps its trust/policy-floor checks, and replay has no
// policy floor to apply.
func VerifyCompiledJobBinding(spec *Spec, key string, p *model.CompiledJobPayload) (CompiledJob, error) {
	return verifyCompiledJobBinding(spec, key, p, true)
}

// VerifyCompiledJobDigests verifies only the schema and digest bindings of a
// compiled payload (pipeline digest and job digest) and skips the local
// recompilation equality. The runner uses it exclusively for its
// payloadLocalBindingCheck test seam; production verification must call
// VerifyCompiledJobBinding so the payload is bound to the parsed spec.
func VerifyCompiledJobDigests(spec *Spec, key string, p *model.CompiledJobPayload) (CompiledJob, error) {
	return verifyCompiledJobBinding(spec, key, p, false)
}

func verifyCompiledJobBinding(spec *Spec, key string, p *model.CompiledJobPayload, bindLocal bool) (CompiledJob, error) {
	var cj CompiledJob
	if p == nil {
		return cj, errors.New("compiled payload: missing")
	}
	if p.SchemaVersion != 1 {
		return cj, fmt.Errorf("compiled payload: unsupported schema version %d (want 1)", p.SchemaVersion)
	}
	wantPipeline, err := PipelineDigest(spec)
	if err != nil {
		return cj, fmt.Errorf("compiled payload: pipeline digest: %w", err)
	}
	if wantPipeline != p.PipelineDigest {
		return cj, fmt.Errorf("compiled payload digest mismatch: pipeline digest %q does not match %q", p.PipelineDigest, wantPipeline)
	}
	raw, err := json.Marshal(p.EffectiveJob)
	if err != nil {
		return cj, fmt.Errorf("compiled payload: encode effective job: %w", err)
	}
	if err := json.Unmarshal(raw, &cj); err != nil {
		return cj, fmt.Errorf("compiled payload: decode effective job: %w", err)
	}
	cjJSON, err := json.Marshal(cj)
	if err != nil {
		return cj, fmt.Errorf("compiled payload: re-encode effective job: %w", err)
	}
	sum := sha256.Sum256(cjJSON)
	if got := hex.EncodeToString(sum[:]); got != p.JobDigest {
		return cj, fmt.Errorf("compiled payload digest mismatch: job digest %q does not match %q", p.JobDigest, got)
	}
	if !bindLocal {
		return cj, nil
	}
	recompiled, cerr := Compile(spec)
	if cerr != nil {
		return cj, fmt.Errorf("compiled payload: recompile pipeline: %w", cerr)
	}
	local, ok := recompiled.Jobs[key]
	if !ok {
		return cj, fmt.Errorf("compiled payload: pipeline has no job %q", key)
	}
	localRaw, err := json.Marshal(local)
	if err != nil {
		return cj, fmt.Errorf("compiled payload: encode local job: %w", err)
	}
	var localNorm CompiledJob
	if err := json.Unmarshal(localRaw, &localNorm); err != nil {
		return cj, fmt.Errorf("compiled payload: decode local job: %w", err)
	}
	localJSON, err := json.Marshal(localNorm)
	if err != nil {
		return cj, fmt.Errorf("compiled payload: re-encode local job: %w", err)
	}
	if !bytes.Equal(localJSON, cjJSON) {
		return cj, errors.New("compiled payload does not match the digest-verified pipeline's local compilation")
	}
	return cj, nil
}
