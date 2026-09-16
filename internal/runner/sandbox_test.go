package runner

import (
	"encoding/json"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// TestPayloadSandboxRequirementsDecode verifies the runner decodes the
// sandbox requirements the effective policy JSON demands (additive fields
// alongside policy.Capabilities) and treats absent requirements as no-ops.
func TestPayloadSandboxRequirementsDecode(t *testing.T) {
	payload := buildPayload(t, payloadPipeline, "build")
	base := policy.DefaultTrustedCapabilities()
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var withSandbox map[string]any
	if err := json.Unmarshal(raw, &withSandbox); err != nil {
		t.Fatal(err)
	}
	withSandbox["rootless"] = true
	withSandbox["read_only_rootfs"] = true
	withSandbox["non_root"] = true
	payload.EffectivePolicy = mustJSON(t, withSandbox)

	req, err := payloadSandboxRequirements(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !req.Rootless || !req.ReadOnlyRootFS || !req.NonRoot {
		t.Fatalf("requirements = %+v, want all three flags (non_root included)", req)
	}

	// A legacy payload whose policy carries no sandbox fields decodes
	// cleanly with no requirements.
	payload.EffectivePolicy = mustJSON(t, policy.DefaultTrustedCapabilities())
	req, err = payloadSandboxRequirements(payload)
	if err != nil {
		t.Fatalf("legacy policy decode: %v", err)
	}
	if req.Rootless || req.ReadOnlyRootFS || req.NonRoot {
		t.Fatalf("legacy policy unexpectedly demands sandbox: %+v", req)
	}

	// Nil payload / nil policy are no-ops, not errors.
	if req, err = payloadSandboxRequirements(nil); err != nil || req.Rootless {
		t.Fatalf("nil payload: %+v %v", req, err)
	}
	payload.EffectivePolicy = nil
	if req, err = payloadSandboxRequirements(payload); err != nil || req.Rootless {
		t.Fatalf("nil policy: %+v %v", req, err)
	}
}

// TestApplyEffectiveSandboxStrengthensOnly verifies the handoff copies
// effective-policy requirements onto the compiled job and never weakens an
// explicit job-level request.
func TestApplyEffectiveSandboxStrengthensOnly(t *testing.T) {
	cj := &pipeline.CompiledJob{ID: "build", Job: pipeline.Job{}}
	applyEffectiveSandbox(cj, effectivePolicySandbox{Rootless: true, ReadOnlyRootFS: true})
	if !cj.Job.Sandbox.Rootless || !cj.Job.Sandbox.ReadOnlyRootFS {
		t.Fatalf("requirements not copied: %+v", cj.Job.Sandbox)
	}

	// An explicit job request stays set even when the policy demands nothing.
	cj = &pipeline.CompiledJob{ID: "build", Job: pipeline.Job{Sandbox: pipeline.Sandbox{Rootless: true}}}
	applyEffectiveSandbox(cj, effectivePolicySandbox{})
	if !cj.Job.Sandbox.Rootless {
		t.Fatal("explicit rootless request was weakened")
	}
}

// TestVerifyCompiledPayloadKeepsPolicyDecodingStrict ensures the extended
// sandbox decode does not disturb the existing strict capability round trip.
func TestVerifyCompiledPayloadKeepsPolicyDecodingStrict(t *testing.T) {
	spec, err := pipeline.Parse([]byte(payloadPipeline))
	if err != nil {
		t.Fatal(err)
	}
	payload := buildPayload(t, payloadPipeline, "build")
	_, caps, policyOK, err := verifyCompiledPayload(spec, payload, true)
	if err != nil || !policyOK || !caps.NativeExecution {
		t.Fatalf("capability round trip disturbed: caps=%+v policyOK=%t err=%v", caps, policyOK, err)
	}
}
