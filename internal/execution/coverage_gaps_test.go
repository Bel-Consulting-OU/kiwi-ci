package execution

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// TestNetworkPolicyNameAndStrength pins the ordering table the effective
// network derivation compares on, including the unknown-value fallbacks.
func TestNetworkPolicyNameAndStrength(t *testing.T) {
	cases := []struct {
		policy   pipeline.NetworkPolicy
		name     string
		strength int
	}{
		{pipeline.NetworkPolicyNone, "none", 0},
		{pipeline.NetworkPolicyServicesOnly, "services-only", 1},
		{pipeline.NetworkPolicyInternet, "internet", 2},
		{pipeline.NetworkPolicyDefault, "default", 2},
		{pipeline.NetworkPolicy(99), "default", 2},
	}
	for _, tc := range cases {
		if got := NetworkPolicyName(tc.policy); got != tc.name {
			t.Errorf("NetworkPolicyName(%d) = %q, want %q", tc.policy, got, tc.name)
		}
		if got := NetworkPolicyStrength(tc.policy); got != tc.strength {
			t.Errorf("NetworkPolicyStrength(%d) = %d, want %d", tc.policy, got, tc.strength)
		}
	}
}

// TestApplyEffectiveNetworkStrengthensAndRefuses covers the three outcomes the
// intersection can have: a weaker request is kept, an equal non-internet
// ceiling is kept, and a request above the ceiling is refused.
func TestApplyEffectiveNetworkStrengthensAndRefuses(t *testing.T) {
	weaker := pipeline.CompiledJob{Job: pipeline.Job{Sandbox: pipeline.Sandbox{Network: pipeline.NetworkPolicyServicesOnly}}}
	if err := ApplyEffectiveNetwork(&weaker, policy.Capabilities{Network: pipeline.NetworkPolicyInternet}); err != nil {
		t.Fatalf("weaker request refused: %v", err)
	}
	if weaker.Job.Sandbox.Network != pipeline.NetworkPolicyServicesOnly {
		t.Fatalf("effective network = %d, want the weaker request services-only", weaker.Job.Sandbox.Network)
	}

	equal := pipeline.CompiledJob{Job: pipeline.Job{Sandbox: pipeline.Sandbox{Network: pipeline.NetworkPolicyServicesOnly}}}
	if err := ApplyEffectiveNetwork(&equal, policy.Capabilities{Network: pipeline.NetworkPolicyServicesOnly}); err != nil {
		t.Fatalf("equal request refused: %v", err)
	}
	if equal.Job.Sandbox.Network != pipeline.NetworkPolicyServicesOnly {
		t.Fatalf("effective network = %d, want the equal ceiling", equal.Job.Sandbox.Network)
	}

	over := pipeline.CompiledJob{Job: pipeline.Job{Sandbox: pipeline.Sandbox{Network: pipeline.NetworkPolicyInternet}}}
	err := ApplyEffectiveNetwork(&over, policy.Capabilities{Network: pipeline.NetworkPolicyNone})
	if err == nil || !strings.Contains(err.Error(), "exceeds the compiled policy ceiling") {
		t.Fatalf("internet above a none ceiling = %v, want the explicit refusal", err)
	}
}

// TestPayloadPolicyDecodeFailures proves malformed effective policies are
// reported, never silently treated as absent, by both decoders and by the
// materializer.
func TestPayloadPolicyDecodeFailures(t *testing.T) {
	invalid := &model.CompiledJobPayload{EffectivePolicy: json.RawMessage("{")}
	if _, err := PayloadSandboxRequirements(invalid); err == nil {
		t.Fatal("invalid policy JSON decoded by PayloadSandboxRequirements")
	}
	if _, _, err := EffectivePolicyCapabilities(invalid, true); err == nil {
		t.Fatal("invalid policy JSON decoded by EffectivePolicyCapabilities")
	}

	wrongShape := &model.CompiledJobPayload{EffectivePolicy: json.RawMessage(`"not-an-object"`)}
	if _, err := PayloadSandboxRequirements(wrongShape); err == nil {
		t.Fatal("wrong-shape policy decoded by PayloadSandboxRequirements")
	}
	if _, _, err := EffectivePolicyCapabilities(wrongShape, false); err == nil {
		t.Fatal("wrong-shape policy decoded by EffectivePolicyCapabilities")
	}

	cj, _ := compileForExecution(t, execPipeline, nil)
	if _, err := MaterializeEffectiveExecution(cj, wrongShape, model.Job{Trusted: true}, policy.Capabilities{}); err == nil {
		t.Fatal("materializer accepted a malformed effective policy")
	}
}

// TestMaterializeRefusesNetworkAboveCeiling covers the admission error path:
// a job asking for internet under a none ceiling must fail materialization.
func TestMaterializeRefusesNetworkAboveCeiling(t *testing.T) {
	text := "version: 1\njobs:\n  build:\n    sandbox:\n      network: internet\n    steps:\n      - run: echo hi\n"
	cj, payload := compileForExecution(t, text, policy.DefaultUntrustedCapabilities())
	caps, _, err := EffectivePolicyCapabilities(payload, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeEffectiveExecution(cj, payload, model.Job{Trusted: false}, caps); err == nil ||
		!strings.Contains(err.Error(), "network admission") {
		t.Fatalf("internet request under an untrusted ceiling = %v, want the admission refusal", err)
	}
}

// TestMaterializedCapsuleDigestMarshalFailure pins the canonicalization error
// path: a value that cannot be JSON-encoded is reported, never hashed.
func TestMaterializedCapsuleDigestMarshalFailure(t *testing.T) {
	e := EffectiveExecution{CompiledJob: pipeline.CompiledJob{Job: pipeline.Job{Resources: pipeline.Resources{CPU: math.NaN()}}}}
	if _, err := MaterializedCapsuleDigest(e); err == nil || !strings.Contains(err.Error(), "canonicalize") {
		t.Fatalf("NaN resource CPU digest = %v, want the canonicalization error", err)
	}
}
