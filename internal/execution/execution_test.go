package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

const execPipeline = "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"

// compileForExecution compiles text and returns the build job plus a coherent
// compiled payload record (optional effective policy).
func compileForExecution(t *testing.T, text string, effectivePolicy any) (pipeline.CompiledJob, *model.CompiledJobPayload) {
	t.Helper()
	spec, err := pipeline.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	pd, err := pipeline.PipelineDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	cj, ok := g.Jobs["build"]
	if !ok {
		t.Fatal("no build job")
	}
	cjJSON, err := json.Marshal(cj)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cjJSON)
	p := &model.CompiledJobPayload{
		SchemaVersion: 1, CompilerVersion: "test",
		PipelineDigest: pd, JobDigest: hex.EncodeToString(sum[:]),
		EffectiveJob: json.RawMessage(cjJSON),
	}
	if effectivePolicy != nil {
		b, err := json.Marshal(effectivePolicy)
		if err != nil {
			t.Fatal(err)
		}
		p.EffectivePolicy = json.RawMessage(b)
	}
	return cj, p
}

// TestEffectivePolicyCapabilitiesFloor pins the shared decode+floor contract
// the runner, replay and the provenance path all rely on.
func TestEffectivePolicyCapabilitiesFloor(t *testing.T) {
	_, payload := compileForExecution(t, execPipeline, policy.DefaultTrustedCapabilities())
	if _, ok, err := EffectivePolicyCapabilities(payload, true); err != nil || !ok {
		t.Fatalf("trusted decode = ok %t err %v", ok, err)
	}
	// A trusted policy is above the untrusted floor: refused, never narrowed.
	if _, _, err := EffectivePolicyCapabilities(payload, false); err == nil {
		t.Fatal("permissive policy accepted for an untrusted job")
	}
	// The exact floor passes and is preserved.
	_, floorPayload := compileForExecution(t, execPipeline, policy.DefaultUntrustedCapabilities())
	caps, ok, err := EffectivePolicyCapabilities(floorPayload, false)
	if err != nil || !ok {
		t.Fatalf("floor decode = ok %t err %v", ok, err)
	}
	if !caps.RequireRootless || !caps.RequireNonRoot || caps.Network != pipeline.NetworkPolicyNone {
		t.Fatalf("floor capabilities = %+v", caps)
	}
	// No policy at all is not an error; the caller keeps baseline admission.
	noPolicy := *floorPayload
	noPolicy.EffectivePolicy = nil
	if _, ok, err := EffectivePolicyCapabilities(&noPolicy, false); err != nil || ok {
		t.Fatalf("no-policy decode = ok %t err %v", ok, err)
	}
}

// TestMaterializeUntrustedFloor proves the untrusted derivation: network
// floor, sandbox floor, immutable images, mandatory workspace bound and the
// persisted service envelope.
func TestMaterializeUntrustedFloor(t *testing.T) {
	cj, payload := compileForExecution(t, execPipeline, policy.DefaultUntrustedCapabilities())
	caps, _, err := EffectivePolicyCapabilities(payload, false)
	if err != nil {
		t.Fatal(err)
	}
	persisted := model.Job{Trusted: false, ServiceEnvelopeRequest: model.ResourceCapacity{CPU: 1, Memory: 1 << 30, PIDs: 16}}
	eff, err := MaterializeEffectiveExecution(cj, payload, persisted, caps)
	if err != nil {
		t.Fatal(err)
	}
	if !eff.Untrusted || !eff.RequireImmutableImages {
		t.Fatalf("trust floor = untrusted %t immutable %t", eff.Untrusted, eff.RequireImmutableImages)
	}
	if eff.Network != pipeline.NetworkPolicyNone || eff.CompiledJob.Job.Sandbox.Network != pipeline.NetworkPolicyNone {
		t.Fatalf("effective network = %v / job %v, want none", eff.Network, eff.CompiledJob.Job.Sandbox.Network)
	}
	if !eff.Sandbox.Rootless || !eff.Sandbox.ReadOnlyRootFS || !eff.Sandbox.NonRoot {
		t.Fatalf("sandbox floor not applied: %+v", eff.Sandbox)
	}
	if eff.WorkspaceMaxBytes != DefaultUntrustedWorkspaceMaxBytes {
		t.Fatalf("workspace bound = %d, want the untrusted default %d", eff.WorkspaceMaxBytes, DefaultUntrustedWorkspaceMaxBytes)
	}
	if eff.WorkspaceQuotaLimit != DefaultUntrustedWorkspaceMaxBytes {
		t.Fatalf("quota limit = %d, want the untrusted default", eff.WorkspaceQuotaLimit)
	}
	if eff.ServiceEnvelope != persisted.ServiceEnvelopeRequest {
		t.Fatalf("service envelope = %+v, want the persisted %+v", eff.ServiceEnvelope, persisted.ServiceEnvelopeRequest)
	}
}

// TestMaterializePersistedOverlayAndLegacyNetwork pins the persisted resource
// overlay and the legacy (nil payload) authoritative network.
func TestMaterializePersistedOverlayAndLegacyNetwork(t *testing.T) {
	cj, payload := compileForExecution(t, execPipeline, nil)
	persisted := model.Job{
		Trusted: true, Network: "none",
		CPURequest: 2, MemoryRequest: 3 << 30, DiskRequest: 4 << 30, PIDsRequest: 128,
	}
	eff, err := MaterializeEffectiveExecution(cj, payload, persisted, policy.Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	if eff.PolicyPresent {
		t.Fatal("nil effective policy reported present")
	}
	if eff.Resources.CPU != 2 || int64(eff.Resources.Memory) != 3<<30 || int64(eff.Resources.Disk) != 4<<30 || eff.Resources.PIDs != 128 {
		t.Fatalf("persisted overlay = %+v", eff.Resources)
	}
	if eff.WorkspaceMaxBytes != 4<<30 || eff.DeclaredDiskBytes != 4<<30 {
		t.Fatalf("workspace bound = %d declared %d, want the persisted disk", eff.WorkspaceMaxBytes, eff.DeclaredDiskBytes)
	}

	legacy, err := MaterializeEffectiveExecution(cj, nil, persisted, policy.Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.CompiledJob.Job.Network != "none" {
		t.Fatalf("legacy network = %q, want the persisted %q", legacy.CompiledJob.Job.Network, "none")
	}
	if legacy.PolicyPresent {
		t.Fatal("legacy record reported a policy")
	}
}
