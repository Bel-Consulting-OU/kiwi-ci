package execution_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/execution"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// TestWorkspaceBoundBytesMirrorsExecutor pins the duplicated pure derivation
// against the executor's canonical implementation (the materializer cannot
// import executor, so the values must provably agree).
func TestWorkspaceBoundBytesMirrorsExecutor(t *testing.T) {
	if execution.DefaultUntrustedWorkspaceMaxBytes != executor.DefaultUntrustedWorkspaceMaxBytes {
		t.Fatalf("default untrusted bound = %d, want the executor's %d",
			execution.DefaultUntrustedWorkspaceMaxBytes, executor.DefaultUntrustedWorkspaceMaxBytes)
	}
	cases := []struct {
		declared  int64
		untrusted bool
		override  int64
	}{
		{0, false, 0}, {0, true, 0}, {0, true, 0}, {5 << 20, false, 0}, {5 << 20, true, 0},
		{0, true, 3 << 20}, {0, true, -1}, {-1, true, 0}, {1 << 40, false, 0},
	}
	for _, tc := range cases {
		want := executor.WorkspaceBoundBytes(tc.declared, tc.untrusted, tc.override)
		got := execution.WorkspaceBoundBytes(tc.declared, tc.untrusted, tc.override)
		if got != want {
			t.Fatalf("WorkspaceBoundBytes(%d,%t,%d) = %d, want %d", tc.declared, tc.untrusted, tc.override, got, want)
		}
	}
}

// buildExecution builds a coherent compiled job + payload for the digest
// tests (optional effective policy).
func buildExecution(t *testing.T, text string, effectivePolicy any) (pipeline.CompiledJob, *model.CompiledJobPayload) {
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
	cj := g.Jobs["build"]
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

// TestMaterializedCapsuleDigestClosesV1Gap is the finding-6 regression: two
// records with an IDENTICAL CompiledJobPayload (same v1 capsule digest) but
// different persisted/effective execution (disk envelope, trust floor,
// network, sandbox) produce DIFFERENT execution capsule digests.
func TestMaterializedCapsuleDigestClosesV1Gap(t *testing.T) {
	text := "version: 1\njobs:\n  build:\n    sandbox:\n      network: internet\n    steps:\n      - run: echo hi\n"
	cjA, payloadA := buildExecution(t, text, policy.DefaultTrustedCapabilities())
	cjB, payloadB := buildExecution(t, text, policy.DefaultTrustedCapabilities())

	v1A, err := provenance.CapsuleDigest(payloadA)
	if err != nil {
		t.Fatal(err)
	}
	v1B, err := provenance.CapsuleDigest(payloadB)
	if err != nil {
		t.Fatal(err)
	}
	if v1A != v1B {
		t.Fatalf("v1 capsule digests differ for identical payloads: %s vs %s", v1A, v1B)
	}

	plain := model.Job{Trusted: true}
	enveloped := model.Job{Trusted: true, CPURequest: 4, MemoryRequest: 8 << 30, DiskRequest: 16 << 30, PIDsRequest: 512,
		ServiceEnvelopeRequest: model.ResourceCapacity{CPU: 1, Memory: 1 << 30, PIDs: 64}}

	effPlain, err := execution.MaterializeEffectiveExecution(cjA, payloadA, plain, policy.Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	effEnvelope, err := execution.MaterializeEffectiveExecution(cjB, payloadB, enveloped, policy.Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	dPlain, err := execution.MaterializedCapsuleDigest(effPlain)
	if err != nil {
		t.Fatal(err)
	}
	dEnvelope, err := execution.MaterializedCapsuleDigest(effEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if dPlain == dEnvelope {
		t.Fatalf("execution capsule digest did not change with the resource envelope/trust overlay: %s", dPlain)
	}

	// Every execution-affecting dimension is inside the digest: network and
	// sandbox mutations of the SAME effective execution change it too.
	mutations := map[string]func(*execution.EffectiveExecution){
		"network": func(e *execution.EffectiveExecution) {
			e.Network = pipeline.NetworkPolicyNone
			e.CompiledJob.Job.Sandbox.Network = pipeline.NetworkPolicyNone
		},
		"sandbox": func(e *execution.EffectiveExecution) {
			e.Sandbox.Rootless = true
			e.CompiledJob.Job.Sandbox.Rootless = true
		},
		"resources": func(e *execution.EffectiveExecution) {
			e.Resources.CPU = 9
			e.CompiledJob.Job.Resources.CPU = 9
		},
		"workspace bound":  func(e *execution.EffectiveExecution) { e.WorkspaceMaxBytes++ },
		"quota limit":      func(e *execution.EffectiveExecution) { e.WorkspaceQuotaLimit++ },
		"trust":            func(e *execution.EffectiveExecution) { e.Trusted = false; e.Untrusted = true },
		"immutable images": func(e *execution.EffectiveExecution) { e.RequireImmutableImages = true },
		"service envelope": func(e *execution.EffectiveExecution) { e.ServiceEnvelope.CPU = 3 },
		"capabilities":     func(e *execution.EffectiveExecution) { e.Capabilities.Network = pipeline.NetworkPolicyNone },
	}
	for name, mutate := range mutations {
		changed := effPlain
		mutate(&changed)
		got, err := execution.MaterializedCapsuleDigest(changed)
		if err != nil {
			t.Fatalf("%s digest: %v", name, err)
		}
		if got == dPlain {
			t.Fatalf("%s mutation left the execution capsule digest unchanged", name)
		}
	}

	// Canonical: repeating the derivation yields the same digest.
	again, err := execution.MaterializedCapsuleDigest(effPlain)
	if err != nil || again != dPlain {
		t.Fatalf("digest not canonical: %s vs %s (%v)", again, dPlain, err)
	}
}

// TestExecutionCapsuleStatementTamperFailsVerification proves the v2 digest
// is inside the signed statement: a mismatch is a constraint failure, and
// rewriting the signed field invalidates the DSSE signature.
func TestExecutionCapsuleStatementTamperFailsVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("a", 64)
	st := provenance.ArtifactStatement(provenance.ArtifactInput{
		Name: "art", SHA256: strings.Repeat("b", 64), RunID: "run", JobID: "job",
		JobKey: "build", Runner: "runner", ExecutionCapsuleDigest: want,
	})
	env, err := provenance.Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	// Correct constraint verifies.
	if _, err := provenance.VerifyWith(raw, nil, provenance.VerifyOptions{TrustedKey: pub, ExecutionCapsuleDigest: want}); err != nil {
		t.Fatalf("verify with matching constraint: %v", err)
	}
	// Constraint mismatch is reported explicitly.
	if _, err := provenance.VerifyWith(raw, nil, provenance.VerifyOptions{TrustedKey: pub, ExecutionCapsuleDigest: strings.Repeat("c", 64)}); err == nil ||
		!strings.Contains(err.Error(), "execution capsule digest mismatch") {
		t.Fatalf("constraint mismatch = %v", err)
	}
	// Rewriting the signed field breaks the signature (it is part of the
	// signed payload, not an unsigned sidecar).
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var tampered map[string]any
	if err := json.Unmarshal(payload, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["executionCapsuleDigest"] = strings.Repeat("d", 64)
	newPayload, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = base64.StdEncoding.EncodeToString(newPayload)
	rawTampered, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provenance.VerifyWith(rawTampered, nil, provenance.VerifyOptions{TrustedKey: pub}); err == nil ||
		!strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered signed execution capsule digest verified: %v", err)
	}
}
