package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

const payloadPipeline = "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"

// buildPayload compiles the pipeline the way the control plane does and
// returns the payload record for the given job key.
func buildPayload(t *testing.T, text, key string) *model.CompiledJobPayload {
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
	cj, ok := g.Jobs[key]
	if !ok {
		t.Fatalf("no compiled job %q", key)
	}
	cjJSON, err := json.Marshal(cj)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cjJSON)
	policyJSON, err := json.Marshal(policy.DefaultTrustedCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	return &model.CompiledJobPayload{
		SchemaVersion:   1,
		CompilerVersion: "test",
		PipelineDigest:  pd,
		JobDigest:       hex.EncodeToString(sum[:]),
		EffectiveJob:    json.RawMessage(cjJSON),
		EffectivePolicy: json.RawMessage(policyJSON),
	}
}

func TestVerifyCompiledPayloadMatching(t *testing.T) {
	spec, err := pipeline.Parse([]byte(payloadPipeline))
	if err != nil {
		t.Fatal(err)
	}
	payload := buildPayload(t, payloadPipeline, "build")
	cj, caps, policyOK, err := verifyCompiledPayload(spec, "build", payload, true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cj.ID != "build" || cj.BaseID != "build" {
		t.Fatalf("effective job = %q/%q", cj.ID, cj.BaseID)
	}
	if !policyOK {
		t.Fatal("policy not reported present")
	}
	if !caps.NativeExecution {
		t.Fatal("trusted caps lost in round trip")
	}
}

func TestVerifyCompiledPayloadTampered(t *testing.T) {
	spec, err := pipeline.Parse([]byte(payloadPipeline))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("pipeline digest", func(t *testing.T) {
		payload := buildPayload(t, payloadPipeline, "build")
		payload.PipelineDigest = strings.Repeat("0", 64)
		_, _, _, err := verifyCompiledPayload(spec, "build", payload, true)
		if err == nil || !strings.Contains(err.Error(), "compiled payload digest mismatch") {
			t.Fatalf("tampered pipeline digest accepted: %v", err)
		}
	})
	t.Run("job digest", func(t *testing.T) {
		payload := buildPayload(t, payloadPipeline, "build")
		payload.JobDigest = strings.Repeat("1", 64)
		_, _, _, err := verifyCompiledPayload(spec, "build", payload, true)
		if err == nil || !strings.Contains(err.Error(), "compiled payload digest mismatch") {
			t.Fatalf("tampered job digest accepted: %v", err)
		}
	})
	t.Run("schema version", func(t *testing.T) {
		payload := buildPayload(t, payloadPipeline, "build")
		payload.SchemaVersion = 2
		_, _, _, err := verifyCompiledPayload(spec, "build", payload, true)
		if err == nil || !strings.Contains(err.Error(), "schema version") {
			t.Fatalf("unknown schema version accepted: %v", err)
		}
	})
}

func TestVerifyCompiledPayloadUntrustedPolicyFloor(t *testing.T) {
	spec, err := pipeline.Parse([]byte(payloadPipeline))
	if err != nil {
		t.Fatal(err)
	}
	payload := buildPayload(t, payloadPipeline, "build")
	// Trusted capabilities exceed the untrusted floor (native execution).
	_, _, _, err = verifyCompiledPayload(spec, "build", payload, false)
	if err == nil || !strings.Contains(err.Error(), "untrusted capability floor") {
		t.Fatalf("floor violation accepted: %v", err)
	}
	// A floor-conformant untrusted policy passes.
	payload.EffectivePolicy = mustJSON(t, policy.DefaultUntrustedCapabilities())
	cj, caps, policyOK, err := verifyCompiledPayload(spec, "build", payload, false)
	if err != nil {
		t.Fatalf("floor-conformant policy rejected: %v", err)
	}
	if !policyOK || cj.ID != "build" || caps.NativeExecution {
		t.Fatalf("unexpected result: cj=%q policyOK=%t caps=%+v", cj.ID, policyOK, caps)
	}
}

func TestVerifyCompiledPayloadMissingPolicy(t *testing.T) {
	spec, err := pipeline.Parse([]byte(payloadPipeline))
	if err != nil {
		t.Fatal(err)
	}
	payload := buildPayload(t, payloadPipeline, "build")
	payload.EffectivePolicy = nil
	_, _, policyOK, err := verifyCompiledPayload(spec, "build", payload, true)
	if err != nil {
		t.Fatalf("payload without policy rejected: %v", err)
	}
	if policyOK {
		t.Fatal("policyOK must be false when the payload carries no policy")
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return json.RawMessage(b)
}

// stubPayloadLocalBinding disables the local-recompilation binding for
// fixtures whose PURPOSE is a different executor path; the binding itself is
// covered by TestExecuteCompiledPayloadRunsEffectiveJob and
// TestVerifyCompiledPayload*.
func stubPayloadLocalBinding(t *testing.T) func() {
	t.Helper()
	prev := payloadLocalBindingCheck
	payloadLocalBindingCheck = false
	return func() { payloadLocalBindingCheck = prev }
}

// TestVerifyCompiledPayloadBindsEffectiveJobToLocalCompile is the direct
// regression for the self-referential digest: a payload whose EffectiveJob
// was replaced (and whose JobDigest was recomputed to match) alongside a
// digest-verified pipeline must be REFUSED because it does not match a local
// recompilation of that pipeline.
func TestVerifyCompiledPayloadBindsEffectiveJobToLocalCompile(t *testing.T) {
	base := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"
	spec, err := pipeline.Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	payload := buildPayload(t, base, "build")
	raw, ok := payload.EffectiveJob.(json.RawMessage)
	if !ok {
		t.Fatalf("effective job = %T", payload.EffectiveJob)
	}
	var eff pipeline.CompiledJob
	if err := json.Unmarshal(raw, &eff); err != nil {
		t.Fatal(err)
	}
	eff.Job.Steps = append(eff.Job.Steps, pipeline.Step{ID: "evil", Run: "touch /tmp/pwned"})
	evilJSON := mustJSON(t, eff)
	sum := sha256.Sum256(evilJSON)
	payload.EffectiveJob = evilJSON
	payload.JobDigest = hex.EncodeToString(sum[:])

	if _, _, _, err := verifyCompiledPayload(spec, "build", payload, true); err == nil || !strings.Contains(err.Error(), "local compilation") {
		t.Fatalf("self-hashed tampered payload = %v, want the local-compilation refusal", err)
	}
}

// TestApplyPersistedResourceRequests: the payload records the
// spec-deterministic compile (unfilled resources); the persisted relational
// request fields (server ceiling fill) are re-applied over the verified job
// so execution bounds match the scheduler's reservations. Zero persisted
// fields leave the payload untouched (trusted jobs, no fill).
func TestApplyPersistedResourceRequests(t *testing.T) {
	var cj pipeline.CompiledJob
	cj.Job.Resources = pipeline.Resources{CPU: 1, Memory: 1, Disk: 1, PIDs: 1}
	applyPersistedResourceRequests(&cj, model.Job{CPURequest: 2, MemoryRequest: 4 << 30, DiskRequest: 10 << 30, PIDsRequest: 256})
	if cj.Job.Resources.CPU != 2 || cj.Job.Resources.Memory != 4<<30 || cj.Job.Resources.Disk != 10<<30 || cj.Job.Resources.PIDs != 256 {
		t.Fatalf("resources = %+v, want the persisted values", cj.Job.Resources)
	}
	applyPersistedResourceRequests(&cj, model.Job{})
	if cj.Job.Resources.CPU != 2 {
		t.Fatalf("empty persisted fields must not zero the resources: %+v", cj.Job.Resources)
	}
}

// TestVerifyCompiledPayloadAcceptsUnfilledCeilingPayload: the enqueue no
// longer fills untrusted ceilings into the payload, so a payload built
// straight from a local compile (zero-declared resources) must verify; the
// ceiling fill arrives via the persisted relational fields instead.
func TestVerifyCompiledPayloadAcceptsUnfilledCeilingPayload(t *testing.T) {
	base := "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc\n    steps:\n      - run: echo hi\n"
	spec, err := pipeline.Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	payload := buildPayload(t, base, "build")
	cj, _, _, err := verifyCompiledPayload(spec, "build", payload, true)
	if err != nil {
		t.Fatalf("unfilled payload verification: %v", err)
	}
	if cj.Job.Resources.CPU != 0 {
		t.Fatalf("payload resources = %+v, want the unfilled compile", cj.Job.Resources)
	}
}
