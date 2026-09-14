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
	cj, caps, policyOK, err := verifyCompiledPayload(spec, payload, true)
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
		_, _, _, err := verifyCompiledPayload(spec, payload, true)
		if err == nil || !strings.Contains(err.Error(), "compiled payload digest mismatch") {
			t.Fatalf("tampered pipeline digest accepted: %v", err)
		}
	})
	t.Run("job digest", func(t *testing.T) {
		payload := buildPayload(t, payloadPipeline, "build")
		payload.JobDigest = strings.Repeat("1", 64)
		_, _, _, err := verifyCompiledPayload(spec, payload, true)
		if err == nil || !strings.Contains(err.Error(), "compiled payload digest mismatch") {
			t.Fatalf("tampered job digest accepted: %v", err)
		}
	})
	t.Run("schema version", func(t *testing.T) {
		payload := buildPayload(t, payloadPipeline, "build")
		payload.SchemaVersion = 2
		_, _, _, err := verifyCompiledPayload(spec, payload, true)
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
	_, _, _, err = verifyCompiledPayload(spec, payload, false)
	if err == nil || !strings.Contains(err.Error(), "untrusted capability floor") {
		t.Fatalf("floor violation accepted: %v", err)
	}
	// A floor-conformant untrusted policy passes.
	payload.EffectivePolicy = mustJSON(t, policy.DefaultUntrustedCapabilities())
	cj, caps, policyOK, err := verifyCompiledPayload(spec, payload, false)
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
	_, _, policyOK, err := verifyCompiledPayload(spec, payload, true)
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
