package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const bindingPipeline = "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"

// bindingPayload compiles text the way the control plane does and returns the
// enqueue-time record for key, with coherent digests.
func bindingPayload(t *testing.T, text, key string) (*Spec, *model.CompiledJobPayload) {
	t.Helper()
	spec, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	pd, err := PipelineDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Compile(spec)
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
	return spec, &model.CompiledJobPayload{
		SchemaVersion:   1,
		CompilerVersion: "test",
		PipelineDigest:  pd,
		JobDigest:       hex.EncodeToString(sum[:]),
		EffectiveJob:    json.RawMessage(cjJSON),
	}
}

func TestVerifyCompiledJobBinding(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		spec, payload := bindingPayload(t, bindingPipeline, "build")
		cj, err := VerifyCompiledJobBinding(spec, "build", payload)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if cj.ID != "build" || cj.BaseID != "build" {
			t.Fatalf("effective job = %q/%q", cj.ID, cj.BaseID)
		}
	})
	t.Run("wrong schema version", func(t *testing.T) {
		spec, payload := bindingPayload(t, bindingPipeline, "build")
		payload.SchemaVersion = 2
		if _, err := VerifyCompiledJobBinding(spec, "build", payload); err == nil || !strings.Contains(err.Error(), "schema version") {
			t.Fatalf("schema version = %v", err)
		}
	})
	t.Run("nil payload", func(t *testing.T) {
		spec, _ := bindingPayload(t, bindingPipeline, "build")
		if _, err := VerifyCompiledJobBinding(spec, "build", nil); err == nil || !strings.Contains(err.Error(), "missing") {
			t.Fatalf("nil payload = %v", err)
		}
	})
	t.Run("tampered pipeline digest", func(t *testing.T) {
		spec, payload := bindingPayload(t, bindingPipeline, "build")
		payload.PipelineDigest = strings.Repeat("0", 64)
		if _, err := VerifyCompiledJobBinding(spec, "build", payload); err == nil || !strings.Contains(err.Error(), "compiled payload digest mismatch") {
			t.Fatalf("pipeline digest = %v", err)
		}
	})
	t.Run("tampered job digest", func(t *testing.T) {
		spec, payload := bindingPayload(t, bindingPipeline, "build")
		payload.JobDigest = strings.Repeat("1", 64)
		if _, err := VerifyCompiledJobBinding(spec, "build", payload); err == nil || !strings.Contains(err.Error(), "compiled payload digest mismatch") {
			t.Fatalf("job digest = %v", err)
		}
	})
	t.Run("effective job not in pipeline", func(t *testing.T) {
		spec, payload := bindingPayload(t, bindingPipeline, "build")
		if _, err := VerifyCompiledJobBinding(spec, "other", payload); err == nil || !strings.Contains(err.Error(), "has no job") {
			t.Fatalf("missing job = %v", err)
		}
	})
	t.Run("effective-job/local-compile mismatch", func(t *testing.T) {
		spec, payload := bindingPayload(t, bindingPipeline, "build")
		raw, ok := payload.EffectiveJob.(json.RawMessage)
		if !ok {
			t.Fatalf("effective job = %T", payload.EffectiveJob)
		}
		var eff CompiledJob
		if err := json.Unmarshal(raw, &eff); err != nil {
			t.Fatal(err)
		}
		// Self-consistent tamper: the payload's own hash is recomputed, so
		// only the local-recompilation binding can catch it.
		eff.Job.Steps = append(eff.Job.Steps, Step{ID: "evil", Run: "touch /tmp/pwned"})
		evilJSON, err := json.Marshal(eff)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(evilJSON)
		payload.EffectiveJob = json.RawMessage(evilJSON)
		payload.JobDigest = hex.EncodeToString(sum[:])
		if _, err := VerifyCompiledJobBinding(spec, "build", payload); err == nil || !strings.Contains(err.Error(), "local compilation") {
			t.Fatalf("self-hashed tamper = %v, want local-compilation refusal", err)
		}
		// The digest-only variant deliberately skips only that binding.
		if _, err := VerifyCompiledJobDigests(spec, "build", payload); err != nil {
			t.Fatalf("digest-only variant refused a digest-coherent payload: %v", err)
		}
	})
}
