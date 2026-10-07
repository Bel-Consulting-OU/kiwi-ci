package provenance

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// decodeJSONValue decodes JSON text into the generic decoded representation
// the persisted CompiledJobPayload carries.
func decodeJSONValue(t *testing.T, raw string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestCapsuleDigestCanonicalAndTamperEvident proves the capsule digest is a
// canonical function of the persisted payload: differently ordered but
// semantically identical JSON yields the same digest, every bound field
// changes it, nil encodes distinctly from an explicit empty value, and
// unencodable values surface an error instead of a digest.
func TestCapsuleDigestCanonicalAndTamperEvident(t *testing.T) {
	base := func() *model.CompiledJobPayload {
		return &model.CompiledJobPayload{
			SchemaVersion:   2,
			CompilerVersion: "compiler/1.0",
			PipelineDigest:  strings.Repeat("a", 64),
			JobDigest:       strings.Repeat("b", 64),
			EffectiveJob:    decodeJSONValue(t, `{"name":"build","steps":[{"run":"make"},{"run":"test"}]}`),
			EffectivePolicy: decodeJSONValue(t, `{"oidc":false,"network":{"allow":true,"hosts":["a","b"]}}`),
		}
	}
	a := base()
	dA, err := CapsuleDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(dA) != 64 {
		t.Fatalf("capsule digest = %q, want a 64-hex sha256", dA)
	}

	// Same values, different JSON key order: the canonical encoding must
	// produce exactly the same digest.
	b := base()
	b.EffectiveJob = decodeJSONValue(t, `{"steps":[{"run":"make"},{"run":"test"}],"name":"build"}`)
	b.EffectivePolicy = decodeJSONValue(t, `{"network":{"hosts":["a","b"],"allow":true},"oidc":false}`)
	dB, err := CapsuleDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if dA != dB {
		t.Fatalf("capsule digest not canonical: %s vs %s", dA, dB)
	}
	// Deterministic across repeated calls.
	again, err := CapsuleDigest(a)
	if err != nil || again != dA {
		t.Fatalf("capsule digest unstable: %q vs %q (%v)", dA, again, err)
	}

	// Every bound field must change the digest.
	mutations := map[string]func(p *model.CompiledJobPayload){
		"schemaVersion":   func(p *model.CompiledJobPayload) { p.SchemaVersion++ },
		"compilerVersion": func(p *model.CompiledJobPayload) { p.CompilerVersion += "x" },
		"pipelineDigest":  func(p *model.CompiledJobPayload) { p.PipelineDigest += "0" },
		"jobDigest":       func(p *model.CompiledJobPayload) { p.JobDigest += "0" },
		"effectiveJob": func(p *model.CompiledJobPayload) {
			p.EffectiveJob = decodeJSONValue(t, `{"name":"other"}`)
		},
		"effectivePolicy": func(p *model.CompiledJobPayload) {
			p.EffectivePolicy = decodeJSONValue(t, `{"oidc":true}`)
		},
	}
	for label, mutate := range mutations {
		p := base()
		mutate(p)
		got, err := CapsuleDigest(p)
		if err != nil {
			t.Fatalf("%s mutation: %v", label, err)
		}
		if got == dA {
			t.Errorf("%s mutation left the capsule digest unchanged", label)
		}
	}

	// nil encodes as empty and must differ from an explicit empty JSON
	// object/array.
	nilValues := base()
	nilValues.EffectiveJob = nil
	nilValues.EffectivePolicy = nil
	dNil, err := CapsuleDigest(nilValues)
	if err != nil {
		t.Fatal(err)
	}
	emptyValues := base()
	emptyValues.EffectiveJob = map[string]any{}
	emptyValues.EffectivePolicy = map[string]any{}
	dEmpty, err := CapsuleDigest(emptyValues)
	if err != nil {
		t.Fatal(err)
	}
	if dNil == dEmpty {
		t.Fatal("nil effective values must not collide with explicit empty values")
	}

	// A nil payload and an unencodable value are errors, never a fabricated
	// digest.
	if _, err := CapsuleDigest(nil); err == nil {
		t.Fatal("nil payload must be rejected")
	}
	bad := base()
	bad.EffectiveJob = make(chan int)
	if _, err := CapsuleDigest(bad); err == nil {
		t.Fatal("unencodable effective job must surface an error")
	}
	badPolicy := base()
	badPolicy.EffectivePolicy = make(chan int)
	if _, err := CapsuleDigest(badPolicy); err == nil {
		t.Fatal("unencodable effective policy must surface an error")
	}
}

// TestArtifactStatementAttemptCapsuleAndPublishedAt proves the new signed
// fields are emitted in the statement (and therefore covered by the
// signature), while a statement with no real terminal timestamp omits
// finishedOn entirely.
func TestArtifactStatementAttemptCapsuleAndPublishedAt(t *testing.T) {
	pub, priv := provKey(t)
	published := time.Unix(1700000000, 0).UTC()
	st := ArtifactStatement(ArtifactInput{
		Name: "app", SHA256: strings.Repeat("c", 64), RunID: "run", JobID: "job",
		AttemptID: "job:7", CapsuleDigest: strings.Repeat("d", 64),
		ArtifactPublishedAt: published,
	})
	env, err := Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"attemptId":"job:7"`, `"capsuleDigest":"` + strings.Repeat("d", 64) + `"`, `"artifactPublishedAt":"2023-11-14T22:13:20Z"`} {
		if !strings.Contains(string(payload), want) {
			t.Errorf("signed payload missing %s: %s", want, payload)
		}
	}
	if strings.Contains(string(payload), "finishedOn") {
		t.Fatalf("statement without a terminal timestamp carries finishedOn: %s", payload)
	}
	if got := st.Predicate.RunDetails.Metadata.InvocationID; got != "run/job:7" {
		t.Fatalf("invocationId = %q, want run/job:7", got)
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyWith(raw, nil, VerifyOptions{
		TrustedKey: pub, AttemptID: "job:7", CapsuleDigest: strings.Repeat("d", 64),
	})
	if err != nil {
		t.Fatalf("matching attempt/capsule constraints must verify: %v", err)
	}
	if got.AttemptID != "job:7" || got.CapsuleDigest != strings.Repeat("d", 64) {
		t.Fatalf("verified statement lost the new identity: %+v", got)
	}
	if got.ArtifactPublishedAt == nil || !got.ArtifactPublishedAt.Equal(published) {
		t.Fatalf("artifactPublishedAt = %v, want %v", got.ArtifactPublishedAt, published)
	}
	if got.Predicate.RunDetails.Metadata.FinishedOn != nil {
		t.Fatalf("finishedOn = %v, want omitted", got.Predicate.RunDetails.Metadata.FinishedOn)
	}

	// Constraints reject mismatches and the error names the constraint.
	if _, err := VerifyWith(raw, nil, VerifyOptions{TrustedKey: pub, AttemptID: "job:8"}); err == nil || !strings.Contains(err.Error(), "attempt id") {
		t.Fatalf("attempt id mismatch error = %v, want constraint label", err)
	}
	if _, err := VerifyWith(raw, nil, VerifyOptions{TrustedKey: pub, CapsuleDigest: strings.Repeat("e", 64)}); err == nil || !strings.Contains(err.Error(), "capsule digest") {
		t.Fatalf("capsule digest mismatch error = %v, want constraint label", err)
	}

	// A real terminal timestamp is emitted; the zero value is not.
	finished := time.Unix(1700000123, 0).UTC()
	withEnd := ArtifactStatement(ArtifactInput{
		Name: "app", SHA256: strings.Repeat("c", 64), RunID: "run", JobID: "job",
		Finished: finished,
	})
	envEnd, err := Sign(withEnd, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	endPayload, err := base64.StdEncoding.DecodeString(envEnd.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(endPayload), `"finishedOn":"2023-11-14T22:15:23Z"`) {
		t.Fatalf("real terminal timestamp not emitted: %s", endPayload)
	}
}

// TestVerifyRejectsTamperedAttemptCapsulePublishedAt proves the signature
// covers the new fields: mutating any of them in the signed payload invalidates
// the envelope.
func TestVerifyRejectsTamperedAttemptCapsulePublishedAt(t *testing.T) {
	pub, priv := provKey(t)
	st := ArtifactStatement(ArtifactInput{
		Name: "app", SHA256: strings.Repeat("c", 64), RunID: "run", JobID: "job",
		AttemptID: "job:7", CapsuleDigest: strings.Repeat("d", 64),
		ArtifactPublishedAt: time.Unix(1700000000, 0).UTC(),
	})
	env, err := Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(raw, nil, VerifyOptions{TrustedKey: pub}); err != nil {
		t.Fatalf("genuine envelope must verify: %v", err)
	}
	for label, mutate := range map[string]func(m map[string]any){
		"attempt": func(m map[string]any) { m["attemptId"] = "job:8" },
		"capsule": func(m map[string]any) { m["capsuleDigest"] = strings.Repeat("e", 64) },
		"published": func(m map[string]any) {
			m["artifactPublishedAt"] = time.Unix(1, 0).UTC().Format(time.RFC3339)
		},
	} {
		var tampered Envelope
		if err := json.Unmarshal(raw, &tampered); err != nil {
			t.Fatal(err)
		}
		payload, err := base64.StdEncoding.DecodeString(tampered.Payload)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(payload, &body); err != nil {
			t.Fatal(err)
		}
		mutate(body)
		mutated, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		tampered.Payload = base64.StdEncoding.EncodeToString(mutated)
		tamperedRaw, err := json.Marshal(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyWith(tamperedRaw, nil, VerifyOptions{TrustedKey: pub}); err == nil {
			t.Errorf("tampered %s field verified", label)
		}
	}
}
