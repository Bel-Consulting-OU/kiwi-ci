package provenance

import (
	"encoding/json"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestGraphFingerprintBindsTopology proves the fingerprint is deterministic,
// order independent, and changes on every node/edge mutation; status and
// identity metadata deliberately do not participate.
func TestGraphFingerprintBindsTopology(t *testing.T) {
	a := model.Job{ID: "id-a", Key: "build", Needs: []string{"id-z"}}
	b := model.Job{ID: "id-b", Key: "test", Needs: []string{"id-a", "id-z"}}
	c := model.Job{ID: "id-c", Key: "lint", Needs: []string{"id-z"}}
	jobs := []model.Job{a, b, c}
	base := GraphFingerprint(jobs)
	if len(base) != 64 {
		t.Fatalf("fingerprint = %q, want 64 hex chars", base)
	}
	if GraphFingerprint([]model.Job{c, a, b}) != base {
		t.Fatal("fingerprint depends on row order")
	}
	// Dependency declaration order is a set: order changes do not move the
	// fingerprint.
	reorderedNeeds := b
	reorderedNeeds.Needs = []string{"id-z", "id-a"}
	if GraphFingerprint([]model.Job{a, reorderedNeeds, c}) != base {
		t.Fatal("fingerprint depends on dependency declaration order")
	}
	changes := map[string][]model.Job{
		"changed key":  {{ID: "id-a", Key: "compile", Needs: []string{"id-z"}}, b, c},
		"dropped need": {{ID: "id-a", Key: "build", Needs: nil}, b, c},
		"added need":   {{ID: "id-a", Key: "build", Needs: []string{"id-z", "id-b"}}, b, c},
		"removed job":  {a, b},
		"added job":    append(append([]model.Job{}, jobs...), model.Job{ID: "id-d", Key: "deploy", Needs: []string{"id-b"}}),
		"empty graph":  nil,
	}
	for name, mutated := range changes {
		if GraphFingerprint(mutated) == base {
			t.Fatalf("%s did not change the fingerprint", name)
		}
	}
	// Status and unrelated identity fields are not part of the graph shape.
	restatus := a
	restatus.Status = model.StatusRunning
	if GraphFingerprint([]model.Job{restatus, b, c}) != base {
		t.Fatal("job status leaked into the graph fingerprint")
	}
	// The empty graph is a well-defined fingerprint, not an empty string.
	empty := GraphFingerprint(nil)
	if empty == "" || empty == base {
		t.Fatalf("empty graph fingerprint = %q", empty)
	}
}

// TestEffectivePolicyDigestCanonicalAndOptional proves the policy digest
// binds the canonical policy JSON (map key order independent), changes with
// any policy change, and is empty when there is no policy to bind.
func TestEffectivePolicyDigestCanonicalAndOptional(t *testing.T) {
	p := &model.CompiledJobPayload{EffectivePolicy: json.RawMessage(`{"Network":0,"Secrets":{"B":true,"A":true}}`)}
	d1, err := EffectivePolicyDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(d1) != 64 {
		t.Fatalf("digest = %q, want 64 hex chars", d1)
	}
	same := &model.CompiledJobPayload{EffectivePolicy: json.RawMessage(`{"Secrets":{"A":true,"B":true},"Network":0}`)}
	d2, err := EffectivePolicyDigest(same)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("digest is not canonical over JSON key order: %s != %s", d1, d2)
	}
	changed := &model.CompiledJobPayload{EffectivePolicy: json.RawMessage(`{"Network":0,"Secrets":{"A":true}}`)}
	d3, err := EffectivePolicyDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if d3 == d1 {
		t.Fatal("policy change did not change the digest")
	}
	for name, payload := range map[string]*model.CompiledJobPayload{
		"nil payload":  nil,
		"nil policy":   {},
		"empty policy": {EffectivePolicy: json.RawMessage("")},
	} {
		got, err := EffectivePolicyDigest(payload)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != "" {
			t.Fatalf("%s digest = %q, want empty", name, got)
		}
	}
}
