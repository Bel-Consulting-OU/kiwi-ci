package pipeline

import (
	"strings"
	"testing"
)

func provenanceDoc(policy string) string {
	return "version: 1\njobs:\n  a:\n    steps:\n      - run: r\n    artifacts:\n      - name: bin\n        paths: [out]\n        provenance: " + policy + "\n"
}

// TestArtifactProvenancePolicyValidation pins the artifact provenance policy
// surface: required and best_effort are accepted (default = best_effort,
// empty), anything else is rejected by both the spec and compiled validators,
// and the YAML allowlist admits the new key.
func TestArtifactProvenancePolicyValidation(t *testing.T) {
	for _, policy := range []string{"required", "best_effort"} {
		spec, err := Parse([]byte(provenanceDoc(policy)))
		if err != nil {
			t.Fatalf("parse %s: %v", policy, err)
		}
		if err := Validate(spec); err != nil {
			t.Fatalf("validate %s: %v", policy, err)
		}
		if got := spec.Jobs["a"].Artifacts[0].Provenance; got != policy {
			t.Fatalf("policy = %q, want %q", got, policy)
		}
	}
	// Empty means best_effort and validates.
	spec, err := Parse([]byte("version: 1\njobs:\n  a:\n    steps:\n      - run: r\n    artifacts:\n      - name: bin\n        paths: [out]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(spec); err != nil {
		t.Fatalf("empty policy: %v", err)
	}
	// An unknown policy is rejected at parse/validate time.
	if _, err := Parse([]byte(provenanceDoc("always"))); err == nil || !strings.Contains(err.Error(), "invalid provenance policy") {
		t.Fatalf("unknown policy = %v", err)
	}
	// The compiled validator sees the same rule (e.g. a persisted compiled
	// job tampered to carry an invalid policy).
	valid, err := Parse([]byte(provenanceDoc("required")))
	if err != nil {
		t.Fatal(err)
	}
	graph, err := Compile(valid)
	if err != nil {
		t.Fatal(err)
	}
	cj := graph.Jobs["a"]
	cj.Job.Artifacts[0].Provenance = "always"
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "invalid provenance policy") {
		t.Fatalf("compiled unknown policy = %v", err)
	}
	// The YAML allowlist admits the key: a near-miss unknown key still fails.
	if _, err := Parse([]byte("version: 1\njobs:\n  a:\n    steps:\n      - run: r\n    artifacts:\n      - name: bin\n        paths: [out]\n        prov: required\n")); err == nil {
		t.Fatal("unknown artifact key accepted")
	}
}
