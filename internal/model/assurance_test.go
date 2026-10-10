package model

import "testing"

// TestExecutionAssuranceClosedSet pins the assurance ladder as a closed,
// named set: every defined level is valid and carries a stable public name,
// every value outside the set is invalid and has no name (evidence must never
// mint a name for an unknown level).
func TestExecutionAssuranceClosedSet(t *testing.T) {
	want := map[ExecutionAssurance]string{
		AssuranceUncontrolled:          "uncontrolled",
		AssuranceIsolatedFilesystem:    "isolated_filesystem",
		AssuranceNoAmbientCredentials:  "no_ambient_credentials",
		AssuranceNetworkDenied:         "network_denied",
		AssuranceKiwiMediatedAuthority: "kiwi_mediated_authority",
		AssuranceHermetic:              "hermetic",
	}
	if len(ExecutionAssuranceNames) != len(want) {
		t.Fatalf("level set size = %d, want %d", len(ExecutionAssuranceNames), len(want))
	}
	for level, name := range want {
		if !level.Valid() {
			t.Fatalf("level %d not valid", level)
		}
		if got := level.Name(); got != name {
			t.Fatalf("level %d name = %q, want %q", level, got, name)
		}
	}
	for _, bad := range []ExecutionAssurance{-1, 6, 99} {
		if bad.Valid() {
			t.Fatalf("level %d accepted", bad)
		}
		if bad.Name() != "" {
			t.Fatalf("unknown level %d has name %q", bad, bad.Name())
		}
	}
}

// TestExternalEffectsClassClosedSet pins the effect classes as a closed set:
// exactly pure, kiwi_mediated and opaque_external are valid.
func TestExternalEffectsClassClosedSet(t *testing.T) {
	for _, class := range []ExternalEffectsClass{EffectsPure, EffectsKiwiMediated, EffectsOpaqueExternal} {
		if !class.Valid() {
			t.Fatalf("class %q not valid", class)
		}
		if class == "" {
			t.Fatal("empty class must not be a defined value")
		}
	}
	for _, bad := range []ExternalEffectsClass{"", "bogus", "PURE", "opaque"} {
		if bad.Valid() {
			t.Fatalf("class %q accepted", bad)
		}
	}
}
