package model

import "testing"

// TestExecutionAssuranceClosedSet pins the derived profiles as a closed,
// named set: every defined profile is valid and carries a stable public name,
// every value outside the set is invalid and has no name (evidence must never
// mint a name for an unknown profile).
func TestExecutionAssuranceClosedSet(t *testing.T) {
	want := map[ExecutionAssurance]string{
		AssuranceUncontrolled:          "uncontrolled",
		AssuranceIsolatedFilesystem:    "isolated_filesystem",
		AssuranceNoInjectedCredentials: "no_injected_credentials",
		AssuranceNetworkDenied:         "network_denied",
		AssuranceKiwiMediatedAuthority: "kiwi_mediated_authority",
		AssuranceSealedPinnedNoNetwork: "sealed_pinned_no_network",
	}
	if len(ExecutionAssuranceNames) != len(want) {
		t.Fatalf("profile set size = %d, want %d", len(ExecutionAssuranceNames), len(want))
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

// TestDeriveAssuranceProfileFromFacts pins the single derivation rule against
// the audit's fact-vector contract: a workspace quota never implies
// filesystem isolation (native + quota is profile 0), the network-denied and
// mediated-authority profiles are siblings, and the strongest profile
// requires network none plus pinned images.
func TestDeriveAssuranceProfileFromFacts(t *testing.T) {
	base := ExecutionFacts{
		Runtime:            RuntimeFactContainer,
		FilesystemIsolated: true,
		NetworkMode:        NetworkModeFactNone,
	}
	cases := []struct {
		name    string
		mut     func(*ExecutionFacts)
		want    ExecutionAssurance
		invalid bool
	}{
		{name: "native with a workspace quota is uncontrolled, never isolated", mut: func(f *ExecutionFacts) {
			f.Runtime = RuntimeFactNative
			f.FilesystemIsolated = false
			f.WorkspaceQuotaEnforced = true
		}, want: AssuranceUncontrolled},
		{name: "sandbox with injected secrets is only isolated", mut: func(f *ExecutionFacts) {
			f.KiwiSecretsInjected = true
		}, want: AssuranceIsolatedFilesystem},
		{name: "sandbox clean credentials network none is profile 2", mut: func(f *ExecutionFacts) {
			f.NetworkMode = NetworkModeFactInternet
		}, want: AssuranceNoInjectedCredentials},
		{name: "sandbox clean network none without mediation is network denied", mut: func(f *ExecutionFacts) {}, want: AssuranceNetworkDenied},
		{name: "mediated authority with allowed network is profile 4", mut: func(f *ExecutionFacts) {
			f.NetworkMode = NetworkModeFactInternet
			f.DeclaredAuthorityMediated = true
		}, want: AssuranceKiwiMediatedAuthority},
		{name: "mediated authority with network none and unpinned images is profile 4", mut: func(f *ExecutionFacts) {
			f.DeclaredAuthorityMediated = true
		}, want: AssuranceKiwiMediatedAuthority},
		{name: "mediated authority network none pinned images is sealed pinned", mut: func(f *ExecutionFacts) {
			f.DeclaredAuthorityMediated = true
			f.ImagesDigestPinned = true
		}, want: AssuranceSealedPinnedNoNetwork},
		{name: "unknown runtime with isolation claimed is inconsistent", mut: func(f *ExecutionFacts) {
			f.Runtime = RuntimeFactUnknown
		}, invalid: true},
		{name: "native runtime with mediated authority is inconsistent", mut: func(f *ExecutionFacts) {
			f.Runtime = RuntimeFactNative
			f.DeclaredAuthorityMediated = true
		}, invalid: true},
		{name: "unobserved sandbox claim with a native receipt is inconsistent", mut: func(f *ExecutionFacts) {
			f.Observed = &ExecutionControlReceipt{Runtime: "native", NetworkEnforced: ObservedNetworkHost}
		}, invalid: true},
		{name: "observed sandbox receipt corroborates a sandboxed execution", mut: func(f *ExecutionFacts) {
			f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone}
		}, want: AssuranceNetworkDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			tc.mut(&f)
			if got := f.Valid(); got == tc.invalid {
				t.Fatalf("facts.Valid() = %v (invalid=%v) for %+v", got, tc.invalid, f)
			}
			if tc.invalid {
				return
			}
			if got := DeriveAssuranceProfile(f); got != tc.want {
				t.Fatalf("DeriveAssuranceProfile = %d (%s), want %d (%s)", got, got.Name(), tc.want, tc.want.Name())
			}
		})
	}
}

// TestUnprovenFactsDeriveUncontrolled pins the conservative fallback: a
// record whose execution cannot be re-materialized claims no runtime, no
// isolation and no credential exclusion, and therefore derives profile 0.
func TestUnprovenFactsDeriveUncontrolled(t *testing.T) {
	f := UnprovenExecutionFacts()
	if !f.Valid() {
		t.Fatalf("unproven facts invalid: %+v", f)
	}
	if got := DeriveAssuranceProfile(f); got != AssuranceUncontrolled {
		t.Fatalf("unproven facts derive %d (%s), want uncontrolled", got, got.Name())
	}
	if !f.KiwiSecretsInjected || !f.HostEnvironmentInherited {
		t.Fatalf("unproven facts must not exclude credentials: %+v", f)
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
