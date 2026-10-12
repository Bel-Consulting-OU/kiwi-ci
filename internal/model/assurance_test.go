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
			f.WorkspaceQuotaConfigured = true
			f.Observed = &ExecutionControlReceipt{Runtime: "native", NetworkEnforced: ObservedNetworkHost, WorkspaceQuotaEnforced: true}
			f.WorkspaceQuotaEnforced = true
		}, want: AssuranceUncontrolled},
		{name: "quota configured without observation does not claim enforcement", mut: func(f *ExecutionFacts) {
			f.WorkspaceQuotaConfigured = true
			f.WorkspaceQuotaEnforced = false
			f.NetworkAccessDenied = true
			f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone}
		}, want: AssuranceNetworkDenied},
		{name: "sandbox with injected secrets is only isolated", mut: func(f *ExecutionFacts) {
			f.KiwiSecretsInjected = true
		}, want: AssuranceIsolatedFilesystem},
		{name: "sandbox clean credentials network none is profile 2", mut: func(f *ExecutionFacts) {
			f.NetworkMode = NetworkModeFactInternet
		}, want: AssuranceNoInjectedCredentials},
		{name: "sandbox clean proven network denial without mediation is network denied", mut: func(f *ExecutionFacts) {
			f.NetworkAccessDenied = true
			f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone}
		}, want: AssuranceNetworkDenied},
		{name: "mediated authority with allowed network is profile 4", mut: func(f *ExecutionFacts) {
			f.NetworkMode = NetworkModeFactInternet
			f.DeclaredAuthorityMediated = true
		}, want: AssuranceKiwiMediatedAuthority},
		{name: "mediated authority with network none and unpinned images is profile 4", mut: func(f *ExecutionFacts) {
			f.DeclaredAuthorityMediated = true
		}, want: AssuranceKiwiMediatedAuthority},
		{name: "mediated authority proven denial pinned images is sealed pinned", mut: func(f *ExecutionFacts) {
			f.DeclaredAuthorityMediated = true
			f.ImagesDigestPinned = true
			f.NetworkAccessDenied = true
			f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone}
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
			f.NetworkAccessDenied = true
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

// TestValidateObservedConsistencyMatrix pins the P2 cross-check: effective
// controls and the executor-observed receipt must agree on every property a
// runtime can unambiguously observe. Contradictory pairs are refused whether
// they were produced by a bug or a hostile runner, before signing and during
// verification (both go through Valid()).
func TestValidateObservedConsistencyMatrix(t *testing.T) {
	containerBase := ExecutionFacts{
		Runtime:            RuntimeFactContainer,
		FilesystemIsolated: true,
		NetworkMode:        NetworkModeFactNone,
	}
	nativeBase := ExecutionFacts{
		Runtime:     RuntimeFactNative,
		NetworkMode: NetworkModeFactDefault,
	}
	cases := []struct {
		name    string
		mut     func(*ExecutionFacts)
		wantErr bool
	}{
		{
			name: "container network none + observed none agrees",
			mut: func(f *ExecutionFacts) {
				f.NetworkAccessDenied = true
				f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone}
			},
		},
		{
			name: "policy none without proven denial is not network_access_denied",
			mut: func(f *ExecutionFacts) {
				f.NetworkAccessDenied = false
				f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone}
			},
			wantErr: true,
		},
		{
			name: "container network none + observed container-namespace is contradictory",
			mut: func(f *ExecutionFacts) {
				f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkContainerNamespace}
			},
			wantErr: true,
		},
		{
			name: "container network none + observed host is contradictory",
			mut: func(f *ExecutionFacts) {
				f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkHost}
			},
			wantErr: true,
		},
		{
			name: "container isolation without sandbox start is contradictory",
			mut: func(f *ExecutionFacts) {
				f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: false, NetworkEnforced: ObservedNetworkNone}
			},
			wantErr: true,
		},
		{
			name: "effective container + native receipt is contradictory",
			mut: func(f *ExecutionFacts) {
				f.Observed = &ExecutionControlReceipt{Runtime: "native", NetworkEnforced: ObservedNetworkHost}
			},
			wantErr: true,
		},
		{
			name: "effective container + tart receipt is contradictory",
			mut: func(f *ExecutionFacts) {
				f.Observed = &ExecutionControlReceipt{Runtime: "tart", SandboxStarted: true, NetworkEnforced: ObservedNetworkVMNAT}
			},
			wantErr: true,
		},
		{
			name: "observed none under effective internet is contradictory",
			mut: func(f *ExecutionFacts) {
				f.NetworkMode = NetworkModeFactInternet
				f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone}
			},
			wantErr: true,
		},
		{
			name: "observed none under effective services is compatible",
			mut: func(f *ExecutionFacts) {
				f.NetworkMode = NetworkModeFactServices
				f.NetworkAccessDenied = true
				f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone}
			},
		},
		{
			name: "quota enforced must match the receipt",
			mut: func(f *ExecutionFacts) {
				f.WorkspaceQuotaEnforced = true
				f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone}
			},
			wantErr: true,
		},
		{
			name: "quota enforced matches a hard receipt",
			mut: func(f *ExecutionFacts) {
				f.WorkspaceQuotaEnforced = true
				f.NetworkAccessDenied = true
				f.Observed = &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone, WorkspaceQuotaEnforced: true}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := containerBase
			tc.mut(&f)
			err := f.ValidateObservedConsistency()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateObservedConsistency accepted %+v", f)
				}
				if f.Valid() {
					t.Fatalf("Valid() accepted contradictory facts %+v", f)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateObservedConsistency: %v", err)
			}
			if !f.Valid() {
				t.Fatalf("Valid() rejected consistent facts %+v", f)
			}
		})
	}

	// Native cannot deny networking: the always-host receipt is NOT compared
	// against an effective policy of none (the runtime cannot observe/enforce
	// it). Quota still is.
	nativeBase.NetworkMode = NetworkModeFactNone
	nativeBase.NetworkAccessDenied = false
	nativeBase.Observed = &ExecutionControlReceipt{Runtime: "native", NetworkEnforced: ObservedNetworkHost}
	if err := nativeBase.ValidateObservedConsistency(); err != nil {
		t.Fatalf("native policy-none vs host receipt must not be a cross-check: %v", err)
	}
	// Policy none on native is NOT proven denial.
	if nativeBase.NetworkAccessDenied {
		t.Fatal("native host networking must not claim network_access_denied")
	}
	// Claiming proven denial while the receipt reports host is refused.
	nativeBase.NetworkAccessDenied = true
	if err := nativeBase.ValidateObservedConsistency(); err == nil {
		t.Fatal("network_access_denied without observed none must be refused")
	}
	nativeBase.NetworkAccessDenied = false
	nativeBase.WorkspaceQuotaEnforced = true
	if err := nativeBase.ValidateObservedConsistency(); err == nil {
		t.Fatal("native quota overclaim must still be refused")
	}
}

// TestApplyObservedControlNeverManufacturesEnforcement: the helper is the only
// legal way to fill workspace_quota_enforced, and it always takes the value
// from the receipt.
func TestApplyObservedControlNeverManufacturesEnforcement(t *testing.T) {
	f := ExecutionFacts{Runtime: RuntimeFactNative, NetworkMode: NetworkModeFactDefault, WorkspaceQuotaConfigured: true}
	if err := f.ApplyObservedControl(nil); err != nil {
		t.Fatalf("ApplyObservedControl(nil): %v", err)
	}
	if f.WorkspaceQuotaEnforced {
		t.Fatalf("nil receipt manufactured enforcement: %+v", f)
	}
	soft := &ExecutionControlReceipt{Runtime: "native", NetworkEnforced: ObservedNetworkHost}
	if err := f.ApplyObservedControl(soft); err != nil {
		t.Fatalf("ApplyObservedControl(soft): %v", err)
	}
	if f.WorkspaceQuotaEnforced {
		t.Fatalf("soft receipt manufactured enforcement: %+v", f)
	}
	hard := &ExecutionControlReceipt{Runtime: "native", NetworkEnforced: ObservedNetworkHost, WorkspaceQuotaEnforced: true}
	if err := f.ApplyObservedControl(hard); err != nil {
		t.Fatalf("ApplyObservedControl(hard): %v", err)
	}
	if !f.WorkspaceQuotaEnforced {
		t.Fatalf("hard receipt dropped enforcement: %+v", f)
	}
}

// TestValidateObservedConsistencyIsolationBidirectional: a started sandbox
// under an effective vector that denies isolation is the matching reverse
// contradiction and must be refused on container/tart.
func TestValidateObservedConsistencyIsolationBidirectional(t *testing.T) {
	f := ExecutionFacts{
		Runtime:            RuntimeFactContainer,
		FilesystemIsolated: false,
		NetworkMode:        NetworkModeFactNone,
		Observed:           &ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone},
	}
	if err := f.ValidateObservedConsistency(); err == nil {
		t.Fatal("sandbox started under a non-isolated effective claim must be refused")
	}
	if f.Valid() {
		t.Fatal("Valid() must refuse sandbox-started without FilesystemIsolated on container")
	}
}

// TestValidateExternalEffectsPureRequiresProvenDenial: the effects gate at
// sign and verify refuses pure next to facts that do not prove network
// denial (policy none is not enough) and refuses pure with injected secrets.
func TestValidateExternalEffectsPureRequiresProvenDenial(t *testing.T) {
	policyOnly := ExecutionFacts{
		Runtime:            RuntimeFactContainer,
		FilesystemIsolated: true,
		NetworkMode:        NetworkModeFactNone,
	}
	if err := ValidateExternalEffects(policyOnly, EffectsPure); err == nil {
		t.Fatal("pure from policy alone must be refused")
	}
	proven := policyOnly
	if err := proven.ApplyObservedControl(&ExecutionControlReceipt{
		Runtime: "docker", SandboxStarted: true, NetworkEnforced: ObservedNetworkNone,
	}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExternalEffects(proven, EffectsPure); err != nil {
		t.Fatalf("proven denial + pure: %v", err)
	}
	if err := ValidateExternalEffects(proven, EffectsKiwiMediated); err != nil {
		t.Fatalf("proven denial + kiwi_mediated: %v", err)
	}
	native := ExecutionFacts{Runtime: RuntimeFactNative, NetworkMode: NetworkModeFactNone}
	if err := ValidateExternalEffects(native, EffectsPure); err == nil {
		t.Fatal("native cannot claim pure")
	}
	if err := ValidateExternalEffects(proven, EffectsOpaqueExternal); err != nil {
		t.Fatalf("opaque is always allowed: %v", err)
	}
}

// TestValidateExternalEffectsMediatedRequiresCleanCredentials: kiwi_mediated
// is not allowed next to injected secrets or an inherited host environment —
// those are opaque_external by the shared derivation.
func TestValidateExternalEffectsMediatedRequiresCleanCredentials(t *testing.T) {
	f := ExecutionFacts{
		Runtime:             RuntimeFactContainer,
		FilesystemIsolated:  true,
		KiwiSecretsInjected: true,
	}
	if err := ValidateExternalEffects(f, EffectsKiwiMediated); err == nil {
		t.Fatal("kiwi_mediated with injected secrets must be refused")
	}
	f.KiwiSecretsInjected = false
	f.HostEnvironmentInherited = true
	if err := ValidateExternalEffects(f, EffectsKiwiMediated); err == nil {
		t.Fatal("kiwi_mediated with inherited host env must be refused")
	}
	f.HostEnvironmentInherited = false
	if err := ValidateExternalEffects(f, EffectsKiwiMediated); err != nil {
		t.Fatalf("clean isolated mediated: %v", err)
	}
}

// TestExecutionAssuranceSatisfiesIsPropertyLattice: Satisfies is the
// property lattice over what each profile proves — NOT the numeric profile
// order. network_denied (3) and kiwi_mediated_authority (4) are
// incomparable despite 3 < 4; sealed (5) satisfies every profile;
// uncontrolled is the bottom; invalid profiles satisfy nothing.
func TestExecutionAssuranceSatisfiesIsPropertyLattice(t *testing.T) {
	all := []ExecutionAssurance{
		AssuranceUncontrolled,
		AssuranceIsolatedFilesystem,
		AssuranceNoInjectedCredentials,
		AssuranceNetworkDenied,
		AssuranceKiwiMediatedAuthority,
		AssuranceSealedPinnedNoNetwork,
	}
	// want[a][need] = a.Satisfies(need).
	want := map[ExecutionAssurance]map[ExecutionAssurance]bool{
		AssuranceUncontrolled: {
			AssuranceUncontrolled: true,
		},
		AssuranceIsolatedFilesystem: {
			AssuranceUncontrolled:       true,
			AssuranceIsolatedFilesystem: true,
		},
		AssuranceNoInjectedCredentials: {
			AssuranceUncontrolled:          true,
			AssuranceIsolatedFilesystem:    true,
			AssuranceNoInjectedCredentials: true,
		},
		AssuranceNetworkDenied: {
			AssuranceUncontrolled:          true,
			AssuranceIsolatedFilesystem:    true,
			AssuranceNoInjectedCredentials: true,
			AssuranceNetworkDenied:         true,
			// Lacks mediated authority.
			AssuranceKiwiMediatedAuthority: false,
			AssuranceSealedPinnedNoNetwork: false,
		},
		AssuranceKiwiMediatedAuthority: {
			AssuranceUncontrolled:          true,
			AssuranceIsolatedFilesystem:    true,
			AssuranceNoInjectedCredentials: true,
			// May allow the network: does not satisfy network_denied.
			AssuranceNetworkDenied:         false,
			AssuranceKiwiMediatedAuthority: true,
			AssuranceSealedPinnedNoNetwork: false,
		},
		AssuranceSealedPinnedNoNetwork: {
			AssuranceUncontrolled:          true,
			AssuranceIsolatedFilesystem:    true,
			AssuranceNoInjectedCredentials: true,
			AssuranceNetworkDenied:         true,
			AssuranceKiwiMediatedAuthority: true,
			AssuranceSealedPinnedNoNetwork: true,
		},
	}
	for _, a := range all {
		for _, need := range all {
			got := a.Satisfies(need)
			if got != want[a][need] {
				t.Fatalf("%s.Satisfies(%s) = %v, want %v", a.Name(), need.Name(), got, want[a][need])
			}
		}
	}
	// The lattice is NOT numeric order: 4 does not satisfy 3 even though 4 > 3.
	if AssuranceKiwiMediatedAuthority.Satisfies(AssuranceNetworkDenied) {
		t.Fatal("kiwi_mediated_authority must not satisfy network_denied (numeric order is not the lattice)")
	}
	if AssuranceNetworkDenied.Satisfies(AssuranceKiwiMediatedAuthority) {
		t.Fatal("network_denied must not satisfy kiwi_mediated_authority")
	}
	// Invalid profiles fail closed on both sides.
	for _, bad := range []ExecutionAssurance{-1, 6, 99} {
		if bad.Satisfies(AssuranceUncontrolled) || bad.Satisfies(bad) {
			t.Fatalf("invalid profile %d must satisfy nothing", bad)
		}
		if AssuranceSealedPinnedNoNetwork.Satisfies(bad) {
			t.Fatalf("sealed must not satisfy invalid requirement %d", bad)
		}
	}
}
