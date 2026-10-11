package model

import "fmt"

// The execution-assurance contract has two layers:
//
//  1. ExecutionFacts — the AUTHORITATIVE vector of proven execution controls,
//     derived from the persisted job/payload/policy records and bound into
//     signed evidence. Consumers that make security decisions must authorize
//     against these facts, never against a numeric profile.
//
//  2. ExecutionAssurance — a small set of DERIVED PROFILE LABELS for humans
//     and policy shorthands. The labels are not an ordinal lattice: the
//     network-denied and kiwi-mediated-authority profiles are siblings, so a
//     higher number does not contain every guarantee of a lower one. The
//     derivation (DeriveAssuranceProfile) is total and deterministic.
//
// Facts state what Kiwi ENFORCED, from durable records. The optional Observed
// receipt inside the facts states what the concrete runtime REPORTED when it
// started (executor-observed enforcement), which lets a consumer corroborate
// the effective vector without replacing it.
//
// Provenance distinction (requested -> effective -> observed): the
// requested controls are the job's declaration, the effective facts below
// are the policy-intersected values Kiwi can prove from durable records, and
// the observed receipt is what the executor captured from the running
// runtime. Normally all three agree; evidence keeps them distinguishable.

// ExecutionRuntimeFact is the closed runtime vocabulary of the effective
// execution facts. "unknown" is the conservative zero value: an execution
// whose records cannot be re-materialized claims no runtime, and every
// runtime-dependent fact must then be false.
type ExecutionRuntimeFact string

const (
	// RuntimeFactUnknown is the unprovable runtime.
	RuntimeFactUnknown ExecutionRuntimeFact = "unknown"
	// RuntimeFactNative is host execution with host authority.
	RuntimeFactNative ExecutionRuntimeFact = "native"
	// RuntimeFactContainer is a container sandbox.
	RuntimeFactContainer ExecutionRuntimeFact = "container"
	// RuntimeFactTart is a Tart VM sandbox.
	RuntimeFactTart ExecutionRuntimeFact = "tart"
)

// ExecutionNetworkModeFact is the closed effective-network vocabulary,
// mirroring the compiled pipeline policy. "unknown" is the conservative zero
// value.
type ExecutionNetworkModeFact string

const (
	// NetworkModeFactUnknown is the unprovable network mode.
	NetworkModeFactUnknown ExecutionNetworkModeFact = "unknown"
	// NetworkModeFactNone is pipeline network none.
	NetworkModeFactNone ExecutionNetworkModeFact = "none"
	// NetworkModeFactServices is pipeline services-only egress.
	NetworkModeFactServices ExecutionNetworkModeFact = "services"
	// NetworkModeFactDefault is the runtime's default network.
	NetworkModeFactDefault ExecutionNetworkModeFact = "default"
	// NetworkModeFactInternet is unrestricted internet egress.
	NetworkModeFactInternet ExecutionNetworkModeFact = "internet"
)

// ObservedNetworkMode is the closed executor-observed network enforcement
// vocabulary: what the concrete runtime actually entered, not what was
// requested.
type ObservedNetworkMode string

const (
	// ObservedNetworkNone: the runtime has no network at all.
	ObservedNetworkNone ObservedNetworkMode = "none"
	// ObservedNetworkContainerNamespace: the runtime has its own network
	// namespace (container), with connectivity per the applied mode.
	ObservedNetworkContainerNamespace ObservedNetworkMode = "container-namespace"
	// ObservedNetworkVMNAT: the runtime is a VM attached through host NAT
	// (Tart), which cannot be denied.
	ObservedNetworkVMNAT ObservedNetworkMode = "vm-nat"
	// ObservedNetworkHost: the process runs with the host's network.
	ObservedNetworkHost ObservedNetworkMode = "host"
)

// ExecutionControlReceipt is the executor-observed enforcement receipt of one
// attempt: the sandbox identity, whether a sandbox actually started, the
// network enforcement the runtime entered, and whether the root filesystem
// was read-only. It is captured when the concrete runtime starts (best
// effort) and is deliberately separate from the effective facts: absence
// means "the executor did not capture a receipt" (legacy attempts, runtimes
// without capture), never "the controls were absent".
type ExecutionControlReceipt struct {
	// Runtime is the runtime that actually started: native, docker or tart.
	Runtime string `json:"runtime"`
	// SandboxStarted is true when a real sandbox boundary started. Native
	// execution reports false.
	SandboxStarted bool `json:"sandbox_started"`
	// NetworkEnforced is what the runtime actually entered.
	NetworkEnforced ObservedNetworkMode `json:"network_enforced"`
	// RootFilesystemReadOnly is true when the runtime applied a read-only
	// root filesystem (container --read-only). False means "not applied",
	// not "unknown".
	RootFilesystemReadOnly bool `json:"root_filesystem_read_only,omitempty"`
	// WorkspaceQuotaEnforced is the attempt-specific hard-quota observation:
	// true only when a hard OS-level workspace quota (XFS project quota) was
	// actually installed before the workspace was populated
	// (executor.DiskQuotaStatus.Hard). It is never a restatement of the
	// requested limit: a requested bound with fallback step-boundary
	// accounting, a failed setup, or no request at all all record false.
	WorkspaceQuotaEnforced bool `json:"workspace_quota_enforced,omitempty"`
}

// Valid reports whether the receipt is a well-formed closed observation.
func (r ExecutionControlReceipt) Valid() bool {
	switch r.Runtime {
	case "native", "docker", "tart":
	default:
		return false
	}
	switch r.NetworkEnforced {
	case ObservedNetworkNone, ObservedNetworkContainerNamespace, ObservedNetworkVMNAT, ObservedNetworkHost:
	default:
		return false
	}
	switch r.Runtime {
	case "native":
		if r.SandboxStarted {
			return false
		}
	case "docker", "tart":
		if !r.SandboxStarted {
			return false
		}
	}
	if r.RootFilesystemReadOnly && r.Runtime != "docker" {
		return false
	}
	return true
}

// ExecutionFacts is the authoritative vector of proven execution controls of
// one attempt. Every field is a closed, derivable fact; no field is a claim
// about what an arbitrary command may attempt inside those controls.
//
// Facts are orthogonal by design (the audit's fact-vector rule): a workspace
// quota bounds disk use but does NOT confine a native process, so
// WorkspaceQuotaEnforced is separate from FilesystemIsolated and never
// implies it.
type ExecutionFacts struct {
	// Runtime is the effective runtime the control plane selected.
	Runtime ExecutionRuntimeFact `json:"runtime"`
	// FilesystemIsolated is true only for a real confinement boundary
	// (container or Tart sandbox). A workspace quota does NOT set it.
	FilesystemIsolated bool `json:"filesystem_isolated"`
	// WorkspaceQuotaConfigured is the CONFIGURATION fact: the execution
	// plan requested a workspace quota bound (a declared resources.disk or
	// the mandatory untrusted default). It says nothing about whether a
	// hard OS-level bound was actually installed.
	WorkspaceQuotaConfigured bool `json:"workspace_quota_configured,omitempty"`
	// WorkspaceQuotaEnforced meaning is SCHEMA-FROZEN:
	//   schema v5 (historical): "a workspace quota bound was configured/requested"
	//   schema v6 (current):    "a hard OS-level quota was proven installed"
	// The verifier must interpret the field under the statement's schema
	// version and never upgrade a v5 claim to the stronger v6 meaning.
	WorkspaceQuotaEnforced bool `json:"workspace_quota_enforced"`
	// KiwiSecretsInjected is true when the effective secret allowlist could
	// admit at least one secret (nil policy, or any allowed entry). The
	// complementary fact is "no INJECTED credentials", deliberately narrower
	// than "no ambient credentials": ambient credential surfaces the
	// execution boundary does not remove (host filesystem for native, VM
	// identity, runtime metadata) are not claimed absent here.
	KiwiSecretsInjected bool `json:"kiwi_secrets_injected"`
	// HostEnvironmentInherited is true when the execution inherits the
	// runner host environment. The distributed execution model always
	// starts from a clean environment, so this is false there; the local
	// `kiwi run` host-environment opt-in is never represented as a
	// distributed attempt.
	HostEnvironmentInherited bool `json:"host_environment_inherited"`
	// NetworkMode is the EFFECTIVE NETWORK POLICY (requested/effective
	// intent). It is NOT a proven enforcement fact. The wire name is
	// historically "network_mode"; schema v6 keeps that name so canonical
	// digests of already-issued statements stay stable. Consumers that
	// authorize on "network was denied" MUST use NetworkAccessDenied, never
	// this field: native execution can be asked for network none and still
	// run with host networking.
	NetworkMode ExecutionNetworkModeFact `json:"network_mode"`
	// NetworkAccessDenied is the PROVEN enforcement fact: true only when the
	// attempt's executor-observed receipt shows the runtime entered a state
	// with no network (ObservedNetworkNone). Absent/false on schema v5
	// statements (the field did not exist) and on any attempt that cannot
	// prove denial. Schema v6 refuses to sign or accept a true value that
	// the receipt does not corroborate.
	NetworkAccessDenied bool `json:"network_access_denied,omitempty"`
	// DeclaredAuthorityMediated is true when every DECLARED external effect
	// (deployments, OIDC) is covered by the effective capability set and the
	// execution is sandboxed. It says nothing about undeclared egress.
	DeclaredAuthorityMediated bool `json:"declared_authority_mediated"`
	// ImagesDigestPinned is true when every declared executable image
	// reference (container image, service images, Tart VM) is digest-pinned.
	ImagesDigestPinned bool `json:"images_digest_pinned"`
	// Observed is the executor-observed enforcement receipt when the attempt
	// captured one. It corroborates the effective vector; it never replaces
	// it and is nil for records without a receipt.
	Observed *ExecutionControlReceipt `json:"observed,omitempty"`
}

// Valid reports whether the fact vector is well-formed under SCHEMA v6
// semantics (the only schema new evidence is built with).
func (f ExecutionFacts) Valid() bool {
	return f.ValidForSchema(6)
}

// ValidForSchema reports whether the fact vector is well-formed under the
// semantics of the given attestation schema version. Historical v5 is
// frozen: its workspace_quota_enforced meant "configured", and it had no
// network_access_denied field, so those cross-checks do not apply.
func (f ExecutionFacts) ValidForSchema(schema int) bool {
	switch f.Runtime {
	case RuntimeFactUnknown, RuntimeFactNative, RuntimeFactContainer, RuntimeFactTart:
	default:
		return false
	}
	switch f.NetworkMode {
	case NetworkModeFactUnknown, NetworkModeFactNone, NetworkModeFactServices, NetworkModeFactDefault, NetworkModeFactInternet:
	default:
		return false
	}
	sandboxed := f.Runtime == RuntimeFactContainer || f.Runtime == RuntimeFactTart
	if f.FilesystemIsolated && !sandboxed {
		return false
	}
	if f.Runtime == RuntimeFactUnknown && (f.FilesystemIsolated || f.DeclaredAuthorityMediated || f.ImagesDigestPinned) {
		return false
	}
	if f.DeclaredAuthorityMediated && !sandboxed {
		return false
	}
	if f.ImagesDigestPinned && !sandboxed {
		return false
	}
	if f.Observed != nil && !f.Observed.Valid() {
		return false
	}
	if schema >= 6 {
		return f.ValidateObservedConsistency() == nil
	}
	return f.validateObservedConsistencyLegacy(schema) == nil
}

// validateObservedConsistencyLegacy applies the FROZEN historical cross-checks.
// v5's workspace_quota_enforced is "configured" (not observation), and
// network_access_denied did not exist — neither is compared to the receipt.
// Runtime correspondence and isolation↔sandbox-started still apply whenever a
// receipt is present: those fields kept their meaning.
func (f ExecutionFacts) validateObservedConsistencyLegacy(schema int) error {
	if f.Observed == nil {
		return nil
	}
	obs := f.Observed
	switch f.Runtime {
	case RuntimeFactContainer:
		if obs.Runtime != "docker" {
			return errObservedMismatch("runtime", f.Runtime, obs.Runtime)
		}
	case RuntimeFactTart:
		if obs.Runtime != "tart" {
			return errObservedMismatch("runtime", f.Runtime, obs.Runtime)
		}
	case RuntimeFactNative:
		if obs.Runtime != "native" {
			return errObservedMismatch("runtime", f.Runtime, obs.Runtime)
		}
	}
	if f.FilesystemIsolated && !obs.SandboxStarted {
		return errObservedMismatch("filesystem_isolated", true, obs.SandboxStarted)
	}
	if obs.SandboxStarted && !f.FilesystemIsolated {
		if f.Runtime == RuntimeFactContainer || f.Runtime == RuntimeFactTart {
			return errObservedMismatch("filesystem_isolated", false, obs.SandboxStarted)
		}
	}
	// A policy-none claim sitting next to a receipt that reports a connected
	// namespace is contradictory under every schema. (What is frozen on v5 is
	// the MEANING of workspace_quota_enforced and the absence of
	// network_access_denied — not permission to sign nonsense.)
	if f.Runtime == RuntimeFactContainer {
		if f.NetworkMode == NetworkModeFactNone && obs.NetworkEnforced != ObservedNetworkNone {
			return errObservedMismatch("network_mode", f.NetworkMode, obs.NetworkEnforced)
		}
	}
	return nil
}

// ValidateObservedConsistency is the single authoritative cross-check between
// the effective control vector and the executor-observed enforcement receipt
// under SCHEMA v6 semantics. It is called before signing and during
// attestation verification so Kiwi can never emit (or accept) internally
// contradictory evidence.
//
// Only properties a runtime can unambiguously observe are cross-checked.
// Native execution cannot deny the network, so a native effective POLICY of
// "none" is NOT compared against the always-host receipt: the POLICY field
// stays "none" while NetworkAccessDenied stays false. That split is the
// point — authorization on "network denied" uses the proven fact only.
func (f ExecutionFacts) ValidateObservedConsistency() error {
	// Quota enforcement is observation-only (v6 meaning).
	observedHard := f.Observed != nil && f.Observed.WorkspaceQuotaEnforced
	if f.WorkspaceQuotaEnforced != observedHard {
		return errObservedMismatch("workspace_quota_enforced", f.WorkspaceQuotaEnforced, observedHard)
	}
	// Network denial is observation-only (v6 meaning).
	observedDenied := f.Observed != nil && f.Observed.NetworkEnforced == ObservedNetworkNone
	if f.NetworkAccessDenied != observedDenied {
		return errObservedMismatch("network_access_denied", f.NetworkAccessDenied, observedDenied)
	}
	if f.Observed == nil {
		return nil
	}
	obs := f.Observed
	// Effective runtime ↔ observed runtime. An UNKNOWN effective runtime may
	// carry any valid receipt (the receipt is then the only proven runtime
	// fact and cannot upgrade the effective vector).
	switch f.Runtime {
	case RuntimeFactContainer:
		if obs.Runtime != "docker" {
			return errObservedMismatch("runtime", f.Runtime, obs.Runtime)
		}
	case RuntimeFactTart:
		if obs.Runtime != "tart" {
			return errObservedMismatch("runtime", f.Runtime, obs.Runtime)
		}
	case RuntimeFactNative:
		if obs.Runtime != "native" {
			return errObservedMismatch("runtime", f.Runtime, obs.Runtime)
		}
	}
	// Filesystem isolation ↔ sandbox started (both directions on a known
	// sandboxed runtime).
	if f.FilesystemIsolated && !obs.SandboxStarted {
		return errObservedMismatch("filesystem_isolated", true, obs.SandboxStarted)
	}
	if obs.SandboxStarted && !f.FilesystemIsolated {
		if f.Runtime == RuntimeFactContainer || f.Runtime == RuntimeFactTart {
			return errObservedMismatch("filesystem_isolated", false, obs.SandboxStarted)
		}
	}
	// Policy none on a runtime that CAN deny networking (container) must be
	// corroborated by the receipt. Tart cannot deny networking (and refuses
	// the policy at start). Native policy none is allowed and is NOT proof of
	// denial — NetworkAccessDenied already stays false for native/host.
	if f.Runtime == RuntimeFactContainer {
		if f.NetworkMode == NetworkModeFactNone && obs.NetworkEnforced != ObservedNetworkNone {
			return errObservedMismatch("network_mode", f.NetworkMode, obs.NetworkEnforced)
		}
		if obs.NetworkEnforced == ObservedNetworkNone && f.NetworkMode == NetworkModeFactInternet {
			return errObservedMismatch("network_mode", f.NetworkMode, obs.NetworkEnforced)
		}
	}
	return nil
}

// errObservedMismatch formats a single-field effective↔observed disagreement.
func errObservedMismatch(field string, effective, observed any) error {
	return &ObservedConsistencyError{Field: field, Effective: fmt.Sprintf("%v", effective), Observed: fmt.Sprintf("%v", observed)}
}

// ObservedConsistencyError reports one effective↔observed disagreement.
type ObservedConsistencyError struct {
	Field     string
	Effective string
	Observed  string
}

func (e *ObservedConsistencyError) Error() string {
	return fmt.Sprintf("execution facts: effective %s=%s contradicts observed %s", e.Field, e.Effective, e.Observed)
}

// ApplyObservedControl attaches the executor-observed enforcement receipt and
// derives the attempt-specific PROVEN enforcement facts from it (schema v6):
// WorkspaceQuotaEnforced and NetworkAccessDenied are copied from the receipt's
// observations and are NEVER manufactured from the requested policy or limit.
// The result is then cross-validated; a contradictory receipt is rejected
// rather than signed.
func (f *ExecutionFacts) ApplyObservedControl(r *ExecutionControlReceipt) error {
	f.Observed = r
	if r != nil {
		f.WorkspaceQuotaEnforced = r.WorkspaceQuotaEnforced
		f.NetworkAccessDenied = r.NetworkEnforced == ObservedNetworkNone
	} else {
		f.WorkspaceQuotaEnforced = false
		f.NetworkAccessDenied = false
	}
	return f.ValidateObservedConsistency()
}

// UnprovenExecutionFacts returns the conservative fact vector for a record
// whose execution cannot be re-materialized: no runtime, no isolation, no
// provable credential restriction, no pinned images. It derives profile 0
// (uncontrolled).
func UnprovenExecutionFacts() ExecutionFacts {
	return ExecutionFacts{
		Runtime:                  RuntimeFactUnknown,
		NetworkMode:              NetworkModeFactUnknown,
		KiwiSecretsInjected:      true,
		HostEnvironmentInherited: true,
	}
}

// ExecutionAssurance is the DERIVED profile label of an execution fact
// vector: a small, stable vocabulary for humans and policy shorthands.
//
// The labels are NOT an ordinal lattice. Levels 1 and 2 are cumulative
// above 0; level 3 (network_denied) and level 4 (kiwi_mediated_authority)
// are SIBLING branches above 2: a level-4 job may allow network egress (then
// unauthenticated egress is explicitly outside Kiwi mediation), while a
// level-3 job denies the network but has no mediated-authority claim. Level
// 5 requires the level-4 control PLUS network none PLUS every image
// digest-pinned. Consumers authorize against ExecutionFacts; a numeric
// comparison between labels is not a security decision.
//
// The exact derivation (DeriveAssuranceProfile):
//
//	0 (uncontrolled): no sandbox boundary (native or unknown runtime).
//
//	1 (isolated_filesystem): a real sandbox boundary (container/Tart), but
//	  credentials could still reach the job (Kiwi-injected via a non-empty
//	  allowlist, or an inherited host environment).
//
//	2 (no_injected_credentials): level 1 plus an explicitly empty (non-nil,
//	  deny-all) secret allowlist and no inherited host environment. This is
//	  "Kiwi injected no credentials", deliberately narrower than "no ambient
//	  credentials": credential surfaces the sandbox itself does not remove
//	  (VM identity, container-runtime metadata endpoints, network-reachable
//	  brokers) are NOT claimed absent.
//
//	3 (network_denied): level 2 plus effective network none.
//
//	4 (kiwi_mediated_authority): level 2 plus every DECLARED external
//	  authority covered by a Kiwi capability. The network may be allowed.
//
//	5 (sealed_pinned_no_network): level 4 plus network none plus every
//	  declared image digest-pinned. This is NOT a hermeticity claim: clocks,
//	  randomness, kernel/runtime state, locale and undeclared host inputs
//	  are outside what these controls prove, so Kiwi does not call it
//	  "hermetic".
type ExecutionAssurance int

const (
	// AssuranceUncontrolled is profile 0: no sandbox boundary.
	AssuranceUncontrolled ExecutionAssurance = iota
	// AssuranceIsolatedFilesystem is profile 1: a real sandbox boundary.
	AssuranceIsolatedFilesystem
	// AssuranceNoInjectedCredentials is profile 2: profile 1 plus an
	// explicitly empty secret allowlist and a clean environment.
	AssuranceNoInjectedCredentials
	// AssuranceNetworkDenied is profile 3: profile 2 plus network none.
	AssuranceNetworkDenied
	// AssuranceKiwiMediatedAuthority is profile 4: profile 2 plus mediated
	// declared authority. The network may be allowed.
	AssuranceKiwiMediatedAuthority
	// AssuranceSealedPinnedNoNetwork is profile 5: profile 4 plus network
	// none plus digest-pinned images. Not a reproducibility claim.
	AssuranceSealedPinnedNoNetwork
)

// ExecutionAssuranceNames maps every profile to its stable public name. The
// names are part of the evidence contract (see docs/evidence-contract.md)
// and must not change meaning without a schema bump. Schema v4 used the names
// "no_ambient_credentials" and "hermetic"; schema v5 renamed them to the
// narrower, provable vocabulary below.
var ExecutionAssuranceNames = map[ExecutionAssurance]string{
	AssuranceUncontrolled:          "uncontrolled",
	AssuranceIsolatedFilesystem:    "isolated_filesystem",
	AssuranceNoInjectedCredentials: "no_injected_credentials",
	AssuranceNetworkDenied:         "network_denied",
	AssuranceKiwiMediatedAuthority: "kiwi_mediated_authority",
	AssuranceSealedPinnedNoNetwork: "sealed_pinned_no_network",
}

// Name returns the stable public name of the profile, or "" for a value
// outside the closed set. Evidence builders must not mint names for unknown
// profiles.
func (a ExecutionAssurance) Name() string {
	return ExecutionAssuranceNames[a]
}

// Valid reports whether a is one of the defined profiles. Evidence that
// carries an out-of-range value is invalid and must be refused, never
// interpreted.
func (a ExecutionAssurance) Valid() bool {
	_, ok := ExecutionAssuranceNames[a]
	return ok
}

// DeriveAssuranceProfile derives the profile label from the authoritative
// fact vector under SCHEMA v6 semantics. Network-denied and sealed profiles
// require the PROVEN NetworkAccessDenied fact — never the policy field alone.
// The function is total and deterministic; it is the ONLY derivation rule for
// current evidence, shared by builders and verifiers.
func DeriveAssuranceProfile(f ExecutionFacts) ExecutionAssurance {
	if !f.FilesystemIsolated {
		return AssuranceUncontrolled
	}
	if f.KiwiSecretsInjected || f.HostEnvironmentInherited {
		return AssuranceIsolatedFilesystem
	}
	if f.DeclaredAuthorityMediated {
		if f.NetworkAccessDenied && f.ImagesDigestPinned {
			return AssuranceSealedPinnedNoNetwork
		}
		return AssuranceKiwiMediatedAuthority
	}
	if f.NetworkAccessDenied {
		return AssuranceNetworkDenied
	}
	return AssuranceNoInjectedCredentials
}

// DeriveAssuranceProfileSchema derives the profile under the semantics of a
// specific attestation schema version. Schema 5 froze "network denied" as the
// POLICY field (network_mode == none); schema 6 requires the proven
// NetworkAccessDenied fact. Verifiers MUST use this so a historical v5
// statement is never reinterpreted under the stronger v6 rule (and vice
// versa).
func DeriveAssuranceProfileSchema(schema int, f ExecutionFacts) ExecutionAssurance {
	if schema >= 6 {
		return DeriveAssuranceProfile(f)
	}
	// Historical v5 (and the v4 name-only block, which never carried facts):
	// the policy field is what the profile was derived from at signing time.
	if !f.FilesystemIsolated {
		return AssuranceUncontrolled
	}
	if f.KiwiSecretsInjected || f.HostEnvironmentInherited {
		return AssuranceIsolatedFilesystem
	}
	if f.DeclaredAuthorityMediated {
		if f.NetworkMode == NetworkModeFactNone && f.ImagesDigestPinned {
			return AssuranceSealedPinnedNoNetwork
		}
		return AssuranceKiwiMediatedAuthority
	}
	if f.NetworkMode == NetworkModeFactNone {
		return AssuranceNetworkDenied
	}
	return AssuranceNoInjectedCredentials
}

// ExternalEffectsClass is the closed classification of where a job's external
// effects (anything observable outside the execution boundary) come from. It
// is evidence, not configuration: a derivation classifies an attempt from its
// durable records and never upgrades the class.
//
//   - pure: a sandbox boundary, an explicitly empty secret allowlist, a
//     clean environment, network none, and no OIDC id_token declaration and
//     no deployment phases. The only effects are files the control plane
//     collects through Kiwi (artifacts, test reports, snapshots, caches),
//     all declared and mediated.
//   - kiwi_mediated: not pure, but sandboxed with an explicitly empty secret
//     allowlist and a clean environment, and every declared external effect
//     (deployments, OIDC, artifacts, downloads) flows through a Kiwi
//     capability. Arbitrary command side effects reachable with the granted
//     authority (for example unauthenticated egress when the network is
//     allowed) are outside Kiwi mediation and are NOT constrained.
//   - opaque_external: ambient credentials are possible: no sandbox boundary
//     (Native execution with host authority), the effective secret allowlist
//     could inject a secret (nil policy or non-empty), or the host
//     environment is inherited. Such a job's effects cannot be attributed to
//     declared Kiwi capabilities; replay/speculation guarantees do not apply
//     to them.
type ExternalEffectsClass string

const (
	// EffectsPure is the pure class.
	EffectsPure ExternalEffectsClass = "pure"
	// EffectsKiwiMediated is the kiwi_mediated class.
	EffectsKiwiMediated ExternalEffectsClass = "kiwi_mediated"
	// EffectsOpaqueExternal is the opaque_external class.
	EffectsOpaqueExternal ExternalEffectsClass = "opaque_external"
)

// ValidateExternalEffects checks that a signed effects class is consistent
// with the proven fact vector. "pure" asserts no egress and no declared
// external authority — it is only true when NetworkAccessDenied is proven
// (never from policy alone). Signing and verification call this so a
// statement cannot claim pure next to facts that do not prove denial.
func ValidateExternalEffects(f ExecutionFacts, c ExternalEffectsClass) error {
	if !c.Valid() {
		return fmt.Errorf("model: undefined external effects class %q", string(c))
	}
	if c == EffectsPure {
		if !f.NetworkAccessDenied {
			return fmt.Errorf("model: external effects class pure requires proven network_access_denied (policy none is not enough)")
		}
		if f.KiwiSecretsInjected || f.HostEnvironmentInherited {
			return fmt.Errorf("model: external effects class pure requires an empty secret allowlist and a clean environment")
		}
	}
	if c == EffectsOpaqueExternal {
		return nil
	}
	// kiwi_mediated / pure both require a sandbox boundary and a clean
	// credential surface (no Kiwi-injected secrets, no inherited host env).
	// Anything less is opaque_external by the shared derivation.
	if !f.FilesystemIsolated {
		return fmt.Errorf("model: external effects class %s requires filesystem isolation", c)
	}
	if f.KiwiSecretsInjected || f.HostEnvironmentInherited {
		return fmt.Errorf("model: external effects class %s cannot claim mediated/pure effects with injected secrets or inherited host environment", c)
	}
	return nil
}

// Valid reports whether c is one of the defined classes.
func (c ExternalEffectsClass) Valid() bool {
	switch c {
	case EffectsPure, EffectsKiwiMediated, EffectsOpaqueExternal:
		return true
	default:
		return false
	}
}
