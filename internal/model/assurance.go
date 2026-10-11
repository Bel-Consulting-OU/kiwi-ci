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
	// WorkspaceQuotaEnforced is the OBSERVATION fact: true only when the
	// attempt-specific executor/runner result proves a hard OS-level
	// workspace quota was installed before the workspace was populated
	// (status.Hard). The evidence builder takes it from the observed
	// control receipt and never manufactures it from the requested limit.
	// It is orthogonal to isolation. Schema note: the field is always
	// present in canonical JSON (including false) so historical v5
	// digests stay stable; the meaning changed from "a bound was
	// requested" to "a hard bound was proven installed".
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
	// NetworkMode is the effective network policy.
	NetworkMode ExecutionNetworkModeFact `json:"network_mode"`
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

// Valid reports whether the fact vector is a well-formed, internally
// consistent member of the closed domains. Inconsistent vectors (for example
// filesystem_isolated on a native runtime) are refused, never interpreted.
// When an observed receipt is present the pair must also satisfy
// ValidateObservedConsistency: effective and observed controls are compared
// semantically before evidence can be signed or accepted.
func (f ExecutionFacts) Valid() bool {
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
	return f.ValidateObservedConsistency() == nil
}

// ValidateObservedConsistency is the single authoritative cross-check between
// the effective control vector and the executor-observed enforcement receipt.
// It is called before signing and during attestation verification so Kiwi can
// never emit (or accept) internally contradictory evidence: a statement that
// claims network denied while its own receipt reports host networking must be
// refused regardless of how it was produced.
//
// Only properties a runtime can unambiguously observe are cross-checked.
// Native execution cannot deny the network, so a native effective policy of
// "none" is NOT compared against the always-host receipt: consumers must read
// Observed for what actually ran. Quota enforcement is always checkable
// because the receipt carries the attempt-specific hard-quota result.
func (f ExecutionFacts) ValidateObservedConsistency() error {
	// Enforcement is observation-only. Claiming a hard quota without a
	// receipt (or with a receipt that did not observe one) is exactly the
	// overclaim this contract forbids.
	observedHard := f.Observed != nil && f.Observed.WorkspaceQuotaEnforced
	if f.WorkspaceQuotaEnforced != observedHard {
		return errObservedMismatch("workspace_quota_enforced", f.WorkspaceQuotaEnforced, observedHard)
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
	// sandboxed runtime). A claimed isolation boundary the runtime did not
	// start is an overclaim; a started sandbox the effective vector denies
	// is the matching underclaim/contradiction. Native is already refused by
	// Valid() when it claims isolation; unknown cannot claim isolation.
	if f.FilesystemIsolated && !obs.SandboxStarted {
		return errObservedMismatch("filesystem_isolated", true, obs.SandboxStarted)
	}
	if obs.SandboxStarted && !f.FilesystemIsolated {
		if f.Runtime == RuntimeFactContainer || f.Runtime == RuntimeFactTart {
			return errObservedMismatch("filesystem_isolated", false, obs.SandboxStarted)
		}
	}
	// Network none is the security-critical direction for runtimes that can
	// deny networking (container). Claiming none while the runtime entered
	// a connected namespace would let Kiwi sign "network denied" over a
	// receipt that says otherwise. Tart cannot deny networking (and refuses
	// the policy at start), so a tart receipt always reports vm-nat; that
	// combination is already refused because effective none would demand
	// observed none.
	if f.Runtime == RuntimeFactContainer || f.Runtime == RuntimeFactTart {
		if f.NetworkMode == NetworkModeFactNone && obs.NetworkEnforced != ObservedNetworkNone {
			return errObservedMismatch("network_mode", f.NetworkMode, obs.NetworkEnforced)
		}
		// The reverse direction: a receipt that reports no network must not
		// sit under an effective claim of unrestricted internet. services is
		// compatible (services-only with no declared services disables all
		// egress at the runtime).
		if obs.NetworkEnforced == ObservedNetworkNone && f.NetworkMode == NetworkModeFactInternet {
			return errObservedMismatch("network_mode", f.NetworkMode, obs.NetworkEnforced)
		}
	}
	// Read-only root: the receipt is the only surface that records it today.
	// When the effective vector claims isolation the receipt must be a real
	// sandbox start (checked above); RootFilesystemReadOnly itself is an
	// observation with no effective counterpart yet, so it is not compared.
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
// derives the attempt-specific enforcement facts from it. WorkspaceQuotaEnforced
// is copied from the receipt's hard-quota observation and is NEVER manufactured
// from the requested limit. The result is then cross-validated; a contradictory
// receipt is rejected rather than signed.
func (f *ExecutionFacts) ApplyObservedControl(r *ExecutionControlReceipt) error {
	f.Observed = r
	if r != nil {
		f.WorkspaceQuotaEnforced = r.WorkspaceQuotaEnforced
	} else {
		f.WorkspaceQuotaEnforced = false
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
// fact vector. The function is total and deterministic; it is the ONLY
// derivation rule, shared by evidence builders and verifiers, so a signed
// profile can never disagree with its signed facts.
func DeriveAssuranceProfile(f ExecutionFacts) ExecutionAssurance {
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

// Valid reports whether c is one of the defined classes.
func (c ExternalEffectsClass) Valid() bool {
	switch c {
	case EffectsPure, EffectsKiwiMediated, EffectsOpaqueExternal:
		return true
	default:
		return false
	}
}
