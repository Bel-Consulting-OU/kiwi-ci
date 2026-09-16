package policy

import (
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// NetworkCapability is the strongest egress mode a capability set permits.
type NetworkCapability = pipeline.NetworkPolicy

// Capabilities is the effective capability set a pipeline may exercise.
// It is compiled as the intersection of repository policy, organization
// policy, trust-domain policy, and the pipeline request. Anything absent is
// denied.
//
// Nil-meaning rules:
//   - Secrets: nil means unrestricted (trusted default; every declared secret
//     may be resolved per pipeline declaration). A non-nil map is an explicit
//     allowlist and an empty non-nil map denies all secrets.
//   - OIDC: nil means unrestricted (trusted default; any audience). A non-nil
//     slice is an explicit audience allowlist and an empty non-nil slice
//     denies id_token issuance entirely.
//   - RunnerLabels: nil means any label. A non-nil slice is an explicit
//     allowlist and an empty non-nil slice denies all runner labels.
//
// Enforced marks the set as an authoritative authorization restriction set:
// the runner's profile/registration claim and the policy file's
// CapabilitiesFor result set it, while the trust defaults
// (DefaultTrustedCapabilities/DefaultUntrustedCapabilities) leave it false.
// An ENFORCED set that grants no runtime backend at all denies every job —
// an empty enforced set means "run nothing", never "no restriction". An
// unenforced (base) set has no such meaning: its empty lists are still the
// documented per-field universal sets.
type Capabilities struct {
	NativeExecution    bool
	Container          bool
	Tart               bool
	Network            NetworkCapability
	Secrets            map[string]bool
	OIDC               []string
	Deployments        bool
	CacheRead          bool
	CacheWrite         bool
	RunnerLabels       []string
	GenerateChildGraph bool
	CrossRepoTrigger   bool
	// RequireRootless, RequireReadOnlyRootFS and RequireNonRoot are
	// sandbox requirements the effective policy demands of every executed
	// job, not grants: Intersect ORs them (any layer that demands one
	// wins) and Effective preserves them. The JSON tags match the
	// runner-side effectivePolicySandbox decode (internal/runner) so the
	// compiled payload carries them as "rootless", "read_only_rootfs" and
	// "non_root".
	RequireRootless       bool `json:"rootless"`
	RequireReadOnlyRootFS bool `json:"read_only_rootfs"`
	RequireNonRoot        bool `json:"non_root"`
	// Enforced is true when this set is an authoritative authorization
	// record (repository/org policy compilation or a runner registration
	// profile) rather than a permissive policy base. It is monotone across
	// Intersect/Effective: any enforced layer makes the result enforced.
	// An enforced set that grants no runtime (native/container/tart all
	// false) denies every runtime; the runner-side equivalent is an
	// enforced, empty capability list.
	Enforced bool `json:"enforced"`
}

// DefaultTrustedCapabilities returns the capabilities granted to trusted
// pipelines by default. Secrets and OIDC are nil (unrestricted per the
// nil-meaning rules above); everything else that is not explicitly granted is
// denied, so Deployments, GenerateChildGraph, and CrossRepoTrigger remain off
// until a repository or organization policy grants them.
func DefaultTrustedCapabilities() Capabilities {
	return Capabilities{
		NativeExecution: true,
		Container:       true,
		Tart:            true,
		Network:         pipeline.NetworkPolicyInternet,
		Secrets:         nil,
		OIDC:            nil,
		Deployments:     false,
		CacheRead:       true,
		CacheWrite:      true,
		RunnerLabels:    nil,
	}
}

// DefaultUntrustedCapabilities returns the hard floor for untrusted
// pipelines: no native execution, no Tart execution (until Tart gains
// isolated networking, a networked VM is not a sandbox boundary), no
// egress, no secrets, no OIDC credentials, and no deployments. Every
// executed job must additionally run rootless, with a read-only rootfs,
// and as a non-root user (the untrusted sandbox floor). Secrets and OIDC
// are non-nil empty allowlists so they deny by default and cannot be
// lifted by Intersect. CacheRead/CacheWrite stay true because the server
// scopes cache namespaces per trust domain.
func DefaultUntrustedCapabilities() Capabilities {
	return Capabilities{
		NativeExecution:       false,
		Container:             true,
		Tart:                  false,
		Network:               pipeline.NetworkPolicyNone,
		Secrets:               map[string]bool{},
		OIDC:                  []string{},
		Deployments:           false,
		CacheRead:             true,
		CacheWrite:            true,
		RunnerLabels:          nil,
		RequireRootless:       true,
		RequireReadOnlyRootFS: true,
		RequireNonRoot:        true,
	}
}

// Intersect returns the least-privilege combination of base and restriction:
// booleans are ANDed, network is the weaker of the two (None < ServicesOnly <
// Internet, with Default compared as Internet), secrets and OIDC audiences are
// intersected as sets, and runner labels are intersected as subsets. A nil
// set acts as the universal set (no restriction from that side), so
// Intersect(c, DefaultUntrustedCapabilities()) always lands on the untrusted
// floor. Sandbox requirements (RequireRootless/RequireReadOnlyRootFS/
// RequireNonRoot) are the one monotone exception: they are ORed, because a
// requirement demanded by any layer must survive — a layer that does not
// demand one is neutral, never a waiver.
func Intersect(base, restriction Capabilities) Capabilities {
	return Capabilities{
		NativeExecution:       base.NativeExecution && restriction.NativeExecution,
		Container:             base.Container && restriction.Container,
		Tart:                  base.Tart && restriction.Tart,
		Network:               minNetwork(base.Network, restriction.Network),
		Secrets:               intersectSecrets(base.Secrets, restriction.Secrets),
		OIDC:                  intersectStrings(base.OIDC, restriction.OIDC),
		Deployments:           base.Deployments && restriction.Deployments,
		CacheRead:             base.CacheRead && restriction.CacheRead,
		CacheWrite:            base.CacheWrite && restriction.CacheWrite,
		RunnerLabels:          intersectStrings(base.RunnerLabels, restriction.RunnerLabels),
		GenerateChildGraph:    base.GenerateChildGraph && restriction.GenerateChildGraph,
		CrossRepoTrigger:      base.CrossRepoTrigger && restriction.CrossRepoTrigger,
		RequireRootless:       base.RequireRootless || restriction.RequireRootless,
		RequireReadOnlyRootFS: base.RequireReadOnlyRootFS || restriction.RequireReadOnlyRootFS,
		RequireNonRoot:        base.RequireNonRoot || restriction.RequireNonRoot,
		// Enforcement is monotone like the sandbox requirements: a result
		// derived from an authoritative layer stays authoritative even when
		// the other layer is a permissive base.
		Enforced: base.Enforced || restriction.Enforced,
	}
}

// Effective applies the hard trust floor: untrusted capability sets are
// intersected with DefaultUntrustedCapabilities so no source can lift an
// untrusted pipeline above the floor. The floor's explicit deny-all forms
// (empty non-nil Secrets/OIDC) are always preserved. Trusted sets are
// returned unchanged.
func (c Capabilities) Effective(trusted bool) Capabilities {
	if trusted {
		return c
	}
	eff := Intersect(c, DefaultUntrustedCapabilities())
	if eff.Secrets == nil {
		eff.Secrets = map[string]bool{}
	}
	if eff.OIDC == nil {
		eff.OIDC = []string{}
	}
	return eff
}

// OIDCAllows reports whether the capability set permits id_token issuance for
// the given audience. nil OIDC permits any audience (trusted default).
func (c Capabilities) OIDCAllows(audience string) bool {
	if c.OIDC == nil {
		return true
	}
	return containsString(c.OIDC, audience)
}

// OIDCPolicy is the OIDC audience policy derived from a capability set.
// AllowedAudiences is nil when the set permits any audience.
type OIDCPolicy struct {
	AllowedAudiences []string
}

// Allows reports whether the policy permits id_token issuance for audience.
func (p OIDCPolicy) Allows(audience string) bool {
	if p.AllowedAudiences == nil {
		return true
	}
	return containsString(p.AllowedAudiences, audience)
}

// OIDCFromCapabilities derives the OIDC audience policy from a capability
// set: a nil OIDC slice (any audience) maps to a nil allowlist; an explicit
// allowlist is copied.
func OIDCFromCapabilities(c Capabilities) OIDCPolicy {
	if c.OIDC == nil {
		return OIDCPolicy{}
	}
	return OIDCPolicy{AllowedAudiences: append([]string(nil), c.OIDC...)}
}

// networkStrength orders network policies for least-privilege comparison:
// None < ServicesOnly < Internet, with Default compared as Internet.
func networkStrength(p pipeline.NetworkPolicy) int {
	switch p {
	case pipeline.NetworkPolicyNone:
		return 0
	case pipeline.NetworkPolicyServicesOnly:
		return 1
	default:
		return 2
	}
}

func minNetwork(a, b pipeline.NetworkPolicy) pipeline.NetworkPolicy {
	if networkStrength(a) <= networkStrength(b) {
		return a
	}
	return b
}

func intersectSecrets(a, b map[string]bool) map[string]bool {
	if a == nil {
		return cloneBoolMap(b)
	}
	if b == nil {
		return cloneBoolMap(a)
	}
	out := make(map[string]bool)
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

func intersectStrings(a, b []string) []string {
	if a == nil {
		return cloneStrings(b)
	}
	if b == nil {
		return cloneStrings(a)
	}
	out := make([]string, 0)
	for _, v := range a {
		if containsString(b, v) {
			out = append(out, v)
		}
	}
	return out
}

func containsString(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s))
	out = append(out, s...)
	return out
}

func cloneBoolMap(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
