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
// pipelines: no native execution, no egress, no secrets, no OIDC credentials,
// and no deployments. Secrets and OIDC are non-nil empty allowlists so they
// deny by default and cannot be lifted by Intersect. CacheRead/CacheWrite stay
// true because the server scopes cache namespaces per trust domain.
func DefaultUntrustedCapabilities() Capabilities {
	return Capabilities{
		NativeExecution: false,
		Container:       true,
		Tart:            true,
		Network:         pipeline.NetworkPolicyNone,
		Secrets:         map[string]bool{},
		OIDC:            []string{},
		Deployments:     false,
		CacheRead:       true,
		CacheWrite:      true,
		RunnerLabels:    nil,
	}
}

// Intersect returns the least-privilege combination of base and restriction:
// booleans are ANDed, network is the weaker of the two (None < ServicesOnly <
// Internet, with Default compared as Internet), secrets and OIDC audiences are
// intersected as sets, and runner labels are intersected as subsets. A nil
// set acts as the universal set (no restriction from that side), so
// Intersect(c, DefaultUntrustedCapabilities()) always lands on the untrusted
// floor.
func Intersect(base, restriction Capabilities) Capabilities {
	return Capabilities{
		NativeExecution:    base.NativeExecution && restriction.NativeExecution,
		Container:          base.Container && restriction.Container,
		Tart:               base.Tart && restriction.Tart,
		Network:            minNetwork(base.Network, restriction.Network),
		Secrets:            intersectSecrets(base.Secrets, restriction.Secrets),
		OIDC:               intersectStrings(base.OIDC, restriction.OIDC),
		Deployments:        base.Deployments && restriction.Deployments,
		CacheRead:          base.CacheRead && restriction.CacheRead,
		CacheWrite:         base.CacheWrite && restriction.CacheWrite,
		RunnerLabels:       intersectStrings(base.RunnerLabels, restriction.RunnerLabels),
		GenerateChildGraph: base.GenerateChildGraph && restriction.GenerateChildGraph,
		CrossRepoTrigger:   base.CrossRepoTrigger && restriction.CrossRepoTrigger,
	}
}

// Effective applies the hard trust floor: untrusted capability sets are
// intersected with DefaultUntrustedCapabilities so no source can lift an
// untrusted pipeline above the floor. Trusted sets are returned unchanged.
func (c Capabilities) Effective(trusted bool) Capabilities {
	if trusted {
		return c
	}
	return Intersect(c, DefaultUntrustedCapabilities())
}

// OIDCAllows reports whether the capability set permits id_token issuance for
// the given audience. nil OIDC permits any audience (trusted default).
func (c Capabilities) OIDCAllows(audience string) bool {
	if c.OIDC == nil {
		return true
	}
	return containsString(c.OIDC, audience)
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
	return append([]string(nil), s...)
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
