package secrets

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Scope is one level of the secret hierarchy. Resolution walks the chain
// from the most specific scope outward; the first hit wins and the explain
// report names every level consulted.
type Scope string

const (
	ScopeInstance     Scope = "instance"
	ScopeOrganization Scope = "organization"
	ScopeTeam         Scope = "team"
	ScopeRepository   Scope = "repository"
	ScopeEnvironment  Scope = "environment"
	ScopeJob          Scope = "job"
	ScopeStep         Scope = "step"
)

// HierarchyOrder is the resolution order, most specific first.
var HierarchyOrder = []Scope{
	ScopeStep, ScopeJob, ScopeEnvironment, ScopeRepository, ScopeTeam, ScopeOrganization, ScopeInstance,
}

// SecretRef is one secret at one scope with its policy dimensions.
type SecretRef struct {
	Name      string    `json:"name"`
	Value     string    `json:"-"` // never serialized
	Scope     Scope     `json:"scope"`
	Owner     string    `json:"owner,omitempty"` // org/team/repo/environment name
	Branch    string    `json:"branch,omitempty"`
	Tag       string    `json:"tag,omitempty"`
	Event     string    `json:"event,omitempty"`
	Fork      *bool     `json:"fork,omitempty"` // nil = both; false = non-fork only
	Trusted   *bool     `json:"trusted,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Provider  string    `json:"provider,omitempty"` // vault, aws, …
}

// Policy is the request context a secret must match.
type Policy struct {
	Repository  string
	Team        string
	Org         string
	Environment string
	Job         string
	Step        string
	Branch      string
	Tag         string
	Event       string
	Fork        bool
	Trusted     bool
	// Now is the request clock. Zero is NOT "no expiry check" — the
	// resolver treats it as time.Now() so an expiry can never fail open
	// because a caller forgot to stamp the clock.
	Now time.Time
}

// matches reports whether the ref's policy dimensions admit the request.
func (r SecretRef) matches(p Policy) bool {
	// Trust floor. Trusted is the MINIMUM trust the ref admits:
	//   nil   → trusted only (safe default)
	//   true  → trusted only
	//   false → untrusted also allowed (explicit opt-in)
	// Untrusted execution is refused every ref that is not explicitly
	// untrusted-allowed.
	switch {
	case r.Trusted == nil || *r.Trusted:
		if !p.Trusted {
			return false
		}
	default: // *r.Trusted == false: untrusted-allowed
		// both trusted and untrusted may see it
	}
	if r.Branch != "" && r.Branch != p.Branch {
		return false
	}
	if r.Tag != "" && r.Tag != p.Tag {
		return false
	}
	if r.Event != "" && r.Event != p.Event {
		return false
	}
	if r.Fork != nil && *r.Fork != p.Fork {
		return false
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
		return false
	}
	// Scope-owner matching: a scoped ref must name the matching owner.
	switch r.Scope {
	case ScopeRepository:
		if r.Owner != "" && r.Owner != p.Repository {
			return false
		}
	case ScopeTeam:
		if r.Owner != "" && r.Owner != p.Team {
			return false
		}
	case ScopeOrganization:
		if r.Owner != "" && r.Owner != p.Org {
			return false
		}
	case ScopeEnvironment:
		if r.Owner != "" && r.Owner != p.Environment {
			return false
		}
	case ScopeJob:
		// A job-scoped ref MUST name its job: an empty owner would match
		// every job and leak across the execution boundary.
		if r.Owner == "" || r.Owner != p.Job {
			return false
		}
	case ScopeStep:
		if r.Owner == "" || r.Owner != p.Step {
			return false
		}
	}
	return true
}

// Hierarchy is the secret resolution store. It is the product-facing
// replacement for hidden precedence: every lookup is explainable.
type Hierarchy struct {
	refs []SecretRef
}

// NewHierarchy builds an empty hierarchy.
func NewHierarchy() *Hierarchy { return &Hierarchy{} }

// Add installs one secret ref.
func (h *Hierarchy) Add(r SecretRef) {
	h.refs = append(h.refs, r)
}

// Explanation is the `kiwi secret explain` report.
type Explanation struct {
	Name         string `json:"name"`
	Source       string `json:"source,omitempty"`
	OverriddenBy string `json:"overridden_by,omitempty"`
	Available    bool   `json:"available"`
	Reason       string `json:"reason"`
	Expires      string `json:"expires,omitempty"`
	Provider     string `json:"provider,omitempty"`
	// Consulted lists every ref considered, most-specific first.
	Consulted []string `json:"consulted"`
}

// Explain reports why a secret does or does not resolve for the policy.
func (h *Hierarchy) Explain(name string, p Policy) Explanation {
	e := Explanation{Name: name}
	var hit *SecretRef
	byScope := map[Scope][]SecretRef{}
	for _, r := range h.refs {
		if r.Name == name {
			byScope[r.Scope] = append(byScope[r.Scope], r)
		}
	}
	// Explain walks LEAST-specific first: "source" is where the secret is
	// defined; "overridden by" names the more specific ref that wins.
	// Resolve still takes the most specific match.
	for i := len(HierarchyOrder) - 1; i >= 0; i-- {
		scope := HierarchyOrder[i]
		for _, r := range byScope[scope] {
			label := string(r.Scope)
			if r.Owner != "" {
				label += " " + r.Owner
			}
			e.Consulted = append(e.Consulted, label)
			if !r.matches(p) {
				continue
			}
			if hit == nil {
				cp := r
				hit = &cp
				e.Source = label
				if !r.ExpiresAt.IsZero() {
					e.Expires = r.ExpiresAt.UTC().Format(time.RFC3339)
				}
				e.Provider = r.Provider
			} else {
				// A MORE specific match overrides the definition.
				e.OverriddenBy = label
				cp := r
				hit = &cp
				if !r.ExpiresAt.IsZero() {
					e.Expires = r.ExpiresAt.UTC().Format(time.RFC3339)
				}
				e.Provider = r.Provider
			}
		}
	}
	if hit == nil {
		e.Available = false
		e.Reason = reasonUnavailable(name, p, h.refs)
		return e
	}
	e.Available = true
	e.Reason = reasonAvailable(*hit, p)
	return e
}

func reasonAvailable(r SecretRef, p Policy) string {
	parts := []string{}
	if r.Branch != "" {
		parts = append(parts, "branch="+r.Branch)
	}
	if r.Tag != "" {
		parts = append(parts, "tag="+r.Tag)
	}
	if r.Event != "" {
		parts = append(parts, "event="+r.Event)
	}
	if r.Trusted != nil && *r.Trusted {
		parts = append(parts, "trusted only")
	}
	if r.Fork != nil && !*r.Fork {
		parts = append(parts, "non-fork only")
	}
	if len(parts) == 0 {
		return "unrestricted at this scope"
	}
	return strings.Join(parts, ", ")
}

func reasonUnavailable(name string, p Policy, refs []SecretRef) string {
	var n int
	for _, r := range refs {
		if r.Name == name {
			n++
		}
	}
	if n == 0 {
		return "no secret named " + name
	}
	if !p.Trusted {
		return "untrusted execution is refused every secret (trust floor)"
	}
	if p.Fork {
		return "fork execution is refused this secret"
	}
	return "no ref at any scope matches this policy"
}

// Resolve returns the winning value. The hierarchy walk is most-specific
// first; the first policy match wins. Two matching refs at the SAME scope are
// ambiguous authority and fail closed — resolution never depends on
// insertion order.
func (h *Hierarchy) Resolve(ctx context.Context, name string, p Policy) (string, error) {
	e := h.Explain(name, p)
	if !e.Available {
		return "", fmt.Errorf("secret %q unavailable: %s", name, e.Reason)
	}
	for _, scope := range HierarchyOrder {
		var hits []SecretRef
		for _, r := range h.refs {
			if r.Name != name || r.Scope != scope || !r.matches(p) {
				continue
			}
			hits = append(hits, r)
		}
		if len(hits) == 0 {
			continue
		}
		if len(hits) > 1 {
			return "", fmt.Errorf("secret %q is ambiguous at scope %s (%d matching refs): fail closed", name, scope, len(hits))
		}
		if hits[0].Value == "" {
			return "", fmt.Errorf("secret %q at %s has no value", name, scope)
		}
		return hits[0].Value, nil
	}
	return "", fmt.Errorf("secret %q unavailable: %s", name, e.Reason)
}

// Provider adapts the hierarchy to the secrets.Provider seam.
type HierarchyProvider struct {
	H *Hierarchy
	P Policy
}

func (p HierarchyProvider) Get(ctx context.Context, name string) (string, error) {
	return p.H.Resolve(ctx, name, p.P)
}

// Names lists every secret name in the hierarchy (sorted, deduplicated).
func (h *Hierarchy) Names() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range h.refs {
		if !seen[r.Name] {
			seen[r.Name] = true
			out = append(out, r.Name)
		}
	}
	sort.Strings(out)
	return out
}
