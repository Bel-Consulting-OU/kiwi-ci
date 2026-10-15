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
		// A scoped ref without an owner is a wildcard — refuse it. Global
		// inheritance is ScopeInstance, never an omitted owner.
		if r.Owner == "" || r.Owner != p.Repository {
			return false
		}
	case ScopeTeam:
		if r.Owner == "" || r.Owner != p.Team {
			return false
		}
	case ScopeOrganization:
		if r.Owner == "" || r.Owner != p.Org {
			return false
		}
	case ScopeEnvironment:
		if r.Owner == "" || r.Owner != p.Environment {
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

// secretDecision is the ONE precedence mechanism. Resolve consumes it and
// Explain renders it — the two can never disagree (an explanatory security
// interface must be observationally equivalent to the authority decision).
type secretDecision struct {
	winner     *SecretRef
	source     string
	overridden string
	ambiguous  bool
	consulted  []string
}

// decide walks the hierarchy and records BOTH the definition (least
// specific match) and the winner (most specific match). Two matches at the
// winning scope are ambiguous — fail closed. Resolve consumes the winner;
// Explain renders source=definition and overridden_by=winner. One engine,
// two views.
func (h *Hierarchy) decide(name string, p Policy) secretDecision {
	var d secretDecision
	byScope := map[Scope][]SecretRef{}
	for _, r := range h.refs {
		if r.Name == name {
			byScope[r.Scope] = append(byScope[r.Scope], r)
		}
	}
	// Consulted trail: least specific first (the audit order).
	for i := len(HierarchyOrder) - 1; i >= 0; i-- {
		for _, r := range byScope[HierarchyOrder[i]] {
			label := string(r.Scope)
			if r.Owner != "" {
				label += " " + r.Owner
			}
			d.consulted = append(d.consulted, label)
		}
	}
	// Definition = first match walking LEAST specific first.
	for i := len(HierarchyOrder) - 1; i >= 0; i-- {
		for _, r := range byScope[HierarchyOrder[i]] {
			if !r.matches(p) {
				continue
			}
			label := string(r.Scope)
			if r.Owner != "" {
				label += " " + r.Owner
			}
			d.source = label
			goto winner
		}
	}
	// No match at all.
	return d
winner:
	// Winner = first match walking MOST specific first (Resolve order).
	for _, scope := range HierarchyOrder {
		var hits []SecretRef
		for _, r := range byScope[scope] {
			if r.matches(p) {
				hits = append(hits, r)
			}
		}
		if len(hits) == 0 {
			continue
		}
		if len(hits) > 1 {
			d.ambiguous = true
			cp := hits[0]
			d.winner = &cp
			return d
		}
		cp := hits[0]
		d.winner = &cp
		if d.source == "" {
			d.source = string(scope)
			if cp.Owner != "" {
				d.source += " " + cp.Owner
			}
		}
		winLabel := string(scope)
		if cp.Owner != "" {
			winLabel += " " + cp.Owner
		}
		d.overridden = winLabel
		return d
	}
	return d
}

// Explain reports why a secret does or does not resolve for the policy.
// It renders the same decision Resolve consumes — never a second precedence
// implementation.
func (h *Hierarchy) Explain(name string, p Policy) Explanation {
	d := h.decide(name, p)
	e := Explanation{Name: name, Consulted: d.consulted}
	if d.ambiguous {
		e.Available = false
		e.Reason = fmt.Sprintf("ambiguous at scope %s (%d matching refs): fail closed", d.source, 2)
		return e
	}
	if d.winner == nil {
		e.Available = false
		e.Reason = reasonUnavailable(name, p, h.refs)
		return e
	}
	e.Available = true
	e.Source = d.source
	e.OverriddenBy = d.overridden
	if !d.winner.ExpiresAt.IsZero() {
		e.Expires = d.winner.ExpiresAt.UTC().Format(time.RFC3339)
	}
	e.Provider = d.winner.Provider
	e.Reason = reasonAvailable(*d.winner, p)
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
func (h *Hierarchy) Resolve(_ context.Context, name string, p Policy) (string, error) {
	// The SAME decision Explain renders — never a second precedence path.
	d := h.decide(name, p)
	if d.ambiguous {
		return "", fmt.Errorf("secret %q is ambiguous at scope %s: fail closed", name, d.source)
	}
	if d.winner == nil {
		return "", fmt.Errorf("secret %q unavailable: %s", name, reasonUnavailable(name, p, h.refs))
	}
	if d.winner.Value == "" {
		return "", fmt.Errorf("secret %q at %s has no value", name, d.source)
	}
	return d.winner.Value, nil
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
