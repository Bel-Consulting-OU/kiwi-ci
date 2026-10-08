package auth

import (
	"fmt"
	"slices"
	"strings"
)

// Capability names one fine-grained permission an external controller
// principal (for example a Faktor-style consumer) can hold without the Kiwi
// admin role. Capabilities are deliberately SEPARATE from roles and
// RepositoryPermission:
//
//   - a capability never substitutes for an Action decision; it is an
//     additional grant consulted only by the routes that declare it (see the
//     server's capability route table);
//   - global capabilities (Principal.Capabilities) cover every repository;
//     repository-scoped capabilities (Principal.RepositoryCapabilities) are
//     resolved with the same canonical/alias grant matching as
//     Principal.Repositories, and a repo entry can only ADD capabilities —
//     a globally held capability is never removed by a repository entry;
//   - an empty repository string (a deliberately unscoped read) is covered
//     ONLY by a global capability or the admin role: a repository-scoped
//     grant names repositories and must not silently widen to "all".
type Capability string

const (
	// CapExecutionEventsRead allows reading the canonical execution event
	// stream (GET /api/v1/events, /api/v1/events/stream). Scoped to a run's
	// repository when a run_id is supplied; the unscoped cursor read requires
	// a global grant.
	CapExecutionEventsRead Capability = "execution.events:read"
	// CapEvidenceRead allows reading execution evidence: the audit trail
	// (global) and the exact-replay pipeline/payload export of a run
	// (run-scoped).
	CapEvidenceRead Capability = "evidence:read"
	// CapCheckpointsRead allows reading the workspace snapshot checkpoints of
	// a run: the record/manifest listing and the archive download.
	CapCheckpointsRead Capability = "checkpoints:read"
	// CapRunsCancel allows cancelling a run in the repositories it covers,
	// equivalent to the repo-scoped ActionCancel decision.
	CapRunsCancel Capability = "runs:cancel"
	// CapGraphMutationsWrite is RESERVED for the future generic graph API.
	// It is declared here (so it parses, validates and round-trips in token
	// files) but deliberately wires NO route yet: no handler consults it.
	CapGraphMutationsWrite Capability = "graph.mutations:write"
)

// KnownCapabilities returns every capability value this binary understands,
// in a stable order. Unknown values are rejected by ParseCapability, so a
// token file can never silently carry a misspelled grant that matches
// nothing.
func KnownCapabilities() []Capability {
	return []Capability{
		CapExecutionEventsRead,
		CapEvidenceRead,
		CapCheckpointsRead,
		CapRunsCancel,
		CapGraphMutationsWrite,
	}
}

// ParseCapability maps a capability string onto the known set. It is the
// ONLY place a Capability value is accepted from configuration; unknown or
// empty strings are rejected.
func ParseCapability(s string) (Capability, error) {
	switch Capability(s) {
	case CapExecutionEventsRead, CapEvidenceRead, CapCheckpointsRead, CapRunsCancel, CapGraphMutationsWrite:
		return Capability(s), nil
	}
	return "", fmt.Errorf("auth: unknown capability %q", s)
}

// HasCapability reports whether the principal's GLOBAL capability set (the
// capabilities that cover every repository) contains c.
func (p Principal) HasCapability(c Capability) bool {
	return capabilitySetContains(p.Capabilities, c)
}

// HasCapabilityInAnyScope reports whether the principal declares c anywhere:
// globally or in at least one repository-scoped capability grant. It is the
// coarse route-tier screen — "this principal may hold the capability" — and
// NOT an authorization decision; the handler resolves the addressed
// repository and calls AuthorizeCapability. A principal with only an
// unrelated repository grant therefore reaches the handler and is answered
// 403 there, never granted by this check.
func (p Principal) HasCapabilityInAnyScope(c Capability) bool {
	if p.HasCapability(c) {
		return true
	}
	for _, caps := range p.RepositoryCapabilities {
		if capabilitySetContains(caps, c) {
			return true
		}
	}
	return false
}

// AuthorizeCapability decides whether the principal may exercise capability
// in the scope of repo.
//
// Semantics (the capability analogue of Authorize):
//
//   - the admin role grants every capability;
//   - a GLOBAL capability (Principal.Capabilities) grants it on every
//     repository, including the repo-less (empty repo) case. It is checked
//     before the repository map because it is an unambiguous all-repository
//     statement: a conflict between repository-scoped entries can only
//     remove capabilities the principal does not hold globally;
//   - a NON-empty repo is resolved through the same typed, fail-closed
//     matcher as RepositoryPermission grants (resolveRepoGrantEntries): a
//     canonical identity matches identical canonical keys and falls back to
//     an explicit bare grant with the same full name, canonically equivalent
//     keys with DIFFERENT capability sets are a conflict and deny, and a
//     repo the map does not mention grants nothing here (there is no
//     role-style fallback: capabilities are opt-in);
//   - an EMPTY repo (or a non-empty repo string that names no repository)
//     is covered only by the admin role or a global capability: a
//     repository-scoped-only grant does NOT authorize an unscoped read.
func AuthorizeCapability(p Principal, capability Capability, repo string) bool {
	if p.Has(RoleAdmin) {
		return true
	}
	if p.HasCapability(capability) {
		return true
	}
	if strings.TrimSpace(repo) == "" {
		return false
	}
	grant, err := ParseStoredRepoID(repo)
	if err != nil {
		return false
	}
	caps, res := p.repoCapabilityEntryGrantMode(grant, true)
	if res != RepoFound {
		// RepoConflict (canonically equivalent entries disagree) and
		// RepoNoEntry both deny: repository-scoped capabilities never fall
		// back to anything.
		return false
	}
	return capabilitySetContains(caps, capability)
}

// repoCapabilityEntryGrantMode resolves the repository-scoped capability
// entry for a typed grant through the shared matcher. equality is set-based:
// capability spelling order and duplicates are irrelevant, so two rotation
// tokens with the same grants in different order are one effective identity.
func (p Principal) repoCapabilityEntryGrantMode(grant RepoGrant, legacyBareFallback bool) ([]Capability, RepoEntryResult) {
	return resolveRepoGrantEntries(p.RepositoryCapabilities, sameCapabilitySet, grant, legacyBareFallback)
}

// capabilitySetContains reports whether the capability set contains c.
func capabilitySetContains(caps []Capability, c Capability) bool {
	for _, have := range caps {
		if have == c {
			return true
		}
	}
	return false
}

// capabilitySet returns the set form of a capability list.
func capabilitySet(caps []Capability) map[Capability]struct{} {
	set := make(map[Capability]struct{}, len(caps))
	for _, c := range caps {
		set[c] = struct{}{}
	}
	return set
}

// sameCapabilitySet reports whether two capability lists carry the same set:
// order and duplicates are irrelevant. It is the equality used by
// effectivePrincipalEqual (rotation safety) and the conflict detector of the
// repository-scoped matcher.
func sameCapabilitySet(a, b []Capability) bool {
	setA := capabilitySet(a)
	setB := capabilitySet(b)
	if len(setA) != len(setB) {
		return false
	}
	for c := range setA {
		if _, ok := setB[c]; !ok {
			return false
		}
	}
	return true
}

// canonicalCapabilities renders a capability list in the deterministic
// persisted form: duplicates removed, sorted. An empty list renders as nil so
// the JSON field is omitted.
func canonicalCapabilities(caps []Capability) []Capability {
	if len(caps) == 0 {
		return nil
	}
	out := make([]Capability, 0, len(caps))
	seen := make(map[Capability]struct{}, len(caps))
	for _, c := range caps {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

// validatePrincipalCapabilities rejects every capability value outside the
// known set, in both the global and the repository-scoped grant. It never
// validates or rewrites the repository grant KEYS: like Repositories, those
// are kept verbatim in-process and normalized by Save (normalizePrincipal...)
// or strictly validated by Load (validatePrincipalRepoGrants).
func validatePrincipalCapabilities(p Principal) error {
	for _, c := range p.Capabilities {
		if _, err := ParseCapability(string(c)); err != nil {
			return err
		}
	}
	for key, caps := range p.RepositoryCapabilities {
		for _, c := range caps {
			if _, err := ParseCapability(string(c)); err != nil {
				return fmt.Errorf("repository grant %q: %w", key, err)
			}
		}
	}
	return nil
}

// normalizePrincipalRepoCapabilities is the Save-side migration for
// capability grants, mirroring normalizePrincipalRepoGrants: every
// repository grant key is rewritten to its explicit serialized spelling
// (ParseRepoGrant's documented positional rule), two canonically equivalent
// keys with different capability sets fail closed instead of silently
// collapsing, and equivalent keys with identical sets dedup. The capability
// lists themselves are canonicalized (dedup + sort) for deterministic
// persistence. A key that cannot be parsed fails closed with the offending
// string in the error.
func normalizePrincipalRepoCapabilities(p Principal) (Principal, error) {
	p.Capabilities = canonicalCapabilities(p.Capabilities)
	if len(p.RepositoryCapabilities) == 0 {
		return p, nil
	}
	normalized := make(map[string][]Capability, len(p.RepositoryCapabilities))
	for key, caps := range p.RepositoryCapabilities {
		grant, err := ParseRepoGrant(key)
		if err != nil {
			return Principal{}, err
		}
		serialized := grant.Serialized()
		if serialized == "" {
			return Principal{}, &RepoGrantError{Grant: key, Detail: "grant renders no usable identity"}
		}
		canon := canonicalCapabilities(caps)
		if prev, ok := normalized[serialized]; ok {
			if !sameCapabilitySet(prev, canon) {
				return Principal{}, &RepoGrantError{
					Grant:  key,
					Detail: fmt.Sprintf("canonically equivalent grant %q already carries a different capability set", serialized),
				}
			}
			continue
		}
		normalized[serialized] = canon
	}
	p.RepositoryCapabilities = normalized
	return p, nil
}
