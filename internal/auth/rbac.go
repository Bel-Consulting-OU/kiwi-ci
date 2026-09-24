package auth

import "strings"

// Action is one authorization decision the control plane can make. Repo-
// scoped actions (read, run, approve, cancel, rerun, artifact_read) consult
// repo-specific grants first; the rest are decided by global roles. ActionAdmin
// is global-only: it is the admin role or nothing, and it gates the workspace
// snapshot archive download.
type Action string

const (
	ActionRead         Action = "read"
	ActionRun          Action = "run"
	ActionTrustedRun   Action = "trusted_run"
	ActionApprove      Action = "approve"
	ActionCancel       Action = "cancel"
	ActionRerun        Action = "rerun"
	ActionArtifactRead Action = "artifact_read"
	ActionRunnerManage Action = "runner_manage"
	ActionPolicyManage Action = "policy_manage"
	ActionAdmin        Action = "admin"
)

// Authorize decides whether the principal may perform action on repo.
//
// Semantics:
//   - the admin role grants every action;
//   - repo-specific entries take precedence when present for repo;
//   - repo is read with the typed positional rule (ParseStoredRepoID):
//     "host/owner/name" (three or more segments, dotted OR dotless host) is a
//     canonical identity, and a name with fewer segments is a bare alias.
//     Dots are never consulted. The typed entry points AuthorizeIdentity and
//     AuthorizeAlias take the values directly;
//   - a canonical identity matches canonical entries of the same
//     (canonical host, full name), and falls back to an EXPLICIT bare grant
//     with the same full name (a bare grant addresses every forge presenting
//     the name);
//   - the LEGACY string entry point keeps the historical positional
//     fallback in BOTH directions: a bare string (a host-less address) also
//     falls back to canonical entries with the same full name, and
//     conflicting equivalent entries at any stage fail closed. The typed
//     AuthorizeAlias entry point does NOT: a typed RepoAlias matches ONLY
//     explicit bare grants, because it is an explicit statement that the
//     value is host-less rather than a legacy string whose host is unknown;
//   - CONFLICTING entries for the same repository identity (canonically
//     equivalent identity keys, or equivalent bare keys, with different
//     permission sets) deny every action: they never fall through to global
//     roles, because that would let a map duplicate silently widen a grant;
//   - global roles apply only when the principal declares NO usable entry
//     for the repository (RepoNoEntry); an empty repository string is the
//     deliberately repo-less case and also uses global roles, but a
//     NON-empty unparseable repository string is denied outright (it names
//     no repository, so a global role must not be borrowed for it);
//   - RoleRun grants untrusted run only; trusted_run requires an explicit
//     RoleTrustedRun, the admin role, or a repo TrustedRun grant;
//   - ActionRun with trusted=true is equivalent to ActionTrustedRun.
func Authorize(p Principal, action Action, repo string, trusted bool) bool {
	if p.Has(RoleAdmin) {
		// The admin role grants every action, including the repo-less global
		// actions and an empty/malformed repository string that carries no
		// identity the map could mention.
		return true
	}
	grant, err := ParseStoredRepoID(repo)
	if err != nil {
		// A non-empty but unparseable repository string carries no identity
		// the map could mention, so it must NOT fall through to the global
		// roles: that would let a malformed scope borrow a broad role and
		// silently authorize a repository the caller never named. Only the
		// deliberately repo-less empty string is decided by global roles
		// (the same path serves the global actions).
		if strings.TrimSpace(repo) == "" {
			return authorizeGlobalRoles(p, action, trusted)
		}
		return false
	}
	return authorizeGrantMode(p, action, grant, trusted, true)
}

// AuthorizeIdentity is the typed canonical-identity authorization entry
// point: the repository is specified by its explicit (host, full name)
// identity, so no string shape is interpreted and a dotless host is just
// another host.
func AuthorizeIdentity(p Principal, action Action, id RepoIdentity, trusted bool) bool {
	return authorizeGrantMode(p, action, IdentityGrant(id), trusted, false)
}

// AuthorizeAlias is the typed bare-alias authorization entry point: a typed
// RepoAlias is an EXPLICIT host-less value, so it matches ONLY explicit bare
// grants and never borrows a canonical grant.
func AuthorizeAlias(p Principal, action Action, alias RepoAlias, trusted bool) bool {
	return authorizeGrantMode(p, action, AliasGrant(alias), trusted, false)
}

// authorizeGrantMode is the single repository-grant resolution behind every
// Authorize entry point. legacyBareFallback selects whether a LEGACY bare
// string may fall back to canonical entries with the same full name (the
// historical positional behavior); the typed AuthorizeAlias passes false.
func authorizeGrantMode(p Principal, action Action, grant RepoGrant, trusted, legacyBareFallback bool) bool {
	if p.Has(RoleAdmin) {
		return true
	}
	perm, res := p.repoEntryGrantMode(grant, legacyBareFallback)
	if res == RepoConflict {
		// The repository's explicit grants disagree with each other: the
		// entry is unusable, and resolving through map iteration order
		// could flip the decision. Deny instead of consulting roles.
		return false
	}
	if res == RepoFound {
		switch action {
		case ActionRead:
			return perm.Read
		case ActionRun:
			if trusted {
				return perm.TrustedRun
			}
			return perm.Run
		case ActionTrustedRun:
			return perm.TrustedRun
		case ActionApprove:
			return perm.Approve
		case ActionCancel:
			return perm.Cancel
		case ActionRerun:
			return perm.Rerun
		case ActionArtifactRead:
			return perm.ArtifactRead
		}
	}
	return authorizeGlobalRoles(p, action, trusted)
}

// authorizeGlobalRoles resolves an action from the principal's global roles,
// used only when the repository map declares no usable entry.
func authorizeGlobalRoles(p Principal, action Action, trusted bool) bool {
	switch action {
	case ActionRead:
		return p.Has(RoleRead)
	case ActionRun:
		if trusted {
			return p.Has(RoleTrustedRun)
		}
		return p.Has(RoleRun)
	case ActionTrustedRun:
		return p.Has(RoleTrustedRun)
	case ActionApprove:
		return p.Has(RoleApprove)
	case ActionCancel:
		return p.Has(RoleCancel)
	case ActionRerun:
		return p.Has(RoleRerun)
	case ActionArtifactRead:
		return p.Has(RoleArtifactRead)
	case ActionRunnerManage:
		return p.Has(RoleRunnerManage)
	case ActionPolicyManage:
		return p.Has(RolePolicyManage)
	case ActionAdmin:
		return false
	}
	return false
}

// CanReadRepo reports whether the principal may read repository repo. It is
// THE repository-visibility decision shared by the per-run read routes and
// the scoped collection projections (run lists and serving runners), so host
// canonicalization, typed identity/alias resolution and the ambiguity
// fail-closed rule resolve identically everywhere. repo accepts a canonical
// repository ID ("host/owner/name", dotted or dotless host) or a bare full
// name, parsed by ParseStoredRepoID; the call is equivalent to
// Authorize(p, ActionRead, repo, false) and shares the full repository-entry
// semantics (an entry present for the repository is authoritative;
// conflicting entries deny; global roles cover only the repositories the map
// does not mention).
func CanReadRepo(p Principal, repo string) bool {
	return Authorize(p, ActionRead, repo, false)
}

// CanReadRepoIdentity is the typed canonical-identity read decision. A
// canonical identity is authorized by an identical canonical grant or by an
// explicit bare grant with the same full name.
func CanReadRepoIdentity(p Principal, id RepoIdentity) bool {
	return AuthorizeIdentity(p, ActionRead, id, false)
}

// CanReadRepoAlias is the typed bare-alias read decision. A bare alias is
// authorized ONLY by an explicit bare grant with the same full name: a
// canonical grant for one forge never authorizes another forge's repository
// of the same name.
func CanReadRepoAlias(p Principal, alias RepoAlias) bool {
	return AuthorizeAlias(p, ActionRead, alias, false)
}

// CanReadAnyRepoAlias reports whether the principal holds a READ capability
// that can cover at least one repository presenting alias.FullName: the
// global read/admin role, a bare read grant for the name, or a canonical
// read grant whose full name is the alias (the alias addresses every forge,
// so any of those forges' repositories may match). It is the coarse
// query-form gate for repository-spanning endpoints that address a bare
// name; the per-candidate authorization still runs through
// CanReadRepoIdentity, so a canonical grant only ever opens its own forge.
func CanReadAnyRepoAlias(p Principal, alias RepoAlias) bool {
	if p.Has(RoleAdmin) || p.Has(RoleRead) {
		return true
	}
	fullName := alias.normalized().FullName
	if fullName == "" {
		return false
	}
	for key, perm := range p.Repositories {
		if !perm.Read {
			continue
		}
		grant, err := ParseStoredRepoID(key)
		if err != nil {
			continue
		}
		if grant.IsAlias() {
			if a, _ := grant.Alias(); a.FullName == fullName {
				return true
			}
			continue
		}
		if id, _ := grant.Identity(); id.FullName == fullName {
			return true
		}
	}
	return false
}

// CanReadAnyRepo reports whether the principal may read at least one
// repository: the admin role, the global read role, or any repository entry
// with Read enabled. Repository-spanning collection endpoints use it as their
// coarse capability gate BEFORE resolving each candidate individually through
// CanReadRepo. It is deliberately NOT a per-repository decision: an entry
// whose equivalent duplicate key conflicts still counts here, because the
// per-repository resolution then answers RepoConflict and denies every
// action; a principal with no read capability at all is refused outright
// instead of receiving an empty collection.
func CanReadAnyRepo(p Principal) bool {
	if p.Has(RoleAdmin) || p.Has(RoleRead) {
		return true
	}
	for _, perm := range p.Repositories {
		if perm.Read {
			return true
		}
	}
	return false
}

// RepoEntryResult reports how the principal's repository map resolved a
// repository identity. It is a tri-state on purpose: the boolean it replaces
// could not distinguish "the principal declares nothing for this repository"
// (global roles apply) from "the principal declares contradictory entries"
// (the repository is poisoned and every action must be denied).
type RepoEntryResult int

const (
	// RepoNoEntry: the map declares no entry for the repository, so global
	// roles decide. This is the ONLY result that may fall through to roles.
	RepoNoEntry RepoEntryResult = iota
	// RepoFound: exactly one effective entry exists for the repository.
	// Equivalent duplicate spellings with IDENTICAL permission sets count
	// as that one entry.
	RepoFound
	// RepoConflict: several equivalent entries carry DIFFERENT permission
	// sets, so no entry can be chosen without depending on Go's randomized
	// map iteration order. Authorize denies every action on the repository
	// instead of falling back to roles.
	RepoConflict
)

// repoEntry resolves the repo-specific permission entry for a repository
// string with the typed positional rule (ParseStoredRepoID) and delegates to
// repoEntryGrant (the legacy string path, which keeps the positional
// bare↔canonical fallback).
func (p Principal) repoEntry(repo string) (RepositoryPermission, RepoEntryResult) {
	grant, err := ParseStoredRepoID(repo)
	if err != nil {
		return RepositoryPermission{}, RepoNoEntry
	}
	return p.repoEntryGrant(grant)
}

// repoEntryGrant is repoEntryGrantMode with the legacy positional fallback
// enabled (the string-derived grant path and the repository-entry tests).
func (p Principal) repoEntryGrant(grant RepoGrant) (RepositoryPermission, RepoEntryResult) {
	return p.repoEntryGrantMode(grant, true)
}

// repoEntryGrantMode resolves the repo-specific permission entry for a typed
// grant. The principal's map keys are parsed with the same documented rule
// (ParseStoredRepoID), so a legacy canonical key written before typed
// identity ("github.com/o/r", or the dotless "gitlab/acme/widget") addresses
// the same identity it was derived from; an unusable key matches nothing.
//
// Resolution is DETERMINISTIC and fails closed:
//
//   - an identity lookup first considers canonical identity keys with the
//     same (canonical host, full name); when several DIFFERENT permission
//     sets collide there, the result is RepoConflict;
//   - on a canonical miss it considers EXPLICIT bare keys with the same full
//     name (a bare grant addresses every forge presenting the name), with the
//     same conflict rule;
//   - an alias lookup first considers explicit bare keys with the same full
//     name (with the same conflict rule). A legacy bare STRING additionally
//     falls back to canonical keys sharing its full name when
//     legacyBareFallback is set, so the string entry point keeps the
//     historical positional behavior; the typed AuthorizeAlias passes false,
//     so a typed RepoAlias never borrows a canonical grant.
//
// Only RepoNoEntry — a repository the map genuinely does not mention — leaves
// the decision to the global roles.
func (p Principal) repoEntryGrantMode(grant RepoGrant, legacyBareFallback bool) (RepositoryPermission, RepoEntryResult) {
	if grant.Kind() == RepoGrantInvalid {
		return RepositoryPermission{}, RepoNoEntry
	}
	identities := map[string]RepositoryPermission{}
	identityFull := map[string]map[string]bool{}
	aliases := map[string]RepositoryPermission{}
	identityConflict := map[string]bool{}
	aliasConflict := map[string]bool{}
	record := func(m map[string]RepositoryPermission, conflicts map[string]bool, key string, perm RepositoryPermission) {
		if prev, ok := m[key]; ok {
			if prev != perm {
				conflicts[key] = true
			}
			return
		}
		m[key] = perm
	}
	for key, perm := range p.Repositories {
		keyGrant, err := ParseStoredRepoID(key)
		if err != nil {
			// Unusable key: it can never match a repository.
			continue
		}
		if keyGrant.IsAlias() {
			a, _ := keyGrant.Alias()
			record(aliases, aliasConflict, a.FullName, perm)
			continue
		}
		id, _ := keyGrant.Identity()
		record(identities, identityConflict, id.ID(), perm)
		if identityFull[id.FullName] == nil {
			identityFull[id.FullName] = map[string]bool{}
		}
		identityFull[id.FullName][id.ID()] = true
	}
	resolve := func(m map[string]RepositoryPermission, conflicts map[string]bool, key string) (RepositoryPermission, RepoEntryResult) {
		if conflicts[key] {
			return RepositoryPermission{}, RepoConflict
		}
		if perm, ok := m[key]; ok {
			return perm, RepoFound
		}
		return RepositoryPermission{}, RepoNoEntry
	}
	// resolveAliasToIdentity mirrors the historical bare→canonical fallback:
	// among the canonical keys sharing the bare full name, exactly one
	// distinct permission set resolves (and several distinct sets, or a
	// conflicting identity, fail closed).
	resolveAliasToIdentity := func(fullName string) (RepositoryPermission, RepoEntryResult) {
		ids := identityFull[fullName]
		if len(ids) == 0 {
			return RepositoryPermission{}, RepoNoEntry
		}
		var match RepositoryPermission
		found, ambiguous := false, false
		for idKey := range ids {
			perm, res := resolve(identities, identityConflict, idKey)
			if res == RepoConflict {
				return RepositoryPermission{}, RepoConflict
			}
			if res != RepoFound {
				continue
			}
			if !found {
				match, found = perm, true
			} else if perm != match {
				ambiguous = true
			}
		}
		if ambiguous {
			return RepositoryPermission{}, RepoConflict
		}
		if found {
			return match, RepoFound
		}
		return RepositoryPermission{}, RepoNoEntry
	}
	if grant.IsAlias() {
		a, _ := grant.Alias()
		if perm, res := resolve(aliases, aliasConflict, a.FullName); res != RepoNoEntry {
			return perm, res
		}
		if !legacyBareFallback {
			return RepositoryPermission{}, RepoNoEntry
		}
		return resolveAliasToIdentity(a.FullName)
	}
	id, _ := grant.Identity()
	if perm, res := resolve(identities, identityConflict, id.ID()); res != RepoNoEntry {
		return perm, res
	}
	return resolve(aliases, aliasConflict, id.FullName)
}

// CanonicalRepoID renders the canonical repository identity "<host>/<fullName>"
// (e.g. github.com/Bel-Consulting-OU/kiwi-ci). The forge host is
// canonicalized first (lowercase, one trailing dot stripped, default port
// dropped, userinfo stripped: see CanonicalHost). A full name that already
// starts with a canonically equivalent spelling of that KNOWN host is reduced
// to its owner/name remainder, so re-canonicalizing a stored identity is
// idempotent. The host is never inferred from the full name: with no known
// forge host the trimmed full name is returned unchanged (and parses as a
// bare alias or, by the documented positional rule, as an identity whose first
// segment is the host), and a full name embedding a DIFFERENT host stays part
// of the name, keeping identities host-scoped. An empty full name stays empty.
// The forge host is usually derived from the run's repo URL.
//
// This is the storage/SQL-facing spelling (the exact string persisted in
// repository IDs). ACL configuration uses the unambiguous r1: form
// (RepoIdentity.Serialized).
func CanonicalRepoID(forgeHost, fullName string) string {
	host, full := canonicalRepoParts(forgeHost, fullName)
	if full == "" {
		return ""
	}
	if host == "" {
		return full
	}
	return host + "/" + full
}

// ActionFor maps a method+path pair onto the authorization decision the
// control plane makes for that route. It is the single route→action table
// shared by the server's auth() tier classification and the handler-level
// requireAction enforcement: the returned repo is empty because repository
// scope resolves from the addressed run/job/artifact at handler time. The
// bool reports whether the route is RBAC-mapped at all; routes outside the
// table are either public, runner-tier, or genuinely admin-only.
func ActionFor(method, path string) (Action, string, bool) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	// Canonical route shapes:
	//   api v1 runs | runs/{id} | runs/{id}/{sub} | runs/{id}/{sub}/{sid}
	//   api v1 jobs/{id}/{sub} | api v1 artifacts/{id}[/{sub}]
	//   api v1 runners | runners/{id}/{op} | api v1 test-intelligence
	//   api v1 schedules[/{id}/{sub}]
	if len(segs) < 3 || segs[0] != "api" || segs[1] != "v1" {
		return "", "", false
	}
	rest := segs[2:]
	switch rest[0] {
	case "runs":
		if len(rest) == 1 {
			if method == "POST" {
				return ActionRun, "", true
			}
			if method == "GET" {
				return ActionRead, "", true
			}
		}
		if len(rest) == 2 && method == "GET" {
			return ActionRead, "", true
		}
		if len(rest) == 3 {
			switch rest[2] {
			case "cancel":
				if method == "POST" {
					return ActionCancel, "", true
				}
			case "rerun":
				if method == "POST" {
					return ActionRerun, "", true
				}
			case "jobs", "logs", "tests", "deployments":
				if method == "GET" {
					return ActionRead, "", true
				}
			case "snapshots":
				// GET /api/v1/runs/{id}/snapshots is the snapshot record
				// LISTING: every record carries the workspace manifest
				// (file names, modes, sizes, SHA-256), the manifest root
				// digest and the archive digest — an inventory of the
				// private workspace archive (checkout, generated and
				// secret-derived files). That is the same class of data as
				// the archive download below, so the listing is admin tier
				// too: ActionAdmin scoped by the handler to the run's
				// canonical repository. A repository read grant (or
				// artifact_read) never satisfies it.
				if method == "GET" {
					return ActionAdmin, "", true
				}
			case "artifacts":
				if method == "GET" {
					return ActionArtifactRead, "", true
				}
			}
		}
		if len(rest) == 4 && method == "GET" {
			if rest[2] == "logs" && rest[3] == "stream" {
				return ActionRead, "", true
			}
			if rest[2] == "snapshots" {
				// GET /api/v1/runs/{id}/snapshots/{sid} streams the full
				// workspace archive (private checkout, generated code,
				// secret-derived files), so it is genuinely admin tier:
				// ActionAdmin scoped by the handler to the run's canonical
				// repository. The handler-level requireRunAdmin enforces
				// it so an authenticated non-admin is answered 403 (not
				// merely screened by the outer admin gate).
				return ActionAdmin, "", true
			}
		}
	case "jobs":
		if len(rest) == 3 && rest[2] == "approve" && method == "POST" {
			return ActionApprove, "", true
		}
	case "artifacts":
		if len(rest) == 2 && method == "GET" {
			return ActionArtifactRead, "", true
		}
		if len(rest) == 3 && rest[2] == "provenance" && method == "GET" {
			return ActionArtifactRead, "", true
		}
	case "runners":
		if len(rest) == 1 && method == "GET" {
			// The full runner inventory is an operations surface: only
			// runner_manage (or admin) principals may list it. Readers
			// use the redacted /runners/serving projection instead.
			return ActionRunnerManage, "", true
		}
		if len(rest) == 2 && rest[1] == "serving" && method == "GET" {
			return ActionRead, "", true
		}
		if len(rest) == 3 && method == "POST" {
			switch rest[2] {
			case "drain", "disable", "enable":
				return ActionRunnerManage, "", true
			}
		}
	case "runner-profiles":
		if len(rest) == 1 && (method == "GET" || method == "POST") {
			return ActionPolicyManage, "", true
		}
		if len(rest) == 2 && (method == "GET" || method == "PUT") {
			return ActionPolicyManage, "", true
		}
		if len(rest) == 4 && rest[2] == "cert" && method == "PUT" {
			return ActionPolicyManage, "", true
		}
	case "test-intelligence":
		if len(rest) == 1 && method == "GET" {
			return ActionRead, "", true
		}
	case "schedules":
		if len(rest) == 1 && (method == "GET" || method == "PUT") {
			return ActionPolicyManage, "", true
		}
		if len(rest) == 3 && rest[2] == "trigger" && method == "POST" {
			return ActionPolicyManage, "", true
		}
	}
	return "", "", false
}
