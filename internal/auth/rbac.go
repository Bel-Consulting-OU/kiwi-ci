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
//   - repo may be a canonical repository ID (host/owner/name): an entry
//     keyed by the bare owner/name full name also satisfies it;
//   - CONFLICTING entries for the same repository identity (canonically
//     equivalent keys with different permission sets) deny every action:
//     they never fall through to global roles, because that would let a
//     map duplicate silently widen a grant;
//   - global roles apply only when the principal declares NO usable entry
//     for the repository (RepoNoEntry);
//   - RoleRun grants untrusted run only; trusted_run requires an explicit
//     RoleTrustedRun, the admin role, or a repo TrustedRun grant;
//   - ActionRun with trusted=true is equivalent to ActionTrustedRun.
func Authorize(p Principal, action Action, repo string, trusted bool) bool {
	if p.Has(RoleAdmin) {
		return true
	}
	perm, res := p.repoEntry(repo)
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
// the scoped collection projections (run lists and serving runners), so
// NormalizeRepoKey, default-port/host-case canonicalization, bare aliases and
// the ambiguity fail-closed rule resolve identically everywhere. repo accepts
// a canonical repository ID ("forge-host/owner/name") or a bare full name;
// the call is equivalent to Authorize(p, ActionRead, repo, false) and shares
// the full repository-entry semantics (an entry present for the repository is
// authoritative; conflicting entries deny; global roles cover only the
// repositories the map does not mention).
func CanReadRepo(p Principal, repo string) bool {
	return Authorize(p, ActionRead, repo, false)
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

// repoEntry resolves the repo-specific permission entry for repo. The map
// may be keyed by the canonical repository ID (host/owner/name) or by the
// bare full name (owner/name): a canonical lookup falls back to the bare
// form and a bare lookup falls back to canonical keys with the same bare
// part, so both keying conventions work. Stored keys and the lookup key are
// canonicalized first (host case, one trailing dot, default ports), so
// equivalent spellings of the same forge host address the same grant. The
// resolution is DETERMINISTIC and fails closed: when several equivalent keys
// carry DIFFERENT permission sets at any stage (equivalent canonical keys,
// canonical→bare, bare→canonical, or duplicate spellings of one canonical
// key) the result is RepoConflict, which Authorize turns into an immediate
// denial for every action. Only RepoNoEntry — a repository the map genuinely
// does not mention — leaves the decision to the global roles.
func (p Principal) repoEntry(repo string) (RepositoryPermission, RepoEntryResult) {
	repo = NormalizeRepoKey(repo)
	if perm, res := lookupRepoEntry(p.Repositories, repo); res != RepoNoEntry {
		return perm, res
	}
	_, bare, hasHost := splitCanonicalRepo(repo)
	if hasHost {
		return lookupRepoEntry(p.Repositories, bare)
	}
	// repo is a bare full name: match canonical keys whose bare part is repo.
	var match RepositoryPermission
	found, ambiguous := false, false
	seen := map[string]RepositoryPermission{}
	for key, perm := range p.Repositories {
		nk := NormalizeRepoKey(key)
		if prev, ok := seen[nk]; ok {
			// Duplicate spellings of one canonical key: identical grants
			// are the same entry, different grants are a conflict.
			if prev != perm {
				ambiguous = true
			}
			continue
		}
		seen[nk] = perm
		if _, kb, kHost := splitCanonicalRepo(nk); kHost && kb == bare {
			if !found {
				match, found = perm, true
			} else if perm != match {
				ambiguous = true
			}
		}
	}
	switch {
	case ambiguous:
		return RepositoryPermission{}, RepoConflict
	case found:
		return match, RepoFound
	}
	return RepositoryPermission{}, RepoNoEntry
}

// lookupRepoEntry resolves the entry whose key canonicalizes to target.
// Equivalent keys carrying IDENTICAL permission sets resolve to that single
// entry; equivalent keys carrying DIFFERENT permission sets resolve to
// RepoConflict (fail closed) instead of depending on map iteration order.
func lookupRepoEntry(m map[string]RepositoryPermission, target string) (RepositoryPermission, RepoEntryResult) {
	var match RepositoryPermission
	found, ambiguous := false, false
	for key, perm := range m {
		if NormalizeRepoKey(key) != target {
			continue
		}
		if !found {
			match, found = perm, true
		} else if perm != match {
			ambiguous = true
		}
	}
	switch {
	case ambiguous:
		return RepositoryPermission{}, RepoConflict
	case found:
		return match, RepoFound
	}
	return RepositoryPermission{}, RepoNoEntry
}

// CanonicalRepoID renders the canonical repository identity "<host>/<fullName>"
// (e.g. github.com/Bel-Consulting-OU/kiwi-ci). The forge host is
// canonicalized first (lowercase, one trailing dot stripped, default port
// dropped, userinfo stripped: see CanonicalHost), and a full name that
// already starts with a canonically equivalent spelling of that host is
// reduced to its owner/name remainder, so re-canonicalizing a stored
// identity is idempotent. The forge host stays authoritative when the full
// name embeds a DIFFERENT host: such a name is prefixed with the canonical
// host, keeping identities host-scoped even when the first segment merely
// looks like a host (the GitLab group "acme.co/service" previously collapsed
// to the bare "acme.co/service", letting a github.com grant authorize a
// gitlab.example run). With no known forge host the trimmed full name is
// returned unchanged; an empty full name stays empty. The forge host is
// usually derived from the run's repo URL.
func CanonicalRepoID(forgeHost, fullName string) string {
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		return ""
	}
	host := CanonicalHost(forgeHost)
	if first, rest, ok := splitHostLike(fullName); ok {
		canonFirst := CanonicalHost(first)
		if host == "" || canonFirst == host {
			// The full name already carries this host: keep one canonical
			// spelling and drop the duplicate prefix.
			if host == "" {
				host = canonFirst
			}
			fullName = rest
		}
	}
	if host == "" {
		return fullName
	}
	return host + "/" + fullName
}

// splitCanonicalRepo splits a canonical "host/owner/name" ID into host and
// bare "owner/name" parts, reporting whether the input carried a host. A
// dotted first segment alone is not enough: a canonical ID always carries
// owner/name after the host, so the remainder must itself contain a slash.
// Without that rule a GitLab group with a dot in its name ("acme.co/service")
// would be misread as host "acme.co" + bare "service", and an unrelated bare
// alias "service" would match it.
func splitCanonicalRepo(repo string) (host, bare string, hasHost bool) {
	if first, rest, ok := splitHostLike(repo); ok {
		return first, rest, true
	}
	return "", repo, false
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
