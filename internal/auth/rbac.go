package auth

import "strings"

// Action is one authorization decision the control plane can make. Repo-
// scoped actions (read, run, approve, cancel, rerun, artifact_read) consult
// repo-specific grants first; the rest are decided by global roles.
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
//   - RoleRun grants untrusted run only; trusted_run requires an explicit
//     RoleTrustedRun, the admin role, or a repo TrustedRun grant;
//   - ActionRun with trusted=true is equivalent to ActionTrustedRun.
func Authorize(p Principal, action Action, repo string, trusted bool) bool {
	if p.Has(RoleAdmin) {
		return true
	}
	if perm, ok := p.repoEntry(repo); ok {
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

// repoEntry resolves the repo-specific permission entry for repo. The map
// may be keyed by the canonical repository ID (host/owner/name) or by the
// bare full name (owner/name): a canonical lookup falls back to the bare
// form and a bare lookup falls back to canonical keys with the same bare
// part, so both keying conventions work.
func (p Principal) repoEntry(repo string) (RepositoryPermission, bool) {
	if perm, ok := p.Repositories[repo]; ok {
		return perm, true
	}
	host, bare, hasHost := splitCanonicalRepo(repo)
	if hasHost {
		perm, ok := p.Repositories[bare]
		return perm, ok
	}
	// repo is a bare full name: match canonical keys whose bare part is repo.
	for key, perm := range p.Repositories {
		if _, kb, kHost := splitCanonicalRepo(key); kHost && kb == bare {
			return perm, true
		}
	}
	_ = host
	return RepositoryPermission{}, false
}

// CanonicalRepoID renders the canonical repository identity "<host>/<fullName>"
// (e.g. github.com/Bel-Consulting-OU/kiwi-ci). A fullName that already
// carries a forge host is returned unchanged; an empty fullName stays empty.
// The forge host is usually derived from the run's repo URL when the stored
// full name lacks one.
func CanonicalRepoID(forgeHost, fullName string) string {
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		return ""
	}
	if parts := strings.SplitN(fullName, "/", 2); len(parts) == 2 && strings.Contains(parts[0], ".") {
		return fullName
	}
	host := strings.TrimSpace(forgeHost)
	if host == "" {
		return fullName
	}
	return host + "/" + fullName
}

// splitCanonicalRepo splits a canonical "host/owner/name" ID into host and
// bare "owner/name" parts, reporting whether the input carried a host.
func splitCanonicalRepo(repo string) (host, bare string, hasHost bool) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 2 && strings.Contains(parts[0], ".") {
		return parts[0], parts[1], true
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
			case "jobs", "logs", "tests", "deployments", "snapshots":
				if method == "GET" {
					return ActionRead, "", true
				}
			case "artifacts":
				if method == "GET" {
					return ActionArtifactRead, "", true
				}
			}
		}
		if len(rest) == 4 && method == "GET" {
			if (rest[2] == "logs" && rest[3] == "stream") || rest[2] == "snapshots" {
				return ActionRead, "", true
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
