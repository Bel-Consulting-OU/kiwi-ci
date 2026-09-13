// Package auth implements operator/admin authentication, role-based access
// control, and the HTTP middleware that binds authenticated principals to
// requests for the Kiwi control plane.
package auth

// Role names one capability a principal may hold globally. Repo-scoped
// grants live in Principal.Repositories and take precedence over roles for
// the repositories they mention.
type Role string

const (
	RoleRead         Role = "read"
	RoleRun          Role = "run"
	RoleTrustedRun   Role = "trusted_run"
	RoleApprove      Role = "approve"
	RoleCancel       Role = "cancel"
	RoleRerun        Role = "rerun"
	RoleArtifactRead Role = "artifact_read"
	RoleRunnerManage Role = "runner_manage"
	RolePolicyManage Role = "policy_manage"
	RoleAdmin        Role = "admin"
)

// RepositoryPermission is a per-repository grant set. A repo entry present
// in Principal.Repositories is authoritative for that repo: it is used
// instead of role-derived permissions, not merged with them.
type RepositoryPermission struct {
	Read         bool `json:"read,omitempty"`
	Run          bool `json:"run,omitempty"`
	TrustedRun   bool `json:"trusted_run,omitempty"`
	Approve      bool `json:"approve,omitempty"`
	Cancel       bool `json:"cancel,omitempty"`
	Rerun        bool `json:"rerun,omitempty"`
	ArtifactRead bool `json:"artifact_read,omitempty"`
}

// Principal is the authenticated identity bound to a request. Roles are
// global capabilities; Repositories holds per-repo overrides.
type Principal struct {
	Subject      string                          `json:"subject"`
	Roles        []Role                          `json:"roles,omitempty"`
	Repositories map[string]RepositoryPermission `json:"repositories,omitempty"`
}

// Has reports whether the principal holds the given role.
func (p Principal) Has(role Role) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// RepoPerm returns the effective permission set for repo. A repo-specific
// entry, when present, is authoritative; otherwise permissions derive from
// roles (admin grants everything).
func (p Principal) RepoPerm(repo string) RepositoryPermission {
	if perm, ok := p.Repositories[repo]; ok {
		return perm
	}
	admin := p.Has(RoleAdmin)
	return RepositoryPermission{
		Read:       admin || p.Has(RoleRead),
		Run:        admin || p.Has(RoleRun),
		TrustedRun: admin || p.Has(RoleTrustedRun),
	}
}

// CanRun reports whether the principal may execute jobs in repo. RoleRun
// grants untrusted execution only: trusted execution requires an explicit
// RoleTrustedRun, the admin role, or a repo-specific TrustedRun grant, and
// vice versa (trusted_run implies nothing about untrusted run).
func (p Principal) CanRun(repo string, trusted bool) bool {
	return Authorize(p, ActionRun, repo, trusted)
}
