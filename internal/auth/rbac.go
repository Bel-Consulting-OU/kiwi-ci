package auth

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
//   - RoleRun grants untrusted run only; trusted_run requires an explicit
//     RoleTrustedRun, the admin role, or a repo TrustedRun grant;
//   - ActionRun with trusted=true is equivalent to ActionTrustedRun.
func Authorize(p Principal, action Action, repo string, trusted bool) bool {
	if p.Has(RoleAdmin) {
		return true
	}
	if perm, ok := p.Repositories[repo]; ok {
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
