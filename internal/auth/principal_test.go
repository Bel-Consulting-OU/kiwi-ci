package auth

import "testing"

func TestPrincipalHas(t *testing.T) {
	p := Principal{Subject: "u", Roles: []Role{RoleRun, RoleApprove}}
	if !p.Has(RoleRun) || !p.Has(RoleApprove) {
		t.Fatal("declared roles not reported")
	}
	if p.Has(RoleAdmin) || p.Has(RoleCancel) {
		t.Fatal("undeclared roles reported")
	}
	if p.Has("bogus") {
		t.Fatal("undeclared role string must not match")
	}
}

func TestRunDoesNotImplyTrustedRun(t *testing.T) {
	p := Principal{Subject: "bot", Roles: []Role{RoleRun}}
	if !p.CanRun("github.com/kiwi/kiwi", false) {
		t.Fatal("RoleRun must grant untrusted run")
	}
	if p.CanRun("github.com/kiwi/kiwi", true) {
		t.Fatal("RoleRun must not grant trusted run")
	}
	trusted := Principal{Subject: "ops", Roles: []Role{RoleTrustedRun}}
	if !trusted.CanRun("github.com/kiwi/kiwi", true) {
		t.Fatal("RoleTrustedRun must grant trusted run")
	}
	if trusted.CanRun("github.com/kiwi/kiwi", false) {
		t.Fatal("RoleTrustedRun must not grant untrusted run")
	}
}

func TestAdminGrantsAll(t *testing.T) {
	p := Principal{Subject: "admin", Roles: []Role{RoleAdmin}}
	for _, a := range []Action{ActionRead, ActionRun, ActionTrustedRun, ActionApprove, ActionCancel, ActionRerun, ActionArtifactRead, ActionRunnerManage, ActionPolicyManage} {
		if !Authorize(p, a, "any/repo", true) {
			t.Fatalf("admin denied %s", a)
		}
	}
	if !p.CanRun("any/repo", true) {
		t.Fatal("admin denied trusted run")
	}
	if !Authorize(p, ActionAdmin, "any/repo", false) {
		t.Fatal("admin role must satisfy ActionAdmin")
	}
}

func TestRepoMapPrecedence(t *testing.T) {
	repo := "github.com/kiwi/kiwi"
	// Role grant is overridden (denied) by an explicit repo entry.
	denied := Principal{Subject: "bot", Roles: []Role{RoleRun},
		Repositories: map[string]RepositoryPermission{repo: {Read: true}}}
	if Authorize(denied, ActionRun, repo, false) {
		t.Fatal("repo entry must take precedence over RoleRun")
	}
	if !Authorize(denied, ActionRead, repo, false) {
		t.Fatal("repo entry read grant ignored")
	}
	// Role applies to repos without an entry.
	if !Authorize(denied, ActionRun, "other/repo", false) {
		t.Fatal("role must still apply to repos without an entry")
	}
	// Repo entry grants run to a principal without RoleRun.
	granted := Principal{Subject: "ci", Repositories: map[string]RepositoryPermission{repo: {Run: true}}}
	if !Authorize(granted, ActionRun, repo, false) {
		t.Fatal("repo entry run grant ignored")
	}
	// Repo entry Run does not grant trusted run.
	if Authorize(granted, ActionRun, repo, true) {
		t.Fatal("repo entry run must not grant trusted run")
	}
	trustedGrant := Principal{Subject: "ops", Repositories: map[string]RepositoryPermission{repo: {TrustedRun: true}}}
	if !Authorize(trustedGrant, ActionTrustedRun, repo, false) {
		t.Fatal("repo entry trusted_run grant ignored")
	}
	// Admin still overrides a repo entry denying everything.
	lockout := Principal{Subject: "root", Roles: []Role{RoleAdmin},
		Repositories: map[string]RepositoryPermission{repo: {}}}
	if !Authorize(lockout, ActionRun, repo, true) {
		t.Fatal("admin must override repo entries")
	}
}

func TestRepoPermDerivation(t *testing.T) {
	p := Principal{Subject: "bot", Roles: []Role{RoleRun, RoleRead}}
	perm := p.RepoPerm("any/repo")
	if !perm.Run || !perm.Read {
		t.Fatalf("role-derived perms wrong: %+v", perm)
	}
	if perm.TrustedRun {
		t.Fatal("role-derived trusted_run must be false without RoleTrustedRun")
	}
	repo := "github.com/kiwi/kiwi"
	p.Repositories = map[string]RepositoryPermission{repo: {TrustedRun: true}}
	if got := p.RepoPerm(repo); !got.TrustedRun || got.Run || got.Read {
		t.Fatalf("repo entry not authoritative: %+v", got)
	}
}

func TestAuthorizeActionTable(t *testing.T) {
	runOnly := Principal{Subject: "bot", Roles: []Role{RoleRun}}
	cases := []struct {
		name    string
		p       Principal
		action  Action
		trusted bool
		want    bool
	}{
		{"run untrusted", runOnly, ActionRun, false, true},
		{"run trusted", runOnly, ActionRun, true, false},
		{"trusted_run", runOnly, ActionTrustedRun, false, false},
		{"approve", runOnly, ActionApprove, false, false},
		{"cancel", runOnly, ActionCancel, false, false},
		{"rerun", runOnly, ActionRerun, false, false},
		{"artifact_read", runOnly, ActionArtifactRead, false, false},
		{"read", runOnly, ActionRead, false, false},
		{"runner_manage", runOnly, ActionRunnerManage, false, false},
		{"policy_manage", runOnly, ActionPolicyManage, false, false},
		{"admin", runOnly, ActionAdmin, false, false},
	}
	for _, c := range cases {
		if got := Authorize(c.p, c.action, "any/repo", c.trusted); got != c.want {
			t.Errorf("%s: Authorize = %v, want %v", c.name, got, c.want)
		}
	}
	ops := Principal{Subject: "ops", Roles: []Role{RoleApprove, RoleCancel, RoleRerun, RoleArtifactRead, RoleRunnerManage, RolePolicyManage}}
	for _, c := range []struct {
		action Action
	}{
		{ActionApprove}, {ActionCancel}, {ActionRerun}, {ActionArtifactRead}, {ActionRunnerManage}, {ActionPolicyManage},
	} {
		if !Authorize(ops, c.action, "any/repo", false) {
			t.Errorf("role %s not honored", c.action)
		}
	}
}
