package auth

import "testing"

func TestCanonicalRepoID(t *testing.T) {
	cases := []struct {
		host, fullName, want string
	}{
		{"github.com", "Bel-Consulting-OU/kiwi-ci", "github.com/Bel-Consulting-OU/kiwi-ci"},
		{"gitlab.com", "o/r", "gitlab.com/o/r"},
		{"", "o/r", "o/r"},
		{"github.com", "github.com/already/hosted", "github.com/already/hosted"},
		{"", "", ""},
		{"forge.example.com", "  ", ""},
	}
	for _, c := range cases {
		if got := CanonicalRepoID(c.host, c.fullName); got != c.want {
			t.Errorf("CanonicalRepoID(%q, %q) = %q, want %q", c.host, c.fullName, got, c.want)
		}
	}
}

func TestActionForMapping(t *testing.T) {
	cases := []struct {
		method, path string
		wantAction   Action
		wantHandled  bool
	}{
		{"POST", "/api/v1/runs", ActionRun, true},
		{"GET", "/api/v1/runs", ActionRead, true},
		{"GET", "/api/v1/runs/r1", ActionRead, true},
		{"POST", "/api/v1/runs/r1/cancel", ActionCancel, true},
		{"POST", "/api/v1/runs/r1/rerun", ActionRerun, true},
		{"GET", "/api/v1/runs/r1/jobs", ActionRead, true},
		{"GET", "/api/v1/runs/r1/logs", ActionRead, true},
		{"GET", "/api/v1/runs/r1/logs/stream", ActionRead, true},
		{"GET", "/api/v1/runs/r1/tests", ActionRead, true},
		{"GET", "/api/v1/runs/r1/deployments", ActionRead, true},
		{"GET", "/api/v1/runs/r1/snapshots", ActionRead, true},
		{"GET", "/api/v1/runs/r1/snapshots/s1", ActionRead, true},
		{"GET", "/api/v1/runs/r1/artifacts", ActionArtifactRead, true},
		{"GET", "/api/v1/artifacts/a1", ActionArtifactRead, true},
		{"GET", "/api/v1/artifacts/a1/provenance", ActionArtifactRead, true},
		{"GET", "/api/v1/test-intelligence", ActionRead, true},
		{"POST", "/api/v1/jobs/j1/approve", ActionApprove, true},
		{"GET", "/api/v1/runners", ActionRead, true},
		{"POST", "/api/v1/runners/r1/drain", ActionRunnerManage, true},
		{"POST", "/api/v1/runners/r1/disable", ActionRunnerManage, true},
		{"POST", "/api/v1/runners/r1/enable", ActionRunnerManage, true},
		{"GET", "/api/v1/schedules", ActionPolicyManage, true},
		{"PUT", "/api/v1/schedules", ActionPolicyManage, true},
		{"POST", "/api/v1/schedules/s1/trigger", ActionPolicyManage, true},
		// Non-RBAC routes are unhandled.
		{"GET", "/api/v1/jobs/j1/test-shards", "", false},
		{"POST", "/api/v1/jobs/j1/heartbeat", "", false},
		{"PUT", "/api/v1/jobs/j1/artifacts/name", "", false},
		{"GET", "/api/v1/jobs/j1/dependencies/p/a", "", false},
		{"GET", "/api/v1/jobs/j1/cache/k", "", false},
		{"PUT", "/api/v1/jobs/j1/cache/k", "", false},
		{"POST", "/api/v1/runners/register", "", false},
		{"POST", "/api/v1/runners/r1/next", "", false},
		{"GET", "/api/v1/audit", "", false},
		{"POST", "/api/v1/drain", "", false},
		{"GET", "/api/v1/drain", "", false},
		{"POST", "/api/v1/runners/enroll", "", false},
		{"GET", "/api/v1/oidc/jwks", "", false},
		{"POST", "/api/v1/jobs/j1/secrets", "", false},
		{"GET", "/metrics", "", false},
	}
	for _, c := range cases {
		action, _, handled := ActionFor(c.method, c.path)
		if handled != c.wantHandled || (c.wantHandled && action != c.wantAction) {
			t.Errorf("ActionFor(%s %s) = (%q, handled=%v), want (%q, handled=%v)", c.method, c.path, action, handled, c.wantAction, c.wantHandled)
		}
	}
}

func TestAuthorizeCanonicalRepoKeys(t *testing.T) {
	p := Principal{Subject: "r", Repositories: map[string]RepositoryPermission{
		"o/r": {Read: true},
	}}
	// Bare full-name lookup.
	if !Authorize(p, ActionRead, "o/r", false) {
		t.Fatal("bare full-name repo key not honored")
	}
	// Canonical ID falls back to the bare key.
	if !Authorize(p, ActionRead, "github.com/o/r", false) {
		t.Fatal("canonical repo id must fall back to the bare full-name key")
	}
	// Other repos denied (explicit map is authoritative for scope).
	if Authorize(p, ActionRead, "github.com/other/x", false) {
		t.Fatal("repo outside the map granted")
	}
	// Canonical keys work as the primary key too.
	p2 := Principal{Subject: "r", Repositories: map[string]RepositoryPermission{
		"github.com/o/r": {Approve: true},
	}}
	if !Authorize(p2, ActionApprove, "github.com/o/r", false) {
		t.Fatal("canonical key not honored directly")
	}
	if !Authorize(p2, ActionApprove, "o/r", false) {
		t.Fatal("bare key must fall back to the canonical key")
	}
}

func TestAuthorizeRoleFallbackWithMapPresent(t *testing.T) {
	// A role still applies to repos not mentioned in the map.
	p := Principal{Subject: "r", Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{
		"o/a": {Cancel: true},
	}}
	if !Authorize(p, ActionRead, "o/b", false) {
		t.Fatal("role-derived read must apply to repos outside the map")
	}
	if !Authorize(p, ActionCancel, "o/a", false) {
		t.Fatal("map cancel grant ignored")
	}
	if Authorize(p, ActionCancel, "o/b", false) {
		t.Fatal("cancel must not apply to repos outside the map without the role")
	}
}
