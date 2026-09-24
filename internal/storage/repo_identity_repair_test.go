package storage

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

// TestPlanStoredRepoIdentity pins the R2-B migration classifier: a clone URL
// proves the canonical "host/full-name" storage identity, a host-less record
// is stored with the explicit alias spelling (plain owner/name or the a1:
// nested form), and a row where neither interpretation can be proven is
// quarantined instead of guessed.
func TestPlanStoredRepoIdentity(t *testing.T) {
	a1Nested := auth.RepoAlias{FullName: "group/sub/project"}.Serialized()
	cases := []struct {
		name         string
		stored       string
		url          string
		full         string
		wantAction   RepoIdentityRepairAction
		wantExplicit string
	}{
		{
			name:         "url canonical unchanged",
			stored:       "gitlab.company.com/group/sub/project",
			url:          "https://gitlab.company.com/group/sub/project.git",
			full:         "group/sub/project",
			wantAction:   RepoIdentityKeep,
			wantExplicit: "gitlab.company.com/group/sub/project",
		},
		{
			name:         "url proves canonical over a bare alias",
			stored:       "acme/backend",
			url:          "https://github.com/acme/backend.git",
			full:         "acme/backend",
			wantAction:   RepoIdentityRewrite,
			wantExplicit: "github.com/acme/backend",
		},
		{
			name:         "url proves canonical over a different host",
			stored:       "gitlab.example/acme/backend",
			url:          "https://github.com/acme/backend.git",
			full:         "acme/backend",
			wantAction:   RepoIdentityRewrite,
			wantExplicit: "github.com/acme/backend",
		},
		{
			name:         "legacy url-less nested verbatim rewrites to a1",
			stored:       "group/sub/project",
			url:          "",
			full:         "group/sub/project",
			wantAction:   RepoIdentityRewrite,
			wantExplicit: a1Nested,
		},
		{
			name:         "url-less owner/name stays a plain alias",
			stored:       "acme/backend",
			url:          "",
			full:         "acme/backend",
			wantAction:   RepoIdentityKeep,
			wantExplicit: "acme/backend",
		},
		{
			name:         "explicit a1 is already the nested alias form",
			stored:       a1Nested,
			url:          "",
			full:         "group/sub/project",
			wantAction:   RepoIdentityKeep,
			wantExplicit: a1Nested,
		},
		{
			name:         "r1 identity is already explicit and kept",
			stored:       auth.RepoIdentity{Host: "github.com", FullName: "acme/backend"}.Serialized(),
			url:          "",
			full:         "",
			wantAction:   RepoIdentityKeep,
			wantExplicit: auth.RepoIdentity{Host: "github.com", FullName: "acme/backend"}.Serialized(),
		},
		{
			name:         "untagged nested with no evidence is quarantined",
			stored:       "group/sub/project",
			url:          "",
			full:         "",
			wantAction:   RepoIdentityQuarantine,
			wantExplicit: QuarantinedRepoIdentity("group/sub/project"),
		},
		{
			name:         "host-less full name vs host-bearing stored value is quarantined",
			stored:       "gitlab/group/sub/project",
			url:          "",
			full:         "group/sub/project",
			wantAction:   RepoIdentityQuarantine,
			wantExplicit: QuarantinedRepoIdentity("gitlab/group/sub/project"),
		},
		{
			name:         "an already-quarantined row is stable",
			stored:       QuarantinedRepoIdentity("group/sub/project"),
			url:          "",
			full:         "",
			wantAction:   RepoIdentityKeep,
			wantExplicit: QuarantinedRepoIdentity("group/sub/project"),
		},
		{
			name:         "empty identity with a URL host stays empty",
			stored:       "",
			url:          "https://github.com/acme/backend.git",
			full:         "acme/backend",
			wantAction:   RepoIdentityKeep,
			wantExplicit: "",
		},
		{
			// R3-B: the old early return left this row with no identity at
			// all (empty repo_id, no URL, nested full name). With no URL host
			// the full name proves a host-less record, so it is stamped with
			// the explicit nested alias form.
			name:         "empty identity with a nested full name is stamped a1",
			stored:       "",
			url:          "",
			full:         "group/sub/project",
			wantAction:   RepoIdentityRewrite,
			wantExplicit: a1Nested,
		},
		{
			name:         "empty identity with a plain full name is stamped as the plain alias",
			stored:       "",
			url:          "",
			full:         "acme/backend",
			wantAction:   RepoIdentityRewrite,
			wantExplicit: "acme/backend",
		},
		{
			name:         "empty identity with no evidence stays empty",
			stored:       "",
			url:          "",
			full:         "",
			wantAction:   RepoIdentityKeep,
			wantExplicit: "",
		},
		{
			name:         "empty identity with an unparseable full name stays empty",
			stored:       "",
			url:          "",
			full:         "bad name",
			wantAction:   RepoIdentityKeep,
			wantExplicit: "",
		},
		{
			name:         "bare name in the url field is not read as a host and the nested full name is stamped a1",
			stored:       "",
			url:          "acme/backend",
			full:         "group/sub/project",
			wantAction:   RepoIdentityRewrite,
			wantExplicit: a1Nested,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PlanStoredRepoIdentity(tc.stored, tc.url, tc.full)
			if got.Action != tc.wantAction || got.Explicit != tc.wantExplicit {
				t.Fatalf("PlanStoredRepoIdentity(%q,%q,%q) = {%v %q %q}, want {%v %q}",
					tc.stored, tc.url, tc.full, got.Action, got.Explicit, got.Reason, tc.wantAction, tc.wantExplicit)
			}
		})
	}
}

// TestPlanStoredRepoIdentityIdempotent: applying the planner to its own output
// is a no-op, so the repair can run.
func TestPlanStoredRepoIdentityIdempotent(t *testing.T) {
	for _, tc := range []struct{ stored, url, full string }{
		{"group/sub/project", "", "group/sub/project"},
		{"", "", "group/sub/project"},
		{"", "", "acme/backend"},
		{"acme/backend", "https://github.com/acme/backend.git", "acme/backend"},
		{"gitlab.company.com/group/sub/project", "https://gitlab.company.com/group/sub/project.git", "group/sub/project"},
		{auth.RepoIdentity{Host: "gitlab", FullName: "team/sub/project"}.Serialized(), "", ""},
	} {
		first := PlanStoredRepoIdentity(tc.stored, tc.url, tc.full)
		second := PlanStoredRepoIdentity(first.Explicit, tc.url, tc.full)
		if second.Action != RepoIdentityKeep || second.Explicit != first.Explicit {
			t.Fatalf("planner not idempotent for %q: first=%+v second=%+v", tc.stored, first, second)
		}
	}
}

// TestQuarantinedRepoIdentityIsReservedCanonical: the quarantine replacement
// is a well-formed canonical storage identity on a host no operator
// configures, so every policy/RBAC grant misses it (fail closed).
func TestQuarantinedRepoIdentityIsReservedCanonical(t *testing.T) {
	q := QuarantinedRepoIdentity("group/sub/project")
	if !strings.HasPrefix(q, RepoIdentityQuarantineHost+"/") {
		t.Fatalf("quarantine identity %q does not use the reserved host", q)
	}
	grant, err := auth.ParseStoredRepoID(q)
	if err != nil {
		t.Fatalf("quarantine identity %q does not parse: %v", q, err)
	}
	id, ok := grant.Identity()
	if !ok {
		t.Fatalf("quarantine identity %q parses as a bare alias, want a canonical identity", q)
	}
	if id.Host != RepoIdentityQuarantineHost {
		t.Fatalf("quarantine host = %q, want %q", id.Host, RepoIdentityQuarantineHost)
	}
}
