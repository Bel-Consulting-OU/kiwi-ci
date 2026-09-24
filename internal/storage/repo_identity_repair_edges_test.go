package storage

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

// TestRepoIdentityRepairActionString pins the operator-facing rendering of
// every classification, including the zero value.
func TestRepoIdentityRepairActionString(t *testing.T) {
	cases := map[RepoIdentityRepairAction]string{
		RepoIdentityKeep:             "keep",
		RepoIdentityRewrite:          "rewrite",
		RepoIdentityQuarantine:       "quarantine",
		RepoIdentityRepairAction(99): "keep",
	}
	for action, want := range cases {
		if got := action.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", action, got, want)
		}
	}
}

// TestPlanStoredRepoIdentityBranches covers the planner branches the main
// table does not reach: URL-shaped evidence without a derivable path,
// malformed explicit spellings, unparseable full names, a bare alias with no
// evidence, and an unparseable stored value.
func TestPlanStoredRepoIdentityBranches(t *testing.T) {
	cases := []struct {
		name         string
		stored       string
		url          string
		full         string
		wantAction   RepoIdentityRepairAction
		wantExplicit string
	}{
		{
			name:         "url-shaped evidence falls back to the full name",
			stored:       "acme/backend",
			url:          "https://github.com",
			full:         "acme/backend",
			wantAction:   RepoIdentityRewrite,
			wantExplicit: "github.com/acme/backend",
		},
		{
			name:         "malformed a1 is quarantined",
			stored:       auth.RepoAliasPrefix + "=",
			url:          "",
			full:         "",
			wantAction:   RepoIdentityQuarantine,
			wantExplicit: QuarantinedRepoIdentity(auth.RepoAliasPrefix + "="),
		},
		{
			name:         "malformed r1 is quarantined",
			stored:       auth.RepoIdentityPrefix + "bad",
			url:          "",
			full:         "",
			wantAction:   RepoIdentityQuarantine,
			wantExplicit: QuarantinedRepoIdentity(auth.RepoIdentityPrefix + "bad"),
		},
		{
			name:         "unparseable full name with no url is quarantined",
			stored:       "weird",
			url:          "",
			full:         "bad//name",
			wantAction:   RepoIdentityQuarantine,
			wantExplicit: QuarantinedRepoIdentity("weird"),
		},
		{
			name:         "disagreeing non-canonical stored value rewrites to the alias",
			stored:       "other/name",
			url:          "",
			full:         "acme/backend",
			wantAction:   RepoIdentityRewrite,
			wantExplicit: "acme/backend",
		},
		{
			name:         "unparseable stored value with no evidence is quarantined",
			stored:       "bad//id",
			url:          "",
			full:         "",
			wantAction:   RepoIdentityQuarantine,
			wantExplicit: QuarantinedRepoIdentity("bad//id"),
		},
		{
			name:         "bare alias with no evidence is kept",
			stored:       "acme/backend",
			url:          "",
			full:         "",
			wantAction:   RepoIdentityKeep,
			wantExplicit: "acme/backend",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PlanStoredRepoIdentity(tc.stored, tc.url, tc.full)
			if got.Action != tc.wantAction || got.Explicit != tc.wantExplicit {
				t.Fatalf("PlanStoredRepoIdentity(%q,%q,%q) = {%v %q}, want {%v %q}",
					tc.stored, tc.url, tc.full, got.Action, got.Explicit, tc.wantAction, tc.wantExplicit)
			}
		})
	}
}

// TestQuarantinedRepoIdentityRecoverable pins that the reserved identity is a
// canonical, non-alias storage value that neither policy nor RBAC matches, and
// that the original value is recoverable from the encoded tail.
func TestQuarantinedRepoIdentityRecoverable(t *testing.T) {
	q := QuarantinedRepoIdentity("group/sub/project")
	if !strings.HasPrefix(q, RepoIdentityQuarantineHost+"/") {
		t.Fatalf("quarantine identity %q does not carry the reserved host", q)
	}
	grant, err := auth.ParseStoredRepoID(q)
	if err != nil {
		t.Fatalf("quarantine identity is not a parseable stored id: %v", err)
	}
	if !grant.IsIdentity() {
		t.Fatalf("quarantine identity parsed as %v, want a canonical identity", grant.Kind())
	}
	id, _ := grant.Identity()
	if id.Host != RepoIdentityQuarantineHost {
		t.Fatalf("quarantine host = %q, want %q", id.Host, RepoIdentityQuarantineHost)
	}
	if strings.Contains(q, "group/sub/project") {
		t.Fatal("quarantine identity embeds the original slash path verbatim")
	}
}
