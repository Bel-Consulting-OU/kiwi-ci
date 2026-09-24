package storage

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// TestQuarantinedRepoIdentityHashedAndCollisionResistant pins the R1-2 fix:
// the reserved identity is a canonical, non-alias storage value carrying the
// SHA-256 hex digest of the ORIGINAL value. Two originals whose legacy base64
// spellings differed only by letter CASE (which the path case-folding readers
// apply would have collapsed to one identity) now produce DISTINCT IDs, and
// the digest never embeds the original value.
func TestQuarantinedRepoIdentityHashedAndCollisionResistant(t *testing.T) {
	original := "group/sub/project"
	q := QuarantinedRepoIdentity(original)
	if !strings.HasPrefix(q, RepoIdentityQuarantineHost+"/quarantined/") {
		t.Fatalf("quarantine identity %q does not carry the reserved host/path", q)
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
	if strings.Contains(q, original) {
		t.Fatal("quarantine identity embeds the original slash path verbatim")
	}
	tail := strings.TrimPrefix(q, RepoIdentityQuarantineHost+"/quarantined/")
	if len(tail) != 64 || strings.ToLower(tail) != tail {
		t.Fatalf("quarantine digest %q is not a lowercase 64-hex SHA-256", tail)
	}
	sum := sha256.Sum256([]byte(original))
	if want := hex.EncodeToString(sum[:]); tail != want {
		t.Fatalf("quarantine digest = %q, want sha256 hex %q", tail, want)
	}
	// The prior base64url tail was case-sensitive: two originals whose base64
	// encodings differed ONLY by letter case produced tails that the
	// case-folding readers (LOWER / FoldRepoFullName) collapsed onto one
	// identity. The digest must keep them distinct. The fixture is built from
	// two one-byte originals whose RawURLEncoding is "AA"/"aA".
	rawA := string([]byte{0x00})
	rawB := "h"
	encA := base64.RawURLEncoding.EncodeToString([]byte(rawA))
	encB := base64.RawURLEncoding.EncodeToString([]byte(rawB))
	if encA == encB || !strings.EqualFold(encA, encB) {
		t.Fatalf("fixture is not a case-only base64 pair: %q vs %q", encA, encB)
	}
	a := QuarantinedRepoIdentity(rawA)
	b := QuarantinedRepoIdentity(rawB)
	if a == b {
		t.Fatalf("case-differing originals collided: %q", a)
	}
	if strings.EqualFold(a, b) {
		t.Fatalf("case-differing originals collide after case folding: %q vs %q", a, b)
	}
}
