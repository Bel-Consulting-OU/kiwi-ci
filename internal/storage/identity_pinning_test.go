package storage

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestRepoIDForPrefersPolicyRepoID: the policy identity (the BASE repository
// of a fork PR) is authoritative for every authorization/quota/cache
// consumer; a legacy record without one falls back to RepoID and then to the
// URL + full-name derivation.
func TestRepoIDForPrefersPolicyRepoID(t *testing.T) {
	job := model.Job{
		RepoID: "github.com/head/forked", PolicyRepoID: "github.com/base/forked",
		RepoURL: "https://github.com/head/forked.git", RepoFullName: "head/forked",
	}
	if got := RepoIDForJob(job); got != "github.com/base/forked" {
		t.Fatalf("RepoIDForJob = %q, want the policy (base) identity", got)
	}
	run := model.Run{
		RepoID: "github.com/head/forked", PolicyRepoID: "github.com/base/forked",
		Repo: "https://github.com/head/forked.git", RepoFullName: "head/forked",
	}
	if got := RepoIDForRun(run); got != "github.com/base/forked" {
		t.Fatalf("RepoIDForRun = %q, want the policy (base) identity", got)
	}
	// Legacy: no PolicyRepoID → stored RepoID wins, then the derivation.
	if got := RepoIDForJob(model.Job{RepoID: "github.com/o/r", RepoURL: "https://mirror.example/o/r.git"}); got != "github.com/o/r" {
		t.Fatalf("legacy stored RepoID = %q", got)
	}
	if got := RepoIDForJob(model.Job{RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r"}); got != "github.com/o/r" {
		t.Fatalf("legacy derivation = %q", got)
	}
	// The runner ACL and quota keys follow the policy identity.
	if !RepoAllowed([]string{"github.com/base/forked"}, job) {
		t.Fatal("base-repository ACL entry must admit the fork job")
	}
	if RepoAllowed([]string{"github.com/head/forked"}, job) {
		t.Fatal("head-repository ACL entry must not authorize the fork job")
	}
}

// TestCanonicalizationParityWithAuth pins that the storage mirrors produce
// the same canonical hosts and repository identities as auth, so quota keys
// and RBAC keys can never disagree on an identity.
func TestCanonicalizationParityWithAuth(t *testing.T) {
	hosts := []string{
		"github.com", "GITHUB.COM", "github.com.", "github.com:443", "github.com:8443",
		"HTTPS://GitHub.com", "https://GitHub.com:443/acme/repo.git",
		"ssh://git@github.com:22/acme/repo.git", "git@github.com:acme/repo.git",
		"gitlab.company.com", "https://gitlab.company.com:8443/acme/repo.git", "",
	}
	for _, raw := range hosts {
		if got, want := RepoHost(raw), auth.CanonicalHost(raw); got != want {
			t.Errorf("RepoHost(%q) = %q, auth.CanonicalHost = %q", raw, got, want)
		}
	}
	urls := []string{
		"https://github.com/acme/repo.git",
		"HTTPS://GitHub.com./acme/repo.git",
		"https://github.com:443/acme/repo.git",
		"ssh://git@github.com:22/acme/repo.git",
		"git@github.com:acme/repo.git",
		"https://github.com:8443/acme/repo.git",
	}
	for _, raw := range urls {
		got := RepoIDFor("", raw, "")
		want := auth.CanonicalRepoID(auth.CanonicalHost(raw), RepoFullNameFromURL(raw))
		if got != want {
			t.Errorf("RepoIDFor(%q) = %q, auth-derived = %q", raw, got, want)
		}
	}
	// The host property itself: equivalent spellings collapse, ports stay.
	for _, raw := range []string{"GITHUB.COM", "github.com.", "github.com:443"} {
		if got := RepoHost(raw + "/acme/repo"); got != "github.com" {
			t.Errorf("RepoHost(%q) = %q, want github.com", raw, got)
		}
	}
	if got := RepoHost("https://github.com:8443/acme/repo.git"); got != "github.com:8443" {
		t.Fatalf("non-default port lost: %q", got)
	}
}
