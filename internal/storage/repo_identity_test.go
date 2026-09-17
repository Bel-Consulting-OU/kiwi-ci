package storage

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestRepoIDForLegacyFallback pins the ONE storage-side identity
// derivation: a stored RepoID is authoritative, and a legacy record without
// one derives the same value the server ingress derives from the clone URL
// and full name.
func TestRepoIDForLegacyFallback(t *testing.T) {
	cases := []struct {
		name         string
		repoID       string
		repoURL      string
		repoFullName string
		want         string
	}{
		{"stored wins", "github.com/acme/backend", "https://mirror.example/acme/backend.git", "acme/backend", "github.com/acme/backend"},
		{"legacy url+full", "", "https://github.com/acme/backend.git", "acme/backend", "github.com/acme/backend"},
		{"legacy self-hosted", "", "https://gitlab.company.com/acme/backend.git", "acme/backend", "gitlab.company.com/acme/backend"},
		{"legacy url only", "", "https://gitlab.company.com/acme/backend.git", "", "gitlab.company.com/acme/backend"},
		{"legacy scp-like", "", "git@github.com:acme/backend.git", "acme/backend", "github.com/acme/backend"},
		{"bare full name", "", "", "acme/backend", "acme/backend"},
		{"empty", "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RepoIDFor(tc.repoID, tc.repoURL, tc.repoFullName); got != tc.want {
				t.Fatalf("RepoIDFor = %q, want %q", got, tc.want)
			}
			job := model.Job{RepoID: tc.repoID, RepoURL: tc.repoURL, RepoFullName: tc.repoFullName}
			if got := RepoIDForJob(job); got != tc.want {
				t.Fatalf("RepoIDForJob = %q, want %q", got, tc.want)
			}
			run := model.Run{RepoID: tc.repoID, Repo: tc.repoURL, RepoFullName: tc.repoFullName}
			if got := RepoIDForRun(run); got != tc.want {
				t.Fatalf("RepoIDForRun = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestQuotaKeysCanonicalIdentity: quota counters key on the canonical
// identity and its host/owner team key, so same-named repositories on
// different forges never share a counter. Legacy URL inputs keep deriving
// the same pair.
func TestQuotaKeysCanonicalIdentity(t *testing.T) {
	github := QuotaKeys("github.com/acme/backend")
	if len(github) != 2 || github[0] != "github.com/acme/backend" || github[1] != "github.com/acme" {
		t.Fatalf("github quota keys = %v", github)
	}
	gitlab := QuotaKeys("gitlab.company.com/acme/backend")
	if len(gitlab) != 2 || gitlab[0] != "gitlab.company.com/acme/backend" || gitlab[1] != "gitlab.company.com/acme" {
		t.Fatalf("gitlab quota keys = %v", gitlab)
	}
	for _, a := range github {
		for _, b := range gitlab {
			if a == b {
				t.Fatalf("quota key %q collides across forges", a)
			}
		}
	}
	// Nested GitLab groups keep the host + first segment team key.
	nested := QuotaKeys("gitlab.company.com/group/sub/backend")
	if len(nested) != 2 || nested[1] != "gitlab.company.com/group" {
		t.Fatalf("nested quota keys = %v", nested)
	}
	// A bare owner/name has no distinct team key.
	if bare := QuotaKeys("acme/backend"); len(bare) != 1 || bare[0] != "acme/backend" {
		t.Fatalf("bare quota keys = %v", bare)
	}
	// A GitLab group containing a dot is not a host.
	if dotted := QuotaKeys("acme.co/service"); len(dotted) != 1 || dotted[0] != "acme.co/service" {
		t.Fatalf("dotted-group quota keys = %v", dotted)
	}
	// Legacy URL inputs derive the same pair.
	legacy := QuotaKeys("https://github.com/acme/backend.git")
	if len(legacy) != 2 || legacy[1] != "github.com/acme" {
		t.Fatalf("legacy quota keys = %v", legacy)
	}
	if RepoTeamKey("github.com/acme/backend") != "github.com/acme" {
		t.Fatalf("RepoTeamKey = %q", RepoTeamKey("github.com/acme/backend"))
	}
	if RepoTeamKey("acme/backend") != "" {
		t.Fatalf("bare RepoTeamKey = %q, want empty", RepoTeamKey("acme/backend"))
	}
}

// TestRepoAllowedCanonicalIdentity: the runner profile ACL matches the
// canonical RepoID; a bare full-name entry remains an explicit alias, and a
// canonical grant for one forge never admits the same-name repository on
// another.
func TestRepoAllowedCanonicalIdentity(t *testing.T) {
	allowed := []string{"github.com/acme/backend"}
	github := model.Job{RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend"}
	if !RepoAllowed(allowed, github) {
		t.Fatal("canonical grant must admit the matching job")
	}
	if RepoAllowed(allowed, model.Job{RepoURL: "https://github.com/acme/other.git", RepoFullName: "acme/other"}) {
		t.Fatal("canonical grant must not admit another repository")
	}
	// Same bare name on another forge: still admitted, because the job's
	// canonical identity differs and only exact/bare matches count.
	gitlab := model.Job{RepoURL: "https://gitlab.company.com/acme/backend.git", RepoFullName: "acme/backend"}
	if RepoAllowed(allowed, gitlab) {
		t.Fatal("canonical github grant must not admit the same-name gitlab job")
	}
	// A stored RepoID is authoritative even when the URL would derive
	// differently.
	stored := model.Job{RepoID: "github.com/acme/backend", RepoURL: "https://mirror.example/acme/backend.git", RepoFullName: "acme/backend"}
	if !RepoAllowed(allowed, stored) {
		t.Fatal("stored RepoID must drive the ACL match")
	}
	// Bare entries are explicit aliases across forges.
	if !RepoAllowed([]string{"acme/backend"}, gitlab) {
		t.Fatal("explicit bare alias must admit the job")
	}
	// An empty allowlist is unrestricted.
	if !RepoAllowed(nil, gitlab) {
		t.Fatal("empty allowlist must be unrestricted")
	}
}

// TestLeasePredicateUsesStoredRepoID: the shared lease predicate resolves
// the job's canonical identity from the stored RepoID (falling back for
// legacy jobs), so the profile ACL sees the immutable identity.
func TestLeasePredicateUsesStoredRepoID(t *testing.T) {
	runner := model.Runner{ID: "r", Capacity: 1, Labels: []string{"container"}, AllowedRepositories: []string{"gitlab.company.com/acme/backend"}}
	job := model.Job{ID: "j", RepoID: "gitlab.company.com/acme/backend", RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend", RequiredLabels: []string{"container"}}
	if !(LeasePredicate{Runner: runner, Job: job}).Allows() {
		t.Fatal("stored RepoID must satisfy the profile ACL")
	}
	legacy := model.Job{ID: "j", RepoURL: "https://gitlab.company.com/acme/backend.git", RepoFullName: "acme/backend", RequiredLabels: []string{"container"}}
	if !(LeasePredicate{Runner: runner, Job: legacy}).Allows() {
		t.Fatal("legacy job must derive the same identity for the profile ACL")
	}
	other := model.Job{ID: "j", RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend", RequiredLabels: []string{"container"}}
	if (LeasePredicate{Runner: runner, Job: other}).Allows() {
		t.Fatal("same-name repository on another forge must not satisfy the profile ACL")
	}
}

// TestInsertCompiledRunPersistsRepoID: the canonical identity rides the
// run/job payload through the atomic enqueue and reads back verbatim (no
// dedicated column needed).
func TestInsertCompiledRunPersistsRepoID(t *testing.T) {
	m := newMemStore()
	const runID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"
	const jobID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae"
	req := compiledRunRequest(runID, jobID, "https://github.com/acme/backend.git")
	req.Run.RepoID = "github.com/acme/backend"
	job := req.Jobs[jobID]
	job.RepoID = "github.com/acme/backend"
	req.Jobs[jobID] = job
	if err := m.InsertCompiledRun(ctx(), req); err != nil {
		t.Fatal(err)
	}
	run, err := m.GetRun(ctx(), runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.RepoID != "github.com/acme/backend" {
		t.Fatalf("run RepoID = %q", run.RepoID)
	}
	got, err := m.GetJob(ctx(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RepoID != "github.com/acme/backend" || RepoIDForJob(got) != run.RepoID {
		t.Fatalf("job RepoID = %q (derived %q)", got.RepoID, RepoIDForJob(got))
	}
}
