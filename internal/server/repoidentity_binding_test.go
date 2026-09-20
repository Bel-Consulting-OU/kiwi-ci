package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestParseCloneURLAcceptsEverySupportedForm pins the strict parser's
// accepted spellings: every one yields the canonical host and the forge
// repository path (no host, no ".git", no trailing slash, no query, no
// fragment, no userinfo).
func TestParseCloneURLAcceptsEverySupportedForm(t *testing.T) {
	cases := []struct {
		raw  string
		host string
		path string
	}{
		{"https://github.com/acme/repo", "github.com", "acme/repo"},
		{"https://github.com/acme/repo.git", "github.com", "acme/repo"},
		{"https://github.com/acme/repo.git/", "github.com", "acme/repo"},
		{"https://GitHub.com./acme/repo.git", "github.com", "acme/repo"},
		{"https://github.com:443/acme/repo.git", "github.com", "acme/repo"},
		{"HTTPS://GitHub.com/acme/repo.git", "github.com", "acme/repo"},
		{"https://github.com:8443/acme/repo.git", "github.com:8443", "acme/repo"},
		{"ssh://git@github.com/acme/repo.git", "github.com", "acme/repo"},
		{"ssh://git@github.com:22/acme/repo.git", "github.com", "acme/repo"},
		{"ssh://git@GitHub.com./acme/repo.git", "github.com", "acme/repo"},
		{"git@github.com:acme/repo.git", "github.com", "acme/repo"},
		{"git@github.com:acme/repo", "github.com", "acme/repo"},
		{"git@GITHUB.com:acme/repo.git", "github.com", "acme/repo"},
		{"git@github.com:group/sub/repo.git", "github.com", "group/sub/repo"},
		{"http://localhost:8080/acme/repo.git", "localhost:8080", "acme/repo"},
		{"http://127.0.0.1/acme/repo.git", "127.0.0.1", "acme/repo"},
		{"http://127.5.5.5/acme/repo.git", "127.5.5.5", "acme/repo"},
	}
	for _, tc := range cases {
		host, path, err := parseCloneURL(tc.raw)
		if err != nil {
			t.Errorf("parseCloneURL(%q) error: %v", tc.raw, err)
			continue
		}
		if host != tc.host || path != tc.path {
			t.Errorf("parseCloneURL(%q) = (%q, %q), want (%q, %q)", tc.raw, host, path, tc.host, tc.path)
		}
	}
}

// TestParseCloneURLRejectsMalformedInputs pins the fail-closed rejections:
// empty/empty-path values, ambiguous paths, credentials, query/fragment,
// non-loopback plain http, unknown schemes and non-URL inputs are refused
// instead of silently becoming a different repository identity.
func TestParseCloneURLRejectsMalformedInputs(t *testing.T) {
	rejected := []string{
		"",
		"   ",
		"https://github.com",
		"https://github.com/",
		"https://github.com//repo.git",
		"https://github.com/acme//repo.git",
		"https://github.com/acme/../repo.git",
		"https://user@github.com/acme/repo.git",
		"https://user:pass@github.com/acme/repo.git",
		"https://github.com/acme/repo.git?ref=main",
		"https://github.com/acme/repo.git#readme",
		"http://evil.example/acme/repo.git",
		"ftp://github.com/acme/repo.git",
		"git://github.com/acme/repo.git",
		"ssh://bob@github.com/acme/repo.git",
		"ssh://git:secret@github.com/acme/repo.git",
		"git@github.com:",
		"git@github.com",
		"bob@github.com:acme/repo.git",
		"acme/repo",
		"github.com/acme/repo",
	}
	for _, raw := range rejected {
		if host, path, err := parseCloneURL(raw); err == nil {
			t.Errorf("parseCloneURL(%q) = (%q, %q), want rejection", raw, host, path)
		}
	}
}

// TestCanonicalHostCollapsesEquivalentSpellings pins the normalizer: case,
// one trailing dot, the scheme's default port and URL/scp framing all
// collapse onto one host, while a non-default port stays distinct. It also
// pins that the server, auth, policy and storage normalizers agree.
func TestCanonicalHostCollapsesEquivalentSpellings(t *testing.T) {
	same := []string{
		"GITHUB.COM",
		"github.com.",
		"github.com:443",
		"HTTPS://GitHub.com",
		"https://GitHub.com:443/acme/repo.git",
		"git@github.com:acme/repo.git",
		"ssh://git@github.com:22/acme/repo",
	}
	for _, raw := range same {
		if got := canonicalHost(raw); got != "github.com" {
			t.Errorf("canonicalHost(%q) = %q, want github.com", raw, got)
		}
		if got := canonicalHost(raw); got != auth.CanonicalHost(raw) {
			t.Errorf("canonicalHost(%q) = %q disagrees with auth.CanonicalHost = %q", raw, got, auth.CanonicalHost(raw))
		}
	}
	distinct := []string{"github.com:8443", "gitlab.company.com", "github.com.evil.example"}
	for _, raw := range distinct {
		if canonicalHost(raw) == "github.com" {
			t.Errorf("canonicalHost(%q) collapsed onto github.com", raw)
		}
	}
	if got := canonicalHost("https://github.com:8443/acme/repo.git"); got != "github.com:8443" {
		t.Errorf("non-default port lost: %q", got)
	}

	// The RepoID property: every equivalent clone URL form canonicalizes to
	// the SAME "<host>/<owner>/<repo>" identity.
	forms := []string{
		"HTTPS://GitHub.com/acme/repo.git",
		"https://github.com/acme/repo.git",
		"https://github.com./acme/repo.git",
		"https://github.com:443/acme/repo.git",
		"ssh://git@github.com:22/acme/repo.git",
		"git@github.com:acme/repo.git",
		"git@GITHUB.com:acme/repo.git",
	}
	for _, raw := range forms {
		host, path, err := parseCloneURL(raw)
		if err != nil {
			t.Fatalf("parseCloneURL(%q): %v", raw, err)
		}
		if id := auth.CanonicalRepoID(host, path); id != "github.com/acme/repo" {
			t.Errorf("RepoID(%q) = %q, want github.com/acme/repo", raw, id)
		}
		if id := repoIDFor("", raw, ""); id != "github.com/acme/repo" {
			t.Errorf("repoIDFor(%q) = %q, want github.com/acme/repo", raw, id)
		}
	}
	// A stored canonical key with an equivalent host spelling collapses too.
	for _, host := range []string{"GITHUB.COM", "github.com.", "github.com:443"} {
		if id := auth.CanonicalRepoID(host, "acme/repo"); id != "github.com/acme/repo" {
			t.Errorf("CanonicalRepoID(%q, acme/repo) = %q", host, id)
		}
	}
	// A non-default port is a DIFFERENT identity.
	if id := repoIDFor("", "https://github.com:8443/acme/repo.git", ""); id != "github.com:8443/acme/repo" {
		t.Errorf("port-scoped RepoID = %q, want github.com:8443/acme/repo", id)
	}
}

// TestDirectSubmitRejectsClaimedIdentityBeforeAuthorization is the audit's
// exact example: repo_url=https://github.com/acme/other.git together with
// repo_full_name=acme/allowed must NOT authorize as acme/allowed. The
// principal is authorized for acme/allowed only, and the mismatch is still
// rejected with 400 BEFORE RBAC (a matching submission would pass RBAC and a
// non-matching identity would be 403, so 400 proves the ordering).
func TestDirectSubmitRejectsClaimedIdentityBeforeAuthorization(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"allowed-token": {
			Subject: "claimed-bot",
			Repositories: map[string]auth.RepositoryPermission{
				"github.com/acme/allowed": {Run: true},
			},
		},
		"ungranted-token": {Subject: "no-grants"},
	})
	body := `{"repo_url":"https://github.com/acme/other.git","repo_full_name":"acme/allowed","ref":"refs/heads/main","pipeline":` + jsonString(simpleContainerPipeline) + `}`
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "allowed-token", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("claimed-identity submit = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "repo_identity_mismatch") {
		t.Fatalf("rejection reason missing: %s", w.Body.String())
	}
	// The same mismatched body from a principal with NO grants is 400, not
	// 403: the binding runs before any authorization decision.
	w = doJSON(t, s, http.MethodPost, "/api/v1/runs", "ungranted-token", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("mismatch must be rejected before RBAC = %d: %s", w.Code, w.Body.String())
	}
	// A matching submission from the SAME ungranted principal is 403, which
	// proves the 400 above was not an authorization outcome.
	matching := `{"repo_url":"https://github.com/acme/other.git","repo_full_name":"acme/other","ref":"refs/heads/main","pipeline":` + jsonString(simpleContainerPipeline) + `}`
	if w = doJSON(t, s, http.MethodPost, "/api/v1/runs", "ungranted-token", matching); w.Code != http.StatusForbidden {
		t.Fatalf("matching submit for an ungranted principal = %d, want 403: %s", w.Code, w.Body.String())
	}
	// No run was enqueued for either rejected submission.
	s.mu.Lock()
	runs := len(s.runs)
	s.mu.Unlock()
	if runs != 0 {
		t.Fatalf("rejected submissions created %d runs", runs)
	}
}

// TestDirectSubmitBindingAcceptsEquivalentForms: the binding is case
// insensitive with one ".git" suffix stripped, and the canonical identity
// derives from the URL path, never from the free-standing name.
func TestDirectSubmitBindingAcceptsEquivalentForms(t *testing.T) {
	s := New("token")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://GitHub.com./Acme/Backend.git","repo_full_name":"acme/backend","ref":"refs/heads/main","pipeline":`+jsonString(simpleContainerPipeline)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("equivalent-form submit = %d: %s", w.Code, w.Body.String())
	}
	var run model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.RepoID != "github.com/Acme/Backend" || run.PolicyRepoID != run.RepoID {
		t.Fatalf("RepoID/PolicyRepoID = %q/%q, want the URL-derived canonical identity", run.RepoID, run.PolicyRepoID)
	}
	if run.CheckoutRepoURL != "https://GitHub.com./Acme/Backend.git" {
		t.Fatalf("CheckoutRepoURL = %q", run.CheckoutRepoURL)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.RunID != run.ID {
			continue
		}
		if j.PolicyRepoID != run.RepoID || j.CheckoutRepoURL != run.CheckoutRepoURL || j.RepoURL != run.CheckoutRepoURL {
			t.Fatalf("job identity = %q/%q/%q", j.PolicyRepoID, j.CheckoutRepoURL, j.RepoURL)
		}
	}
}

// TestEnqueueBindsNonWebhookIngress: enqueue itself (the path schedules,
// dispatch and reruns use) refuses a mismatched direct-style submission even
// when a stored RepoID was pre-set, so no ingress can smuggle a
// repo_full_name past the binding.
func TestEnqueueBindsNonWebhookIngress(t *testing.T) {
	s := New("token")
	_, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/acme/other.git", RepoFullName: "acme/allowed",
		Ref: "refs/heads/main", Pipeline: simpleContainerPipeline,
	})
	if err == nil {
		t.Fatal("enqueue accepted a mismatched repo_url/repo_full_name pair")
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/acme/other.git", RepoFullName: "acme/other",
		Ref: "refs/heads/main", Pipeline: simpleContainerPipeline,
	}); err != nil {
		t.Fatalf("matching enqueue rejected: %v", err)
	}
}

// TestForkPRPolicyIdentityIsBaseCheckoutIsHead is the P0 fork-PR contract: an
// untrusted cross-repo PR derives its policy/RBAC/quota/cache identity from
// the BASE repository while the runner checks out the HEAD repository. The
// base full name deliberately differs from the head clone URL, so the
// webhook ingress must skip the direct-submission binding.
func TestForkPRPolicyIdentityIsBaseCheckoutIsHead(t *testing.T) {
	api := (&gitHubHookAPI{fileBody: untrustedPipeline}).server(t)
	s := newGitHubSqueezeServer(t, api, "hunter2")
	for raw, p := range map[string]auth.Principal{
		"base-token": {Subject: "base-bot", Repositories: map[string]auth.RepositoryPermission{
			"github.com/octocat/hello-world": {Read: true, Run: true},
		}},
		"head-token": {Subject: "head-bot", Repositories: map[string]auth.RepositoryPermission{
			"github.com/fork/hello-world": {Read: true, Run: true},
		}},
	} {
		if err := s.AuthStore.AddToken(raw, p); err != nil {
			t.Fatal(err)
		}
	}
	w := postWebhook(t, s, "hunter2", "pull_request", "fork-pr-1", githubPRPayload("opened", "fork/hello-world"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("fork PR webhook = %d: %s", w.Code, w.Body.String())
	}
	runID, _ := decodeRun(t, w)
	s.mu.Lock()
	run := s.runs[runID]
	var jobs []model.Job
	for _, j := range s.jobs {
		if j.RunID == runID {
			jobs = append(jobs, j)
		}
	}
	s.mu.Unlock()
	if len(jobs) == 0 {
		t.Fatal("fork PR run has no jobs")
	}
	if run.Trusted {
		t.Fatal("fork PR must be untrusted")
	}
	if run.PolicyRepoID != "github.com/octocat/hello-world" || run.RepoID != "github.com/octocat/hello-world" {
		t.Fatalf("policy identity = %q/%q, want the BASE repository", run.PolicyRepoID, run.RepoID)
	}
	if repoIDForRun(run) != "github.com/octocat/hello-world" {
		t.Fatalf("authorization identity = %q, want the base repository", repoIDForRun(run))
	}
	if run.CheckoutRepoURL != "https://github.com/fork/hello-world.git" || run.Repo != "https://github.com/fork/hello-world.git" {
		t.Fatalf("checkout URL = %q / repo = %q, want the HEAD repository", run.CheckoutRepoURL, run.Repo)
	}
	if run.RepoFullName != "octocat/hello-world" {
		t.Fatalf("display full name = %q, want the base repository", run.RepoFullName)
	}
	for _, j := range jobs {
		if j.PolicyRepoID != "github.com/octocat/hello-world" {
			t.Fatalf("job policy identity = %q, want the base repository", j.PolicyRepoID)
		}
		if j.CheckoutRepoURL != "https://github.com/fork/hello-world.git" || j.RepoURL != "https://github.com/fork/hello-world.git" {
			t.Fatalf("job checkout = %q/%q, want the HEAD clone URL", j.CheckoutRepoURL, j.RepoURL)
		}
		if storage.RepoIDForJob(j) != "github.com/octocat/hello-world" {
			t.Fatalf("storage identity = %q, want the base repository", storage.RepoIDForJob(j))
		}
		repo, trust := cacheNamespace(j)
		if repo != "github.com/octocat/hello-world" || trust != "untrusted" {
			t.Fatalf("cache namespace = %q/%q, want the base repository", repo, trust)
		}
		if repoTeamKey(repoIDForJob(j)) != "github.com/octocat" {
			t.Fatalf("quota team key = %q, want the base repository's owner", repoTeamKey(repoIDForJob(j)))
		}
	}

	// RBAC follows the policy identity: the base repository's principal can
	// read the run, the head repository's principal cannot.
	if w = doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runID, "base-token", ""); w.Code != http.StatusOK {
		t.Fatalf("base principal read = %d: %s", w.Code, w.Body.String())
	}
	if w = doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runID, "head-token", ""); w.Code != http.StatusForbidden {
		t.Fatalf("head principal read = %d, want 403: %s", w.Code, w.Body.String())
	}

	// The leased task delivers the CHECKOUT URL to the runner, never the
	// policy identity. The runner registers with the server's admin bearer.
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "runner-secret", `{"name":"fork-runner","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register runner = %d: %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "runner-secret", "")
	if w.Code != http.StatusOK {
		t.Fatalf("lease next = %d: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.Job.RepoURL != "https://github.com/fork/hello-world.git" {
		t.Fatalf("task RepoURL = %q, want the HEAD clone URL", task.Job.RepoURL)
	}
	if task.Job.PolicyRepoID != "github.com/octocat/hello-world" {
		t.Fatalf("task PolicyRepoID = %q, want the base repository", task.Job.PolicyRepoID)
	}
}

// TestRerunCopiesPolicyAndCheckoutIdentity: a rerun copies the source run's
// PolicyRepoID and CheckoutRepoURL verbatim (never re-deriving from the
// possibly-changed clone URL), so a fork-PR rerun keeps base/head separation.
func TestRerunCopiesPolicyAndCheckoutIdentity(t *testing.T) {
	s, old := rerunServer(t)
	s.mu.Lock()
	stored := s.runs[old.ID]
	stored.RepoID = "github.com/base/forked"
	stored.PolicyRepoID = "github.com/base/forked"
	stored.CheckoutRepoURL = "https://github.com/head/forked.git"
	stored.Repo = "https://mirror.example/forked.git"
	stored.RepoFullName = "base/forked"
	s.runs[old.ID] = stored
	s.mu.Unlock()
	out := rerunAs(t, s, "trusted-token", old.ID)
	if out.PolicyRepoID != "github.com/base/forked" {
		t.Fatalf("rerun PolicyRepoID = %q, want the source policy identity", out.PolicyRepoID)
	}
	if out.CheckoutRepoURL != "https://github.com/head/forked.git" {
		t.Fatalf("rerun CheckoutRepoURL = %q, want the source checkout URL", out.CheckoutRepoURL)
	}
	if out.RepoID != "github.com/base/forked" {
		t.Fatalf("rerun RepoID = %q", out.RepoID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.RunID != out.ID {
			continue
		}
		if j.PolicyRepoID != "github.com/base/forked" || j.CheckoutRepoURL != "https://github.com/head/forked.git" {
			t.Fatalf("rerun job identity = %q/%q", j.PolicyRepoID, j.CheckoutRepoURL)
		}
	}
}

// TestScheduleBindingRejectsMismatchBeforeTrustedRun: a TRUSTED schedule
// whose Repository does not match repo_url is rejected BEFORE the trusted_run
// authorization, even when the caller holds trusted_run for the CLAIMED
// repository.
func TestScheduleBindingRejectsMismatchBeforeTrustedRun(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"mgmt": {
			Subject: "mgmt-bot",
			Roles:   []auth.Role{auth.RolePolicyManage},
			Repositories: map[string]auth.RepositoryPermission{
				"github.com/acme/allowed": {TrustedRun: true},
				"github.com/acme/other":   {TrustedRun: true},
			},
		},
	})
	mismatch := `{"repository":"acme/allowed","repo_url":"https://github.com/acme/other.git","trusted":true,"spec":` + jsonString(scheduleSpec) + `}`
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "mgmt", mismatch)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("mismatched trusted schedule = %d, want 400: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	stored := len(s.schedules)
	s.mu.Unlock()
	if stored != 0 {
		t.Fatalf("mismatched schedule was stored (%d rows)", stored)
	}
	matching := `{"repository":"acme/other","repo_url":"https://github.com/acme/other.git","trusted":true,"spec":` + jsonString(scheduleSpec) + `}`
	w = doJSON(t, s, http.MethodPut, "/api/v1/schedules", "mgmt", matching)
	if w.Code != http.StatusOK {
		t.Fatalf("matching trusted schedule = %d, want 200: %s", w.Code, w.Body.String())
	}
	var sc storage.Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.RepoID != "github.com/acme/other" || sc.RepoURL != "https://github.com/acme/other.git" || sc.Repository != "acme/other" {
		t.Fatalf("stored schedule identity = %+v", sc)
	}
	// The legacy Repository-as-URL form still works and is normalized to the
	// repository path for display.
	w = doJSON(t, s, http.MethodPut, "/api/v1/schedules", "mgmt",
		`{"repository":"https://github.com/acme/other.git","spec":`+jsonString(scheduleSpec)+`}`)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy URL schedule = %d: %s", w.Code, w.Body.String())
	}
	var legacy storage.Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Repository != "acme/other" || legacy.RepoID != "github.com/acme/other" {
		t.Fatalf("legacy schedule normalized identity = %+v", legacy)
	}
}

// TestDurableMismatchedScheduleDisabledAtLoadFS: a hand-crafted fs schedule
// file with a TRUSTED schedule whose RepoID disagrees with its URL (and an
// untrusted schedule whose Repository disagrees) is disabled at load and
// never fires.
func TestDurableMismatchedScheduleDisabledAtLoadFS(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	file := schedulesFileJSON{Schedules: []storage.Schedule{
		{
			ID: "trusted-bad", Repository: "acme/allowed", RepoID: "github.com/acme/allowed",
			RepoURL: "https://github.com/acme/other.git", Forge: "github", Trusted: true, Enabled: true,
			Spec: nativeScheduleSpec, CreatedAt: now,
		},
		{
			ID: "untrusted-bad", Repository: "acme/service", RepoURL: "https://gitlab.com/acme/other.git",
			Enabled: true, Spec: scheduleSpec, CreatedAt: now,
		},
		{
			ID: "ok", Repository: "acme/service", RepoID: "gitlab.com/acme/service",
			RepoURL: "https://gitlab.com/acme/service.git", Forge: "gitlab", Enabled: true,
			Spec: scheduleSpec, CreatedAt: now,
		},
	}}
	b, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, schedulesFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	trustedBad := s.schedules["trusted-bad"]
	untrustedBad := s.schedules["untrusted-bad"]
	ok := s.schedules["ok"]
	s.mu.Unlock()
	if trustedBad.Enabled || untrustedBad.Enabled {
		t.Fatalf("mismatched schedules not disabled: trusted=%v untrusted=%v", trustedBad.Enabled, untrustedBad.Enabled)
	}
	if !ok.Enabled || ok.RepoID != "gitlab.com/acme/service" {
		t.Fatalf("consistent schedule disturbed: %+v", ok)
	}
	// The disabled state is persisted: a reload sees it disabled again.
	b, err = os.ReadFile(filepath.Join(dir, schedulesFile))
	if err != nil {
		t.Fatal(err)
	}
	var reloaded schedulesFileJSON
	if err := json.Unmarshal(b, &reloaded); err != nil {
		t.Fatal(err)
	}
	for _, sc := range reloaded.Schedules {
		if (sc.ID == "trusted-bad" || sc.ID == "untrusted-bad") && sc.Enabled {
			t.Fatalf("disabled schedule %s was persisted as enabled", sc.ID)
		}
	}
	// Firing the raw (mismatched) rows is refused outright, and the due pass
	// cannot fire them either.
	if _, fired, ferr := s.fireSchedule(context.Background(), trustedBad, now); ferr == nil || fired {
		t.Fatalf("mismatched trusted schedule fired: fired=%v err=%v", fired, ferr)
	}
	if _, fired, ferr := s.fireSchedule(context.Background(), untrustedBad, now); ferr == nil || fired {
		t.Fatalf("mismatched untrusted schedule fired: fired=%v err=%v", fired, ferr)
	}
	s.fireDueSchedules(context.Background(), now)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, run := range s.runs {
		if sid := run.Metadata["schedule_id"]; sid == "trusted-bad" || sid == "untrusted-bad" {
			t.Fatalf("disabled schedule %s produced a run", sid)
		}
	}
}

// TestDurableMismatchedScheduleDisabledAtLoadDB: the SQL load path applies
// the SAME validation: a mismatched trusted row is disabled in memory,
// persisted disabled through the schedule store, audited, and never fires.
func TestDurableMismatchedScheduleDisabledAtLoadDB(t *testing.T) {
	now := time.Now().UTC()
	bad := storage.Schedule{
		ID: "trusted-bad", Repository: "acme/allowed", RepoID: "github.com/acme/allowed",
		RepoURL: "https://github.com/acme/other.git", Forge: "github", Trusted: true, Enabled: true,
		Spec: nativeScheduleSpec, CreatedAt: now,
	}
	f := newDBFakeStore()
	f.mu.Lock()
	f.schedules[bad.ID] = bad
	f.mu.Unlock()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	loaded := s.schedules[bad.ID]
	s.mu.Unlock()
	if loaded.Enabled {
		t.Fatalf("mismatched durable schedule not disabled at DB load: %+v", loaded)
	}
	f.mu.Lock()
	persisted := f.schedules[bad.ID]
	var audited bool
	for _, e := range f.audit {
		if e.Action == "schedule.invalid_disabled" && e.Metadata["schedule"] == bad.ID {
			audited = true
		}
	}
	f.mu.Unlock()
	if persisted.Enabled {
		t.Fatal("disabled schedule was not persisted as disabled")
	}
	if !audited {
		t.Fatal("disabling a durable schedule must emit an audit line")
	}
	if _, fired, err := s.fireSchedule(context.Background(), bad, now); err == nil || fired {
		t.Fatalf("mismatched durable schedule fired: fired=%v err=%v", fired, err)
	}
	s.fireDueSchedules(context.Background(), now)
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, run := range f.runs {
		if run.Metadata["schedule_id"] == bad.ID {
			t.Fatal("disabled durable schedule produced a run")
		}
	}
}
