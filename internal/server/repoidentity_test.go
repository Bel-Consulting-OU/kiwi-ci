package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const unpinnedContainerPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine:latest
    steps:
      - run: echo hi
`

// TestRepoIDDerivedAtIngressAndPersisted: the API ingress derives the
// canonical identity from repo_url + repo_full_name, persists it on the run
// and on every job, and the jobs copy the run's identity verbatim.
func TestRepoIDDerivedAtIngressAndPersisted(t *testing.T) {
	s := New("token")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://github.com/acme/backend.git","repo_full_name":"acme/backend","ref":"refs/heads/main","pipeline":`+jsonString(simpleContainerPipeline)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit = %d: %s", w.Code, w.Body.String())
	}
	var run model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.RepoID != "github.com/acme/backend" {
		t.Fatalf("run RepoID = %q, want canonical github.com/acme/backend", run.RepoID)
	}
	if run.Repo != "https://github.com/acme/backend.git" || run.RepoFullName != "acme/backend" {
		t.Fatalf("display/clone fields changed: repo=%q full=%q", run.Repo, run.RepoFullName)
	}
	s.mu.Lock()
	jobs := 0
	for _, j := range s.jobs {
		if j.RunID != run.ID {
			continue
		}
		jobs++
		if j.RepoID != run.RepoID {
			t.Fatalf("job RepoID = %q, want the run's %q", j.RepoID, run.RepoID)
		}
		if j.RepoURL != run.Repo || j.RepoFullName != run.RepoFullName {
			t.Fatalf("job display fields = %q/%q", j.RepoURL, j.RepoFullName)
		}
	}
	s.mu.Unlock()
	if jobs == 0 {
		t.Fatal("no jobs persisted for the run")
	}

	// A client-supplied repo_id is never accepted: the submission decoder
	// rejects unknown fields, so the identity can only be the server-side
	// derivation from repo_url + repo_full_name.
	w = doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_id":"evil.example/acme/backend","repo_url":"https://github.com/acme/backend.git","repo_full_name":"acme/backend","ref":"refs/heads/main","pipeline":`+jsonString(simpleContainerPipeline)+`}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("spoofed submit = %d, want 400 (unknown field): %s", w.Code, w.Body.String())
	}
}

// TestRepoIDLegacyFallbackMatchesIngressDerivation: a record persisted
// before RepoID existed derives EXACTLY the identity the ingress derivation
// produced for the same clone URL + full name, in both the server and the
// storage package (one shared derivation).
func TestRepoIDLegacyFallbackMatchesIngressDerivation(t *testing.T) {
	cases := []struct {
		name         string
		repoURL      string
		repoFullName string
		want         string
	}{
		{"github", "https://github.com/acme/backend.git", "acme/backend", "github.com/acme/backend"},
		{"gitlab self-hosted", "https://gitlab.company.com/acme/backend.git", "acme/backend", "gitlab.company.com/acme/backend"},
		{"scp-like", "git@github.com:acme/backend.git", "acme/backend", "github.com/acme/backend"},
		{"url only", "https://gitlab.company.com/acme/backend.git", "", "gitlab.company.com/acme/backend"},
		{"bare full name", "", "acme/backend", "acme/backend"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ingress := repoIDFor("", tc.repoURL, tc.repoFullName)
			if ingress != tc.want {
				t.Fatalf("derivation = %q, want %q", ingress, tc.want)
			}
			if got := repoIDForRun(model.Run{Repo: tc.repoURL, RepoFullName: tc.repoFullName}); got != ingress {
				t.Fatalf("legacy run = %q, want %q", got, ingress)
			}
			if got := repoIDForJob(model.Job{RepoURL: tc.repoURL, RepoFullName: tc.repoFullName}); got != ingress {
				t.Fatalf("legacy job = %q, want %q", got, ingress)
			}
			if got := storage.RepoIDFor("", tc.repoURL, tc.repoFullName); got != ingress {
				t.Fatalf("storage derivation = %q, want %q (derivations must agree)", got, ingress)
			}
		})
	}
}

// TestRepoIDStoredIdentityWins: once a record carries a RepoID it is
// authoritative — a rerun-style copy or a changed clone URL never re-derives
// it.
func TestRepoIDStoredIdentityWins(t *testing.T) {
	run := model.Run{RepoID: "github.com/acme/backend", Repo: "https://mirror.example/acme/backend.git", RepoFullName: "acme/backend"}
	if got := repoIDForRun(run); got != "github.com/acme/backend" {
		t.Fatalf("stored run RepoID ignored: %q", got)
	}
	job := model.Job{RepoID: "github.com/acme/backend", RepoURL: "https://mirror.example/acme/backend.git", RepoFullName: "acme/backend"}
	if got := repoIDForJob(job); got != "github.com/acme/backend" {
		t.Fatalf("stored job RepoID ignored: %q", got)
	}
}

// TestPolicySeparatesSameNameAcrossForges: a repository policy keyed for
// github.com/acme/backend does not restrict gitlab.company.com/acme/backend
// at admission, and its grants do not leak.
func TestPolicySeparatesSameNameAcrossForges(t *testing.T) {
	yes := true
	s := New("token")
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{
		"github.com/acme/backend": {RequireDigestPins: &yes, CrossRepoTrigger: &yes},
	}}
	if w := submitPipeline(t, s, "https://github.com/acme/backend.git", "acme/backend", unpinnedContainerPipeline); w.Code != http.StatusForbidden {
		t.Fatalf("github unpinned = %d, want 403 (repo policy applies): %s", w.Code, w.Body.String())
	}
	if w := submitPipeline(t, s, "https://gitlab.company.com/acme/backend.git", "acme/backend", unpinnedContainerPipeline); w.Code != http.StatusAccepted {
		t.Fatalf("gitlab same-name unpinned = %d, want 202 (github policy must not apply): %s", w.Code, w.Body.String())
	}
	if g := s.Policy.GrantsFor("github.com/acme/backend"); !g.CrossRepoTrigger {
		t.Fatalf("github grants = %+v, want cross_repo_trigger", g)
	}
	if g := s.Policy.GrantsFor("gitlab.company.com/acme/backend"); g.CrossRepoTrigger {
		t.Fatalf("github grant leaked to the same-name gitlab host: %+v", g)
	}
}

// TestRBACUsesStoredRepoID: authorization resolves the run's stored
// canonical RepoID, so a principal keyed for github.com/acme/backend never
// authorizes the same-name repository on another forge.
func TestRBACUsesStoredRepoID(t *testing.T) {
	principal := auth.Principal{
		Subject: "github-bot",
		Repositories: map[string]auth.RepositoryPermission{
			"github.com/acme/backend": {Read: true, Run: true},
		},
	}
	githubRun := model.Run{RepoID: "github.com/acme/backend", Repo: "https://github.com/acme/backend.git", RepoFullName: "acme/backend"}
	gitlabRun := model.Run{RepoID: "gitlab.company.com/acme/backend", Repo: "https://gitlab.company.com/acme/backend.git", RepoFullName: "acme/backend"}
	if !auth.Authorize(principal, auth.ActionRead, repoIDForRun(githubRun), false) {
		t.Fatal("declared canonical repo must authorize")
	}
	if auth.Authorize(principal, auth.ActionRead, repoIDForRun(gitlabRun), false) {
		t.Fatal("same-name repository on another forge must not be authorized")
	}
}

// TestCacheNamespaceSeparatesSameNameAcrossForges: the cache trust
// namespace derives from the job's canonical RepoID, so entries never cross
// forges even when the bare name is identical.
func TestCacheNamespaceSeparatesSameNameAcrossForges(t *testing.T) {
	githubJob := model.Job{ID: "j1", RepoID: "github.com/acme/backend", RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend", Trusted: true}
	gitlabJob := model.Job{ID: "j2", RepoID: "gitlab.company.com/acme/backend", RepoURL: "https://gitlab.company.com/acme/backend.git", RepoFullName: "acme/backend", Trusted: true}
	ghRepo, ghTrust := cacheNamespace(githubJob)
	glRepo, glTrust := cacheNamespace(gitlabJob)
	if ghRepo != "github.com/acme/backend" || glRepo != "gitlab.company.com/acme/backend" {
		t.Fatalf("cache repos = %q/%q, want canonical identities", ghRepo, glRepo)
	}
	if ghTrust != glTrust {
		t.Fatalf("trust domains differ: %q/%q", ghTrust, glTrust)
	}
	if cacheFileKey(ghRepo, ghTrust, "key") == cacheFileKey(glRepo, glTrust, "key") {
		t.Fatal("same-name forge repositories share a cache file key")
	}
	// Legacy job without RepoID derives the identical namespace.
	legacy := model.Job{ID: "j3", RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend", Trusted: true}
	if lr, lt := cacheNamespace(legacy); lr != ghRepo || lt != ghTrust || cacheFileKey(lr, lt, "key") != cacheFileKey(ghRepo, ghTrust, "key") {
		t.Fatalf("legacy namespace = %q/%q, want %q/%q", lr, lt, ghRepo, ghTrust)
	}
}

// TestQuotaCountersSeparateSameNameAcrossForges: the memory-mode quota
// counters key on the job's canonical RepoID, so a repository at its
// concurrency limit does not block the same-name repository on another
// forge.
func TestQuotaCountersSeparateSameNameAcrossForges(t *testing.T) {
	s := New("token")
	s.QuotaLimits.RepoConcurrency = 1
	githubRun := model.Run{ID: "r-gh", RepoID: "github.com/acme/backend", Status: model.StatusRunning}
	s.runs[githubRun.ID] = githubRun
	s.jobs["j-gh"] = model.Job{ID: "j-gh", RunID: githubRun.ID, RepoID: "github.com/acme/backend", Status: model.StatusRunning}
	gitlabRun := model.Run{ID: "r-gl", Repo: "https://gitlab.company.com/acme/backend.git", RepoFullName: "acme/backend", Status: model.StatusQueued}
	if err := s.admitQuotaLocked(gitlabRun, 1); err != nil {
		t.Fatalf("same-name repository on another forge was quota-blocked: %v", err)
	}
	secondGithub := model.Run{ID: "r-gh2", RepoID: "github.com/acme/backend", Status: model.StatusQueued}
	if err := s.admitQuotaLocked(secondGithub, 1); err == nil {
		t.Fatal("repository at its concurrency limit must be quota-blocked")
	}
	// Legacy running job (no RepoID) still counts against its canonical key.
	s.jobs["j-legacy"] = model.Job{ID: "j-legacy", RunID: githubRun.ID, RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend", Status: model.StatusRunning}
	s.QuotaLimits.RepoConcurrency = 2
	if err := s.admitQuotaLocked(secondGithub, 1); err == nil {
		t.Fatal("legacy same-repo running job must count against the canonical key")
	}
}

// TestQuotaTeamKeySeparatesSameNameAcrossForges: team concurrency keys the
// forge host plus owner, so the team counter of github.com/acme and
// gitlab.company.com/acme never collide.
func TestQuotaTeamKeySeparatesSameNameAcrossForges(t *testing.T) {
	gh := storage.RepoTeamKey("github.com/acme/backend")
	gl := storage.RepoTeamKey("gitlab.company.com/acme/backend")
	if gh != "github.com/acme" || gl != "gitlab.company.com/acme" {
		t.Fatalf("team keys = %q/%q", gh, gl)
	}
	if gh == gl {
		t.Fatal("team keys collide across forges")
	}
}

// TestDownstreamAuthorizationUsesCanonicalRepoIDs: allowlist keys are
// canonical repository IDs; a same-name source on another forge is refused,
// while a bare entry stays an explicit alias.
func TestDownstreamAuthorizationUsesCanonicalRepoIDs(t *testing.T) {
	s := New("token")
	s.DownstreamAllowlist = map[string][]string{
		"github.com/acme/backend": {"github.com/acme/source"},
	}
	payload := downstreamPayload{ParentJobID: "j", ParentRunID: "run-gh", TargetRepo: "acme/backend", TargetRef: "refs/heads/main"}
	s.runs["run-gh"] = model.Run{ID: "run-gh", RepoID: "github.com/acme/source", Repo: "https://github.com/acme/source.git", RepoFullName: "acme/source"}
	if !s.downstreamAllowed(context.Background(), payload, "github.com/acme/backend") {
		t.Fatal("canonical source must be allowed by the canonical target entry")
	}
	s.runs["run-gl"] = model.Run{ID: "run-gl", RepoID: "gitlab.company.com/acme/source", Repo: "https://gitlab.company.com/acme/source.git", RepoFullName: "acme/source"}
	payload.ParentRunID = "run-gl"
	if s.downstreamAllowed(context.Background(), payload, "github.com/acme/backend") {
		t.Fatal("same-name source on another forge must not be allowed")
	}
	// The same-name TARGET on another forge has no entry (default deny).
	payload.ParentRunID = "run-gh"
	if s.downstreamAllowed(context.Background(), payload, "gitlab.company.com/acme/backend") {
		t.Fatal("same-name target on another forge must be denied")
	}
	// A bare allowlist entry is an explicit alias.
	s.DownstreamAllowlist = map[string][]string{"acme/backend": {"github.com/acme/source"}}
	if !s.downstreamAllowed(context.Background(), payload, "gitlab.company.com/acme/backend") {
		t.Fatal("explicit bare alias must authorize the target")
	}
}

// TestDownstreamTargetRepoIDPersistsForgeHost: the child identity derives
// from the persisted target forge coordinates, so a bare target never
// collapses across forges.
func TestDownstreamTargetRepoIDPersistsForgeHost(t *testing.T) {
	cases := []struct {
		forgeKind, baseURL, want string
	}{
		{"github", "", "github.com/acme/child"},
		{"gitlab", "https://gitlab.company.com", "gitlab.company.com/acme/child"},
		{"forgejo", "https://forgejo.internal.example", "forgejo.internal.example/acme/child"},
	}
	for _, tc := range cases {
		got := auth.CanonicalRepoID(downstreamForgeHost(tc.forgeKind, tc.baseURL), "acme/child")
		if got != tc.want {
			t.Errorf("target RepoID(%s, %s) = %q, want %q", tc.forgeKind, tc.baseURL, got, tc.want)
		}
	}
}

// TestScheduleIdentitySeparatesSameNameAcrossForges: schedules store the
// canonical RepoID derived at create, legacy rows derive the same value from
// their stored URL, and a bare name without a forge host is rejected.
func TestScheduleIdentitySeparatesSameNameAcrossForges(t *testing.T) {
	s := New("token")
	put := func(repoURL string) storage.Schedule {
		t.Helper()
		w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token",
			`{"repository":"acme/backend","repo_url":`+jsonString(repoURL)+`,"spec":`+jsonString(scheduleSpec)+`}`)
		if w.Code != http.StatusOK {
			t.Fatalf("put schedule (%s) = %d: %s", repoURL, w.Code, w.Body.String())
		}
		var sc storage.Schedule
		if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
			t.Fatal(err)
		}
		return sc
	}
	gh := put("https://github.com/acme/backend.git")
	gl := put("https://gitlab.company.com/acme/backend.git")
	if gh.RepoID != "github.com/acme/backend" || gl.RepoID != "gitlab.company.com/acme/backend" {
		t.Fatalf("schedule RepoIDs = %q/%q", gh.RepoID, gl.RepoID)
	}
	if gh.RepoID == gl.RepoID {
		t.Fatal("same-name schedules across forges share an identity")
	}
	// Legacy row (no RepoID) derives the ingress identity from its URL.
	legacy := storage.Schedule{ID: "legacy", Repository: "acme/backend", RepoURL: "https://github.com/acme/backend.git"}
	if got := scheduleRepoID(legacy); got != gh.RepoID {
		t.Fatalf("legacy schedule RepoID = %q, want %q", got, gh.RepoID)
	}
	// Legacy row that stored the clone URL as its identity.
	legacyURL := storage.Schedule{ID: "legacy-url", Repository: "https://gitlab.company.com/acme/backend.git"}
	if got := scheduleRepoID(legacyURL); got != gl.RepoID {
		t.Fatalf("legacy URL schedule RepoID = %q, want %q", got, gl.RepoID)
	}
	// A bare name without a forge host cannot be scheduled.
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token",
		`{"repository":"acme/backend","spec":`+jsonString(scheduleSpec)+`}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bare schedule = %d, want 400: %s", w.Code, w.Body.String())
	}
}

// TestOIDCClaimsCarryCanonicalRepoID: the subject and repository_id claim
// carry the canonical identity while the repository claim stays the
// human-readable full name.
func TestOIDCClaimsCarryCanonicalRepoID(t *testing.T) {
	s := newOIDCTestServer(t, false)
	exp := time.Now().Add(time.Minute)
	s.mu.Lock()
	s.runs["run-oidc"] = model.Run{ID: "run-oidc", RepoID: "github.com/acme/backend", Repo: "https://github.com/acme/backend.git", RepoFullName: "acme/backend", Ref: "main", SHA: "abc123", Event: "push", Status: model.StatusRunning}
	s.jobs["job-oidc"] = model.Job{ID: "job-oidc", RunID: "run-oidc", Key: "build", RepoID: "github.com/acme/backend", RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend", Status: model.StatusRunning, Trusted: true, OIDCAllowed: true, LeaseExpiresAt: &exp, LeaseTokenHash: hashLeaseToken(s.leaseKey, "lease1"), LeaseRunnerID: "runner-1"}
	s.mu.Unlock()
	tok := issueOIDCToken(t, s, "job-oidc", "lease1", "https://aud.example.com")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed jwt %q", tok)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(cb, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["repository"] != "acme/backend" {
		t.Fatalf("repository claim = %v, want the display full name", claims["repository"])
	}
	if claims["repository_id"] != "github.com/acme/backend" {
		t.Fatalf("repository_id claim = %v, want the canonical identity", claims["repository_id"])
	}
	if claims["sub"] != "repo:github.com/acme/backend:ref:main:job:build" {
		t.Fatalf("subject = %v, want the canonical subject coordinate", claims["sub"])
	}
}

// TestOPAInputCarriesCanonicalRepoID: the Rego input repository coordinate
// is the canonical identity; a policy keyed for one forge never matches the
// same bare name on another.
func TestOPAInputCarriesCanonicalRepoID(t *testing.T) {
	const rules = `package kiwi

allow := true

deny contains "repository is not github.com/acme/backend" if {
	input.repository != "github.com/acme/backend"
}
`
	s := New("token")
	s.Policy = &policy.Config{OPARules: rules}
	if err := s.ConfigureOPA(); err != nil {
		t.Fatal(err)
	}
	spec, err := pipeline.Parse([]byte(nativePipeline))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	github := SubmitRun{RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend", Ref: "refs/heads/main", Event: "push"}
	if denial := s.opaAdmissionCheck(context.Background(), github, g, policy.DefaultUntrustedCapabilities(), nil); denial != nil {
		t.Fatalf("canonical github input denied: %v", denial.Reasons)
	}
	gitlab := SubmitRun{RepoURL: "https://gitlab.company.com/acme/backend.git", RepoFullName: "acme/backend", Ref: "refs/heads/main", Event: "push"}
	denial := s.opaAdmissionCheck(context.Background(), gitlab, g, policy.DefaultUntrustedCapabilities(), nil)
	if denial == nil {
		t.Fatal("same-name gitlab input must not match the github canonical coordinate")
	}
}

// TestWebhookIngressDerivesCanonicalRepoID: the GitHub and GitLab webhook
// handlers derive the identity from the delivery's forge-native coordinate
// (full_name / path_with_namespace plus the reported instance host) and
// persist it on the run.
func TestWebhookIngressDerivesCanonicalRepoID(t *testing.T) {
	// GitHub: an enterprise clone URL host must win over the public host.
	gh, _ := newGitHubHookServer(t, "hunter2")
	body := `{
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "9049f1265b7d61be4a8904a9a27120d2064dab3b",
  "repository": {
    "id": 42,
    "full_name": "acme/backend",
    "clone_url": "https://github.enterprise.example/acme/backend.git",
    "default_branch": "main"
  }
}`
	w := postWebhook(t, gh, "hunter2", "push", "del-repoid", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("github webhook = %d: %s", w.Code, w.Body.String())
	}
	runID, _ := decodeRun(t, w)
	gh.mu.Lock()
	ghRun := gh.runs[runID]
	gh.mu.Unlock()
	if ghRun.RepoID != "github.enterprise.example/acme/backend" {
		t.Fatalf("github run RepoID = %q, want the enterprise host coordinate", ghRun.RepoID)
	}
	if ghRun.RepoFullName != "acme/backend" {
		t.Fatalf("github run RepoFullName = %q", ghRun.RepoFullName)
	}

	// GitLab: the same bare name on a different forge host is a different
	// identity.
	gl := newGitLabHookServer(t, "gl-secret")
	payload := `{
  "object_kind": "push",
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "9049f1265b7d61be4a8904a9a27120d2064dab3b",
  "checkout_sha": "9049f1265b7d61be4a8904a9a27120d2064dab3b",
  "repository": {
    "name": "backend",
    "git_http_url": "https://gitlab.company.com/acme/backend.git"
  },
  "project": {
    "id": 7,
    "path_with_namespace": "acme/backend",
    "git_http_url": "https://gitlab.company.com/acme/backend.git",
    "http_url_to_repo": "https://gitlab.company.com/acme/backend.git",
    "default_branch": "main"
  }
}`
	w = postGitLabWebhook(t, gl, "gl-secret", "del-repoid-gl", payload)
	if w.Code != http.StatusAccepted {
		t.Fatalf("gitlab webhook = %d: %s", w.Code, w.Body.String())
	}
	runID, _ = decodeRun(t, w)
	gl.mu.Lock()
	glRun := gl.runs[runID]
	gl.mu.Unlock()
	if glRun.RepoID != "gitlab.company.com/acme/backend" {
		t.Fatalf("gitlab run RepoID = %q", glRun.RepoID)
	}
	if ghRun.RepoID == glRun.RepoID {
		t.Fatal("same-name repositories on different forges share a RepoID")
	}

	// Forgejo: derivation from the forge-native full name plus host.
	fj := New("token")
	fj.SetForgeBaseURL("forgejo", "https://forgejo.internal.example")
	got := fj.forgeRepoID("forgejo", forge.Repository{FullName: "acme/backend", CloneURL: "https://forgejo.internal.example/acme/backend.git"})
	if got != "forgejo.internal.example/acme/backend" {
		t.Fatalf("forgejo RepoID = %q", got)
	}
}

// newGitLabHookServer wires a Server against a fake GitLab API serving the
// pipeline contents and an empty compare.
func newGitLabHookServer(t *testing.T, secret string) *Server {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/raw"):
			_, _ = io.WriteString(w, webhookPipeline)
		case strings.Contains(r.URL.Path, "/repository/compare"):
			_ = json.NewEncoder(w).Encode(map[string]any{"diffs": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	s := New("runner-secret")
	s.GitLabWebhookSecret = secret
	s.gitLabAPIBase = api.URL
	s.PipelinePath = ".kiwi/pipeline.yaml"
	return s
}

func postGitLabWebhook(t *testing.T, s *Server, secret, delivery, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/hooks/gitlab", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gitlab-Event", "Push Hook")
	req.Header.Set("X-Gitlab-Token", secret)
	if delivery != "" {
		req.Header.Set("X-Gitlab-Event-UUID", delivery)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

// TestRerunCopiesSourceRepoID: a rerun copies the source run's immutable
// RepoID instead of re-deriving it from the (possibly changed) clone URL.
func TestRerunCopiesSourceRepoID(t *testing.T) {
	s, old := rerunServer(t)
	// The stored identity stays github.com/kiwi/repo while the clone URL
	// points at a moved mirror: re-deriving would flip the identity.
	s.mu.Lock()
	stored := s.runs[old.ID]
	stored.RepoID = "github.com/kiwi/repo"
	stored.Repo = "https://moved.example/kiwi/repo.git"
	s.runs[old.ID] = stored
	s.mu.Unlock()
	out := rerunAs(t, s, "trusted-token", old.ID)
	if out.RepoID != "github.com/kiwi/repo" {
		t.Fatalf("rerun RepoID = %q, want the source run's immutable identity", out.RepoID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.RunID == out.ID && j.RepoID != "github.com/kiwi/repo" {
			t.Fatalf("rerun job RepoID = %q, want the source run's identity", j.RepoID)
		}
	}
}
