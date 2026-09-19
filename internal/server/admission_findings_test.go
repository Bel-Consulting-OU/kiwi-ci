package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const pinnedImageDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// TestNoPolicyDownstreamDeclarationRejected (P0/P1-5): without any policy
// file the capability DEFAULT still rejects a downstream cross-repo
// declaration — the capability invariants must run even when s.Policy is
// nil (the old early return skipped them entirely).
func TestNoPolicyDownstreamDeclarationRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// s.Policy stays nil.
	untrusted := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    downstream:
      repository: acme/child
      ref: refs/heads/main
    steps:
      - run: echo hi
`
	w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", untrusted)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no-policy downstream declaration = %d, want 403: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["reason"] != "policy_denied" {
		t.Fatalf("reason = %q, want policy_denied", body["reason"])
	}
}

// TestNoPolicyGenerateDeclarationRejected (P0/P1-5): same for generate.path.
func TestNoPolicyGenerateDeclarationRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	untrusted := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    generate:
      path: generated.yaml
    steps:
      - run: echo hi
`
	w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", untrusted)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no-policy generate declaration = %d, want 403: %s", w.Code, w.Body.String())
	}
}

// TestPolicyFileAdmissionUnchanged (P0/P1-5): with a policy file loaded the
// split changes nothing — capability-gated declarations, host restrictions
// and digest pins all still behave as before.
func TestPolicyFileAdmissionUnchanged(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{
		AllowedCloneHosts: []string{"github.com"},
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {CrossRepoTrigger: boolPtr(true), GenerateChildGraph: boolPtr(true)},
		},
	}
	// Grant present: the declaration passes; the host must still be
	// allowlisted (org restriction unchanged). CrossRepoTrigger is a
	// grant-gated capability, so it is exercised through the trusted
	// enqueue path (the untrusted floor denies it by design).
	ok := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    downstream:
      repository: acme/child
    steps:
      - run: echo hi
`
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Pipeline: ok, Trusted: true,
	}); err != nil {
		t.Fatalf("granted+allowlisted: %v", err)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://evil.example/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Pipeline: ok, Trusted: true,
	}); err == nil {
		t.Fatal("granted+disallowed host must be rejected")
	}
	// Grant removed: the declaration is rejected again.
	s.Policy = &policy.Config{AllowedCloneHosts: []string{"github.com"}}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Pipeline: ok, Trusted: true,
	}); err == nil {
		t.Fatal("grant removed must reject the declaration")
	}
}

// TestGeneratedFragmentRequireDigestPinsEnforced (P0/P1-6): a generated
// fragment with an unpinned image is rejected when the policy demands
// digest pins — the fragment runs the FULL canonical admission.
func TestGeneratedFragmentRequireDigestPinsEnforced(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	s.Policy = &policy.Config{
		RequireDigestPins: true,
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {GenerateChildGraph: boolPtr(true)},
		},
	}
	runnerID, task := leaseRunJob(t, s)
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine:latest","steps":[{"run":"echo child"}]}},"deps":{}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", fragmentBody(t, frag), leaseHeaders(task, runnerID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("unpinned fragment under require_digest_pins = %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "digest") {
		t.Fatalf("rejection should mention the digest pin: %s", w.Body.String())
	}
	// A pinned fragment passes.
	frag = `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:` + pinnedImageDigest + `","steps":[{"run":"echo child"}]}},"deps":{}}`
	w = doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", fragmentBody(t, frag), leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("pinned fragment = %d, want 201: %s", w.Code, w.Body.String())
	}
}

// TestGeneratedFragmentRegionAllowlistEnforced (P0/P1-6): the fragment's
// placement regions pass the org-policy region allowlist.
func TestGeneratedFragmentRegionAllowlistEnforced(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	s.Policy = &policy.Config{
		AllowedRegions: []string{"eu-west-1"},
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {GenerateChildGraph: boolPtr(true)},
		},
	}
	runnerID, task := leaseRunJob(t, s)
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:` + pinnedImageDigest + `","placement":{"regions":["us-east-1"]},"steps":[{"run":"echo child"}]}},"deps":{}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", fragmentBody(t, frag), leaseHeaders(task, runnerID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("fragment outside allowed regions = %d, want 403: %s", w.Code, w.Body.String())
	}
}

// TestGeneratedFragmentContainerImageRequired (Cleanup): the fragment path
// enforces the container-image structural rule too.
func TestGeneratedFragmentContainerImageRequired(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	frag := `{"jobs":{"child-a":{"runtime":"container","steps":[{"run":"echo child"}]}},"deps":{}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", fragmentBody(t, frag), leaseHeaders(task, runnerID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("imageless container fragment = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "image") {
		t.Fatalf("rejection should mention the image: %s", w.Body.String())
	}
}

// TestScheduleSpecViolatingHostAllowlistRejected (P0/P1-6): a scheduled run
// whose stored clone URL is outside the org clone-host allowlist is
// rejected at fire time through the canonical admission.
func TestScheduleSpecViolatingHostAllowlistRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{AllowedCloneHosts: []string{"github.com"}}
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token",
		`{"repository":"acme/service","repo_url":"https://evil.example/acme/service.git","spec":`+jsonString(scheduleSpec)+`}`)
	if w.Code != http.StatusOK {
		t.Fatalf("put schedule = %d: %s", w.Code, w.Body.String())
	}
	var sc storage.Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	if _, fired, err := s.fireSchedule(context.Background(), sc, time.Now().UTC().Truncate(time.Minute)); err == nil {
		t.Fatal("schedule with disallowed clone host must be rejected at fire")
	} else if fired {
		t.Fatal("rejected schedule reported fired")
	}
}

// TestDownstreamChildAdmissionEnforced (P0/P1-6): the downstream child run
// goes through the canonical admission — a child pipeline violating
// require_digest_pins is refused and the reservation released for retry.
func TestDownstreamChildAdmissionEnforced(t *testing.T) {
	s, _ := downstreamServer(t, downstreamPipeline)
	s.Policy = &policy.Config{
		RequireDigestPins: true,
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {CrossRepoTrigger: boolPtr(true)},
		},
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	unpinnedChild := `version: 1
jobs:
  child-build:
    runtime: container
    image: alpine:latest
    steps:
      - run: echo child
`
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return unpinnedChild, nil
	}
	s.flushOutbox(context.Background())
	if got := childRunsOf(s); len(got) != 0 {
		t.Fatalf("child runs = %d, want 0 (child rejected by admission)", len(got))
	}
	// The failed launch releases the reservation so a retry can proceed.
	link, ok, err := s.getDownstreamLink(context.Background(), task.Job.ID, "acme/child", "refs/heads/main")
	if err != nil || !ok {
		t.Fatalf("link: ok=%v err=%v", ok, err)
	}
	if link.Reserved {
		t.Fatal("failed child admission must release the reservation")
	}
}

// TestContainerWithoutImageRejected (Cleanup): a container job with an
// EMPTY image is a compile-time admission error — never deferred to
// execution.
func TestContainerWithoutImageRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	imageless := `version: 1
jobs:
  build:
    runtime: container
    steps:
      - run: echo hi
`
	w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", imageless)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("imageless container job = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "image") {
		t.Fatalf("rejection should mention the image: %s", w.Body.String())
	}
	// An explicitly empty image is rejected too.
	empty := `version: 1
jobs:
  build:
    runtime: container
    image: ""
    steps:
      - run: echo hi
`
	if w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", empty); w.Code != http.StatusBadRequest {
		t.Fatalf("empty image = %d, want 400: %s", w.Code, w.Body.String())
	}
	// Native runtime without an image stays valid (only container demands
	// one).
	native := `version: 1
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Pipeline: native, Trusted: true,
	}); err != nil {
		t.Fatalf("native job without image must stay valid: %v", err)
	}
}

// TestRequireDigestPinsStrict (P1-29): require_digest_pins uses the strict
// IsDigestPinned check — truncated, uppercase and embedded digests are all
// rejected, and only a terminal "@sha256:<64 lowercase hex>" passes.
func TestRequireDigestPinsStrict(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{RequireDigestPins: true}
	cases := []struct {
		name  string
		image string
		want  int
	}{
		{"truncated digest", "alpine@sha256:aaaa", http.StatusForbidden},
		{"uppercase digest", "alpine@sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", http.StatusForbidden},
		{"embedded digest with tag suffix", "alpine@sha256:" + pinnedImageDigest + ":latest", http.StatusForbidden},
		{"digest not terminal", "alpine@sha256:" + pinnedImageDigest + "/extra", http.StatusForbidden},
		{"bare tag", "alpine:latest", http.StatusForbidden},
		{"strict pinned", "alpine@sha256:" + pinnedImageDigest, http.StatusAccepted},
	}
	for _, tc := range cases {
		p := `version: 1
jobs:
  build:
    runtime: container
    image: ` + tc.image + `
    steps:
      - run: echo hi
`
		w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", p)
		if w.Code != tc.want {
			t.Fatalf("%s = %d, want %d: %s", tc.name, w.Code, tc.want, w.Body.String())
		}
	}
	// Services use the same strict check.
	svc := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    services:
      - name: db
        image: postgres@sha256:` + pinnedImageDigest[:60] + `
    steps:
      - run: echo hi
`
	if w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", svc); w.Code != http.StatusForbidden {
		t.Fatalf("truncated service digest = %d, want 403: %s", w.Code, w.Body.String())
	}
}
