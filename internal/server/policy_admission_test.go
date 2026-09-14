package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

func submitPipeline(t *testing.T, s *Server, repoURL, repoFull, pipelineText string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":`+jsonString(repoURL)+`,"repo_full_name":`+jsonString(repoFull)+`,"ref":"refs/heads/main","pipeline":`+jsonString(pipelineText)+`}`)
}

func TestCloneHostAllowlistRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{AllowedCloneHosts: []string{"github.com"}}
	w := submitPipeline(t, s, "https://evil.example/o/r.git", "o/r", smokePipeline)
	if w.Code != http.StatusForbidden {
		t.Fatalf("disallowed host = %d, want 403: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["reason"] != "policy_denied" {
		t.Fatalf("reason = %q, want policy_denied", body["reason"])
	}
	w = submitPipeline(t, s, "https://github.com/o/r.git", "o/r", smokePipeline)
	if w.Code != http.StatusAccepted {
		t.Fatalf("allowed host = %d, want 202: %s", w.Code, w.Body.String())
	}
}

func TestCloneHostAllowlistRepoLevel(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {AllowedCloneHosts: []string{"gitlab.example.com"}},
		},
	}
	if w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", smokePipeline); w.Code != http.StatusForbidden {
		t.Fatalf("repo-level disallowed host = %d, want 403: %s", w.Code, w.Body.String())
	}
	if w := submitPipeline(t, s, "https://gitlab.example.com/o/r.git", "o/r", smokePipeline); w.Code != http.StatusAccepted {
		t.Fatalf("repo-level allowed host = %d, want 202: %s", w.Code, w.Body.String())
	}
	// A different repo without a repo-level rule is unrestricted.
	if w := submitPipeline(t, s, "https://github.com/x/y.git", "x/y", smokePipeline); w.Code != http.StatusAccepted {
		t.Fatalf("unrestricted repo = %d, want 202: %s", w.Code, w.Body.String())
	}
}

func TestAllowedRegionsRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{AllowedRegions: []string{"eu-west-1"}}
	regionPipeline := `version: 1
jobs:
  build:
    runtime: container
    placement:
      regions:
        - us-east-1
    steps:
      - run: echo hi
`
	if w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", regionPipeline); w.Code != http.StatusForbidden {
		t.Fatalf("disallowed region = %d, want 403: %s", w.Code, w.Body.String())
	}
	okPipeline := `version: 1
jobs:
  build:
    runtime: container
    placement:
      regions:
        - eu-west-1
    steps:
      - run: echo hi
`
	if w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", okPipeline); w.Code != http.StatusAccepted {
		t.Fatalf("allowed region = %d, want 202: %s", w.Code, w.Body.String())
	}
}

func TestRequireDigestPinsRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{RequireDigestPins: true}
	unpinned := `version: 1
jobs:
  build:
    runtime: container
    image: alpine:latest
    steps:
      - run: echo hi
`
	if w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", unpinned); w.Code != http.StatusForbidden {
		t.Fatalf("unpinned image = %d, want 403: %s", w.Code, w.Body.String())
	}
	unpinnedService := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    services:
      - name: db
        image: postgres:16
    steps:
      - run: echo hi
`
	if w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", unpinnedService); w.Code != http.StatusForbidden {
		t.Fatalf("unpinned service image = %d, want 403: %s", w.Code, w.Body.String())
	}
	unpinnedVM := `version: 1
jobs:
  build:
    runtime: tart
    vm: ghcr.io/cirruslabs/macos-sonoma-base:latest
    steps:
      - run: echo hi
`
	if w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", unpinnedVM); w.Code != http.StatusForbidden {
		t.Fatalf("unpinned vm = %d, want 403: %s", w.Code, w.Body.String())
	}
	pinned := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo hi
`
	if w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", pinned); w.Code != http.StatusAccepted {
		t.Fatalf("pinned image = %d, want 202: %s", w.Code, w.Body.String())
	}
}

func TestPolicyRestrictionsUnsetPolicyPasses(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if w := submitPipeline(t, s, "https://github.com/o/r.git", "o/r", smokePipeline); w.Code != http.StatusAccepted {
		t.Fatalf("no policy = %d, want 202: %s", w.Code, w.Body.String())
	}
}
