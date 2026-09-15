package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/components"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// pinnedImage is a digest-pinned image accepted by untrusted admission.
const pinnedImage = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const componentPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: ubuntu@sha256:` + pinnedImage + `
    component: build@sha256:PLACEHOLDER
    with:
      environment: staging
`

func TestComponentResolutionAtEnqueue(t *testing.T) {
	spec := components.Spec{
		Name: "build",
		Inputs: []components.Input{
			{Name: "environment", Type: "enum", Required: true, Options: []string{"staging", "production"}},
		},
		Steps: []pipeline.Step{{ID: "compile", Run: "make build"}},
		Env:   map[string]string{"CI": "1"},
	}
	digest, err := components.Digest(spec)
	if err != nil {
		t.Fatal(err)
	}
	s := New("secret")
	s.ComponentRegistry = components.NewLocalRegistry()
	s.ComponentRegistry.(*components.LocalRegistry).Register(spec)
	c := newTestClient(t, s.Handler(), "secret")

	pipelineText := strings.Replace(componentPipeline, "PLACEHOLDER", digest, 1)
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: pipelineText}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	var run struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var stored string
	var compDigest string
	for _, j := range s.jobs {
		stored = j.Pipeline
		compDigest = j.ComponentDigest
	}
	if compDigest != digest {
		t.Fatalf("component digest = %q, want %q", compDigest, digest)
	}
	if !strings.Contains(stored, "make build") {
		t.Fatalf("resolved steps missing from canonical pipeline:\n%s", stored)
	}
	if strings.Contains(stored, `"component"`) {
		t.Fatalf("canonical pipeline still carries a component reference:\n%s", stored)
	}
	if !strings.Contains(stored, `"environment":"staging"`) {
		t.Fatalf("with value missing from resolved env:\n%s", stored)
	}
	// The canonical pipeline must itself parse and compile.
	spec2, err := pipeline.Parse([]byte(stored))
	if err != nil {
		t.Fatalf("canonical pipeline does not parse: %v", err)
	}
	if _, err := pipeline.Compile(spec2); err != nil {
		t.Fatalf("canonical pipeline does not compile: %v", err)
	}
}

func TestComponentResolutionErrors(t *testing.T) {
	spec := components.Spec{
		Name: "build",
		Inputs: []components.Input{
			{Name: "environment", Type: "enum", Required: true, Options: []string{"staging", "production"}},
		},
		Steps: []pipeline.Step{{Run: "make build"}},
	}
	digest, err := components.Digest(spec)
	if err != nil {
		t.Fatal(err)
	}
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")

	// No registry configured: component references are rejected.
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: strings.Replace(componentPipeline, "PLACEHOLDER", digest, 1)}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no component registry") {
		t.Fatalf("want registry error, got %d %s", w.Code, w.Body.String())
	}

	reg := components.NewLocalRegistry()
	reg.Register(spec)
	s.ComponentRegistry = reg

	// Unpinned reference is rejected.
	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: `version: 1
jobs:
  build:
    component: build
    with: {environment: staging}
`}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unpinned ref accepted: %d %s", w.Code, w.Body.String())
	}

	// Digest mismatch is rejected.
	bad := strings.Repeat("0", 64)
	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: strings.Replace(componentPipeline, "PLACEHOLDER", bad, 1)}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "digest mismatch") {
		t.Fatalf("want digest mismatch, got %d %s", w.Code, w.Body.String())
	}

	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: `version: 1
jobs:
  build:
    component: build@sha256:` + digest + `
    with: {environment: dev}
`}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "must be one of") {
		t.Fatalf("want enum error, got %d %s", w.Code, w.Body.String())
	}
}

func TestInputsValidationAndInjection(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	pipelineText := `version: 1
inputs:
  environment:
    type: enum
    required: true
    options: [staging, production]
  verbose:
    type: boolean
    default: "false"
  workers:
    type: integer
    default: 2
jobs:
  build:
    runtime: container
    image: ubuntu@sha256:` + pinnedImage + `
    steps:
      - run: echo $KIWI_INPUT_ENVIRONMENT
`
	ok := SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: pipelineText,
		Metadata: map[string]string{"input.environment": "production", "input.workers": "8"}}
	w := c.do(http.MethodPost, "/api/v1/runs", ok, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	var stored string
	for _, j := range s.jobs {
		stored = j.Pipeline
	}
	s.mu.Unlock()
	for _, want := range []string{`"KIWI_INPUT_ENVIRONMENT":"production"`, `"KIWI_INPUT_WORKERS":"8"`, `"KIWI_INPUT_VERBOSE":"false"`} {
		if !strings.Contains(stored, want) {
			t.Fatalf("canonical pipeline missing %s:\n%s", want, stored)
		}
	}

	// Required missing.
	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: pipelineText}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `required input "environment"`) {
		t.Fatalf("want required error, got %d %s", w.Code, w.Body.String())
	}
	// Unknown input.
	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: pipelineText,
		Metadata: map[string]string{"input.environment": "staging", "input.nope": "1"}}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `unknown input "nope"`) {
		t.Fatalf("want unknown input error, got %d %s", w.Code, w.Body.String())
	}
	// Bad boolean.
	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: pipelineText,
		Metadata: map[string]string{"input.environment": "staging", "input.verbose": "yes"}}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "must be a boolean") {
		t.Fatalf("want boolean error, got %d %s", w.Code, w.Body.String())
	}
	// Bad integer.
	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: pipelineText,
		Metadata: map[string]string{"input.environment": "staging", "input.workers": "many"}}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "must be an integer") {
		t.Fatalf("want integer error, got %d %s", w.Code, w.Body.String())
	}
	// Enum membership.
	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: pipelineText,
		Metadata: map[string]string{"input.environment": "dev"}}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "must be one of") {
		t.Fatalf("want enum error, got %d %s", w.Code, w.Body.String())
	}
}
