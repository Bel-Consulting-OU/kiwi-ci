package gitlab

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// fixture is a realistic multi-stage GitLab pipeline exercising the mapped
// constructs and several that must be reported.
const fixture = `stages:
  - build
  - test
  - deploy

variables:
  GO_VERSION: "1.23"
  CI: "false"

default:
  image: golang:1.23

cache:
  key:
    files:
      - go.sum
  paths:
    - vendor/

workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

build-binary:
  stage: build
  tags:
    - docker
    - linux
  script:
    - go build -o bin/app ./...
  artifacts:
    paths:
      - bin/app
    name: app-binary
    expire_in: 1 week
  timeout: 30m

unit-tests:
  stage: test
  image: golang:1.23
  needs:
    - job: build-binary
      artifacts: true
  retry:
    max: 2
    when:
      - runner_system_failure
  variables:
    TEST_MODE: race
  script:
    - go test -race ./...

lint:
  stage: test
  allow_failure: true
  before_script:
    - go version
  script:
    - go vet ./...
  after_script:
    - echo cleanup
  rules:
    - changes:
        - "src/**"
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: never

deploy-prod:
  stage: deploy
  environment:
    name: production
    url: https://example.com
  when: manual
  script:
    - ./deploy.sh
`

func TestImportParsesAndMapsSemantics(t *testing.T) {
	res, err := New().Import(fixture)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v\n%s", err, res.PipelineYAML)
	}

	// Global variables → pipeline env.
	if spec.Env["GO_VERSION"] != "1.23" {
		t.Fatalf("env = %v", spec.Env)
	}

	// Stage ordering → needs.
	unit := spec.Jobs["unit-tests"]
	wantNeeds := []string{"build-binary"}
	if len(unit.Needs) != 1 || unit.Needs[0] != "build-binary" {
		t.Fatalf("unit-tests needs = %v, want %v", unit.Needs, wantNeeds)
	}
	// lint is in the test stage too: it depends on build-binary (stage build).
	lint := spec.Jobs["lint"]
	if len(lint.Needs) != 1 || lint.Needs[0] != "build-binary" {
		t.Fatalf("lint needs = %v, want [build-binary]", lint.Needs)
	}
	// deploy depends on both earlier stages.
	deploy := spec.Jobs["deploy-prod"]
	if len(deploy.Needs) != 3 {
		t.Fatalf("deploy needs = %v, want 3 (build + test jobs)", deploy.Needs)
	}

	// Image → container runtime.
	if unit.Runtime != "container" || unit.Image != "golang:1.23" {
		t.Fatalf("unit-tests runtime/image = %q/%q", unit.Runtime, unit.Image)
	}
	// Default image applied to jobs without one.
	build := spec.Jobs["build-binary"]
	if build.Runtime != "container" || build.Image != "golang:1.23" {
		t.Fatalf("build-binary runtime/image = %q/%q", build.Runtime, build.Image)
	}

	// Tags → runner labels.
	if len(build.Runner) != 2 || build.Runner[0] != "docker" || build.Runner[1] != "linux" {
		t.Fatalf("build runner labels = %v", build.Runner)
	}

	// Script → steps; artifacts; cache; timeout.
	if len(build.Steps) != 1 || build.Steps[0].Run != "go build -o bin/app ./..." {
		t.Fatalf("build steps = %+v", build.Steps)
	}
	if len(build.Artifacts) != 1 || build.Artifacts[0].Name != "app-binary" || len(build.Artifacts[0].Paths) != 1 {
		t.Fatalf("build artifacts = %+v", build.Artifacts)
	}
	if build.Timeout.Duration.String() != "30m0s" {
		t.Fatalf("build timeout = %v", build.Timeout.Duration)
	}
	if len(build.Cache) != 1 || len(build.Cache[0].HashFiles) != 1 || build.Cache[0].HashFiles[0] != "go.sum" {
		t.Fatalf("build cache = %+v", build.Cache)
	}

	// Retry maps to job retry.
	if unit.Retry.Max != 2 {
		t.Fatalf("unit retry = %+v", unit.Retry)
	}

	// Job variables → env.
	if unit.Env["TEST_MODE"] != "race" {
		t.Fatalf("unit env = %v", unit.Env)
	}

	// allow_failure → continue_on_error steps.
	if len(lint.Steps) == 0 || !lint.Steps[len(lint.Steps)-1].ContinueOnError {
		t.Fatalf("lint steps lack continue_on_error: %+v", lint.Steps)
	}

	// rules: changes → paths, when: never + predefined variable if → report.
	if len(lint.Paths) != 1 || lint.Paths[0] != "src/**" {
		t.Fatalf("lint paths = %v", lint.Paths)
	}

	// environment.
	if deploy.Environment.Name != "production" || deploy.Environment.URL != "https://example.com" {
		t.Fatalf("deploy environment = %+v", deploy.Environment)
	}

	// Unsupported constructs are reported, never approximated.
	for _, want := range []string{"allow_failure", "when: manual", "after_script", "predefined variables"} {
		found := false
		for _, u := range res.Unsupported {
			if containsSub(u, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("construct %q not reported as unsupported: %v", want, res.Unsupported)
		}
	}
}

func TestParseGitLabDuration(t *testing.T) {
	cases := map[string]string{
		"1h": "1h0m0s", "30m": "30m0s", "1h 30m": "1h30m0s", "45s": "45s",
	}
	for in, want := range cases {
		d, ok := parseGitLabDuration(in)
		if !ok || d.String() != want {
			t.Errorf("parseGitLabDuration(%q) = %v (ok=%v), want %s", in, d, ok, want)
		}
	}
	if _, ok := parseGitLabDuration("bogus"); ok {
		t.Errorf("parseGitLabDuration(bogus) ok, want false")
	}
}

func containsSub(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
