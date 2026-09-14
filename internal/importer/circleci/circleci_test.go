package circleci

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// fixture is a realistic CircleCI 2.1 config exercising docker executors,
// run/checkout/restore_cache/save_cache steps, workflows requires, filters
// and a workflow matrix.
const fixture = `version: 2.1

orbs:
  slack: circleci/slack@4.0.0

jobs:
  build:
    docker:
      - image: cimg/go:1.23
        auth:
          username: $DOCKERHUB_USERNAME
          password: $DOCKERHUB_PASSWORD
      - image: redis:7
    environment:
      CGO_ENABLED: "0"
    steps:
      - checkout
      - run:
          name: build
          command: go build ./...
          working_directory: src
      - run:
          name: quick check
          command: go vet ./...
          when: on_fail
      - save_cache:
          key: v1-modules-{{ checksum "go.sum" }}
          paths:
            - /go/pkg/mod
      - store_artifacts:
          path: bin/
          destination: binaries

  test:
    docker:
      - image: cimg/go:1.23
    steps:
      - checkout
      - restore_cache:
          keys:
            - v1-modules-{{ checksum "go.sum" }}
      - run:
          command: go test ./...

  deploy:
    machine: true
    steps:
      - run:
          command: ./deploy.sh

workflows:
  main:
    jobs:
      - build
      - test:
          requires:
            - build
          filters:
            branches:
              only: [main]
          matrix:
            parameters:
              go: ["1.22", "1.23"]
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

	build := spec.Jobs["build"]
	if build.Runtime != "container" || build.Image != "cimg/go:1.23" {
		t.Fatalf("build runtime/image = %q/%q", build.Runtime, build.Image)
	}
	if build.Env["CGO_ENABLED"] != "0" {
		t.Fatalf("build env = %v", build.Env)
	}
	// run steps with name/command/working_directory and when mapping.
	if len(build.Steps) != 2 {
		t.Fatalf("build steps = %+v, want 2 runnable steps (checkout and save_cache are job-level)", build.Steps)
	}
	if build.Steps[0].Name != "build" || build.Steps[0].WorkingDirectory != "src" {
		t.Fatalf("build step 0 = %+v", build.Steps[0])
	}
	if build.Steps[1].If != "failure()" {
		t.Fatalf("build step 1 if = %q, want failure()", build.Steps[1].If)
	}

	test := spec.Jobs["test"]
	if len(test.Needs) != 1 || test.Needs[0] != "build" {
		t.Fatalf("test needs = %v", test.Needs)
	}
	if len(test.Matrix["go"]) != 2 {
		t.Fatalf("test matrix = %v", test.Matrix)
	}

	// Branch filters land on the push trigger.
	if got := spec.On["push"].Branches; len(got) != 1 || got[0] != "main" {
		t.Fatalf("on.push.branches = %v", got)
	}

	// Machine executor and orbs are reported, never approximated.
	found := map[string]bool{}
	for _, u := range res.Unsupported {
		for _, want := range []string{"machine", "orbs", "auth"} {
			if len(u) >= len(want) && containsSub(u, want) {
				found[want] = true
			}
		}
	}
	for _, want := range []string{"machine", "orbs", "auth"} {
		if !found[want] {
			t.Fatalf("construct %q not reported as unsupported: %v", want, res.Unsupported)
		}
	}
	// checkout/restore_cache/save_cache/store_artifacts surface as TODOs.
	for _, want := range []string{"checkout", "restore_cache", "save_cache", "store_artifacts"} {
		found := false
		for _, td := range res.TODOs {
			if containsSub(td, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("TODO %q missing: %v", want, res.TODOs)
		}
	}
	// A job with only checkout/restore_cache steps must still parse:
	// the runner has an empty step list, which pipeline.Parse rejects,
	// so the importer keeps the run step; verify deploy has one run step.
	deploy := spec.Jobs["deploy"]
	if len(deploy.Steps) != 1 {
		t.Fatalf("deploy steps = %+v", deploy.Steps)
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
