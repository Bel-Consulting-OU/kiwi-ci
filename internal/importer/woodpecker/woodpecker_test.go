package woodpecker

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// fixture is a realistic Woodpecker pipeline exercising images, commands,
// environment, secrets, when filters, depends_on, a job matrix, and plugin
// steps.
const fixture = `branches: [main, develop]

clone:
  depth: 50

pipeline:
  lint:
    image: golang:1.23
    commands:
      - go vet ./...
      - gofmt -l .
    when:
      branch: [main]
      path: ["src/**"]
    matrix:
      GO: ["1.22", "1.23"]

  test:
    image: golang:1.23
    depends_on: [lint]
    environment:
      RACE: "true"
    secrets: [codecov_token]
    commands:
      - go test -race ./...
    when:
      event: [push, tag]

  notify:
    image: plugins/slack
    settings:
      webhook: https://hooks.example.com/x
    when:
      event: [push]
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

	// Top-level branches → on.push.branches.
	if got := spec.On["push"].Branches; len(got) != 2 || got[0] != "main" || got[1] != "develop" {
		t.Fatalf("on.push.branches = %v", got)
	}

	lint := spec.Jobs["lint"]
	if lint.Runtime != "container" || lint.Image != "golang:1.23" {
		t.Fatalf("lint runtime/image = %q/%q", lint.Runtime, lint.Image)
	}
	if len(lint.Steps) != 1 || !contains(lint.Steps[0].Run, "go vet") {
		t.Fatalf("lint steps = %+v", lint.Steps)
	}
	if lint.If != "branch == 'main'" {
		t.Fatalf("lint if = %q", lint.If)
	}
	if len(lint.Paths) != 1 || lint.Paths[0] != "src/**" {
		t.Fatalf("lint paths = %v", lint.Paths)
	}
	if len(lint.Matrix["GO"]) != 2 {
		t.Fatalf("lint matrix = %v", lint.Matrix)
	}

	test := spec.Jobs["test"]
	if len(test.Needs) != 1 || test.Needs[0] != "lint" {
		t.Fatalf("test needs = %v", test.Needs)
	}
	if test.Env["RACE"] != "true" {
		t.Fatalf("test env = %v", test.Env)
	}
	if len(test.Steps) != 1 || len(test.Steps[0].Secrets) != 1 || test.Steps[0].Secrets[0] != "codecov_token" {
		t.Fatalf("test step secrets = %+v", test.Steps)
	}

	// Plugin step: image reported, settings reported, no approximation.
	notify := spec.Jobs["notify"]
	if notify.Runtime != "" {
		t.Fatalf("notify must not get a container runtime for a plugin image, got %q", notify.Runtime)
	}
	found := map[string]bool{}
	for _, u := range res.Unsupported {
		for _, want := range []string{"plugin", "settings", "event"} {
			if contains(u, want) {
				found[want] = true
			}
		}
	}
	for _, want := range []string{"plugin", "settings", "event"} {
		if !found[want] {
			t.Fatalf("construct %q not reported as unsupported: %v", want, res.Unsupported)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
