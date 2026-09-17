package woodpecker

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// edgeFixture uses the `steps:` spelling, a pipeline-level matrix, clone and
// skip_clone settings, multi-branch when filters and multi-key conditions.
const edgeFixture = `branches: [main]

matrix:
  GO: ["1.22"]

clone:
  depth: 1

skip_clone: true

steps:
  build:
    image: golang:1.23
    commands: [go build ./...]
    environment:
      CGO: "0"
    when:
      branch: [main, develop]
      path: [src/**]
      event: [push, tag]
      repo: example/repo
      platform: linux/amd64
    detach: true
    privileged: true
    group: deploy

  dup:
    image: alpine:3.20
    commands: [echo dup]
    depends_on: [build, build]
`

func TestImportEdgeFixture(t *testing.T) {
	res, err := New().Import(edgeFixture)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v\n%s", err, res.PipelineYAML)
	}

	if got := spec.On["push"].Branches; len(got) != 1 || got[0] != "main" {
		t.Fatalf("on.push.branches = %v", got)
	}

	build := spec.Jobs["build"]
	if build.Image != "golang:1.23" || build.Env["CGO"] != "0" {
		t.Fatalf("build = %+v", build)
	}
	if build.If != "(branch == 'main' || branch == 'develop')" {
		t.Fatalf("build if = %q", build.If)
	}
	if len(build.Paths) != 1 || build.Paths[0] != "src/**" {
		t.Fatalf("build paths = %v", build.Paths)
	}

	for _, want := range []string{
		"pipeline-level matrix", "clone settings", "skip_clone",
		"when.event", "when.repo/platform", "detach/privileged", "group",
	} {
		if !hasNote(res.Unsupported, want) && !hasNote(res.TODOs, want) {
			t.Errorf("note %q missing: unsupported=%v todos=%v", want, res.Unsupported, res.TODOs)
		}
	}

	dup := spec.Jobs["dup"]
	if len(dup.Needs) != 1 || dup.Needs[0] != "build" {
		t.Fatalf("duplicate depends_on must collapse: %v", dup.Needs)
	}
}

func TestImportRejectsMalformedInput(t *testing.T) {
	if _, err := New().Import("a: [unclosed\n"); err == nil || !strings.Contains(err.Error(), "parse .woodpecker.yml") {
		t.Fatalf("error = %v", err)
	}
	if _, err := New().Import("- a\n"); err == nil || !strings.Contains(err.Error(), "must be a YAML mapping") {
		t.Fatalf("error = %v", err)
	}
}

func TestSecretsWithoutStepsIsReported(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("image: alpine\nsecrets: [token, other]\n"), &root); err != nil {
		t.Fatal(err)
	}
	res := &importer.Result{}
	j := convertStepBlock(res, importer.Document(&root), "lonely")
	if len(j.Steps) != 0 {
		t.Fatalf("steps = %+v", j.Steps)
	}
	if !hasNote(res.TODOs, "no commands step") {
		t.Fatalf("unattachable secrets not reported: %v", res.TODOs)
	}
}

func TestConvertWhenSingleAndEmptyBranch(t *testing.T) {
	parse := func(t *testing.T, src string) *yaml.Node {
		t.Helper()
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(src), &root); err != nil {
			t.Fatal(err)
		}
		return importer.Key(importer.Document(&root), "when")
	}
	res := &importer.Result{}

	j := pipeline.Job{}
	convertWhen(res, parse(t, "when: {branch: [release]}\n"), "job", &j)
	if j.If != "branch == 'release'" {
		t.Fatalf("single branch if = %q", j.If)
	}

	j = pipeline.Job{}
	convertWhen(res, parse(t, "when: {branch: []}\n"), "job", &j)
	if j.If != "" {
		t.Fatalf("empty branch list must not set if, got %q", j.If)
	}

	// event list with only push: no report.
	j = pipeline.Job{}
	convertWhen(res, parse(t, "when: {event: [push]}\n"), "job", &j)
	if len(res.Unsupported) != 0 {
		t.Fatalf("push-only events must not be reported: %v", res.Unsupported)
	}
}

func TestSeqAnyNilAndScalars(t *testing.T) {
	if got := seqAny(nil); len(got) != 0 {
		t.Fatalf("seqAny(nil) = %#v", got)
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("- 7\n- {a: b}\n- nope\n"), &root); err != nil {
		t.Fatal(err)
	}
	got := seqAny(importer.Document(&root))
	if len(got) != 2 || got[0] != 7 || got[1] != "nope" {
		t.Fatalf("seqAny = %#v", got)
	}
}

func TestMapKeysAndAppendUnique(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("settings: {z: 1, a: 2}\n"), &root); err != nil {
		t.Fatal(err)
	}
	got := mapKeys(importer.Key(importer.Document(&root), "settings"))
	if len(got) != 2 || got[0] != "a" || got[1] != "z" {
		t.Fatalf("mapKeys = %v", got)
	}

	list := appendUnique(nil, "a")
	list = appendUnique(list, "b")
	list = appendUnique(list, "a")
	if len(list) != 2 {
		t.Fatalf("appendUnique = %v", list)
	}
}

func hasNote(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
