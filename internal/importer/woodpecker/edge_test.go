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
	// when.branch list is an OR, when.event list is an OR, and the two
	// filters AND together. tag is reported (not silently dropped).
	if build.If != "((branch == 'main' || branch == 'develop') && event == 'push')" {
		t.Fatalf("build if = %q", build.If)
	}
	if len(build.Paths) != 1 || build.Paths[0] != "src/**" {
		t.Fatalf("build paths = %v", build.Paths)
	}
	if len(build.Placement.Labels) != 1 || build.Placement.Labels[0] != "platform-linux-amd64" {
		t.Fatalf("build placement = %+v", build.Placement)
	}

	for _, want := range []string{
		"when.event", "when.repo", "group",
	} {
		if !hasNote(res.Unsupported, want) && !hasNote(res.TODOs, want) {
			t.Errorf("note %q missing: unsupported=%v todos=%v", want, res.Unsupported, res.TODOs)
		}
	}
	// Matrix, clone, skip_clone, privileged, detach are native mappings.
	if !hasNote(res.Mapped, "matrix") {
		t.Errorf("matrix not mapped: %v", res.Mapped)
	}
	if !hasNote(res.Mapped, "clone") {
		t.Errorf("clone not mapped: mapped=%v", res.Mapped)
	}
	if !hasNote(res.Mapped, "skip_clone") {
		t.Errorf("skip_clone not mapped: %v", res.Mapped)
	}
	if !hasNote(res.Mapped, "privileged") {
		t.Errorf("privileged not mapped as trust-gated capability: %v", res.Mapped)
	}
	if hasNote(res.Unsafe, "privileged") {
		t.Errorf("privileged is a trust-gated Kiwi capability, not an unsafe drop: %v", res.Unsafe)
	}
	if !hasNote(res.Mapped, "detach") {
		t.Errorf("detach not mapped to step background: %v", res.Mapped)
	}
	if build.Sandbox.Privileged != true {
		t.Errorf("build sandbox.privileged = %v, want true", build.Sandbox.Privileged)
	}
	if !build.Clone.Skip {
		t.Errorf("build clone.skip = false, want true from skip_clone")
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

// TestImportWhenBranchScalarGlobAndInjection locks the F6-C fixes: a scalar
// when.branch is honored; a wildcard pattern becomes a glob predicate that
// still matches glob-style; and a branch value containing a quote cannot
// inject condition operators (the condition is left unset and reported).
func TestImportWhenBranchScalarGlobAndInjection(t *testing.T) {
	const src = `steps:
  scalar:
    image: alpine
    commands: [echo s]
    when:
      branch: main
  glob:
    image: alpine
    commands: [echo g]
    when:
      branch: release/*
`
	res, err := New().Import(src)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v\n%s", err, res.PipelineYAML)
	}
	if got := spec.Jobs["scalar"].If; got != "branch == 'main'" {
		t.Fatalf("scalar branch if = %q", got)
	}
	glob := spec.Jobs["glob"].If
	if glob != "branchMatch('release/*')" {
		t.Fatalf("glob branch if = %q", glob)
	}
	// The glob predicate keeps glob semantics (release/1.2 matches,
	// main does not).
	if ok, err := pipeline.Eval(glob, pipeline.EvalContext{Branch: "release/1.2"}); err != nil || !ok {
		t.Fatalf("glob if must match release/1.2: ok=%v err=%v", ok, err)
	}
	if ok, err := pipeline.Eval(glob, pipeline.EvalContext{Branch: "main"}); err != nil || ok {
		t.Fatalf("glob if must not match main: ok=%v err=%v", ok, err)
	}

	// Injection: a branch value carrying a quote cannot become a condition.
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("when:\n  branch: \"x' || true || '\"\n"), &root); err != nil {
		t.Fatal(err)
	}
	res = &importer.Result{}
	j := pipeline.Job{}
	convertWhen(res, importer.Key(importer.Document(&root), "when"), "job", &j)
	if j.If != "" {
		t.Fatalf("quote-bearing branch must not produce a condition, got %q", j.If)
	}
	if !hasNote(res.Unsupported, "cannot be expressed") {
		t.Fatalf("unsafe branch value not reported: %v", res.Unsupported)
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
