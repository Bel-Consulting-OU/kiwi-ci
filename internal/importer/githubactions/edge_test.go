package githubactions

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

const edgeFixture = `name: edges

defaults:
  run:
    shell: pwsh

secrets:
  TOKEN: ${{ secrets.TOKEN }}

on:
  push:
  pull_request:
    types: [opened, synchronize]
    branches-ignore: [wip/**]
    tags: [v*]
    tags-ignore: [v0.*]

jobs:
  edge:
    runs-on: [self-hosted, linux]
    needs: ["", not-a-job]
    if: github.ref == 'refs/heads/main'
    env:
      A: "1"
    outputs:
      out: "x"
    strategy:
      fail-fast: true
      matrix:
        include:
          - go: "1.24"
    secrets:
      S: value
    environment: prod
    permissions:
      contents: read
    concurrency:
      group: g
    steps:
      - name: empty
      - name: envstep
        run: echo hi
        env:
          B: "2"
        shell: python
      - name: cond
        run: echo cond
        if: github.event_name == 'push'
      - uses: docker/build-push-action@v5
      - name: withstep
        run: echo with
        with:
          file: Dockerfile
          push: true
  weird:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        bad: [{k: v}, scalar]
        onlyinclude:
          include:
            - go: "1.24"
    steps:
      - "not a mapping"
      - name: ok
        run: "true"
  stratonly:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
    steps:
      - name: ok
        run: "true"
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
	if spec.Defaults.Shell != "pwsh" {
		t.Fatalf("defaults shell = %q", spec.Defaults.Shell)
	}
	if !hasUnsupported(res, "workflow-level secrets") {
		t.Fatalf("workflow secrets not reported: %v", res.Unsupported)
	}

	// on.push with an empty config still produces the trigger.
	if _, ok := spec.On["push"]; !ok {
		t.Fatalf("empty push trigger missing: %+v", spec.On)
	}
	pr := spec.On["pull_request"]
	if len(pr.Actions) != 2 || pr.Actions[0] != "opened" {
		t.Fatalf("pull_request types = %v", pr.Actions)
	}
	if len(pr.Tags) != 1 || pr.Tags[0] != "v*" || len(pr.TagsIgnore) != 1 {
		t.Fatalf("tags = %v / %v", pr.Tags, pr.TagsIgnore)
	}

	edge := spec.Jobs["edge"]
	if len(edge.Runner) != 2 || edge.Runner[0] != "self-hosted" {
		t.Fatalf("runner = %v", edge.Runner)
	}
	if len(edge.Needs) != 0 {
		t.Fatalf("needs must drop unknown/empty references, got %v", edge.Needs)
	}
	if edge.If != "" {
		t.Fatalf("unmappable condition must not be set, got %q", edge.If)
	}
	if edge.Env["A"] != "1" || edge.Outputs["out"] != "x" {
		t.Fatalf("env/outputs = %v / %v", edge.Env, edge.Outputs)
	}
	if edge.Matrix != nil {
		t.Fatalf("include-only matrix must collapse to nil, got %v", edge.Matrix)
	}
	if !hasUnsupported(res, "strategy.matrix.include") || !hasUnsupported(res, "secrets") ||
		!hasUnsupported(res, "environment") || !hasUnsupported(res, "permissions") ||
		!hasUnsupported(res, "concurrency") {
		t.Fatalf("unsupported reports incomplete: %v", res.Unsupported)
	}
	if !hasUnsupported(res, "Kiwi cannot evaluate") {
		t.Fatalf("unmappable condition not reported: %v", res.Unsupported)
	}

	// Steps: the bare "empty" step is skipped; envstep keeps env and shell;
	// cond drops an unmappable condition; "with" produces a TODO; the
	// unknown action is a disabled placeholder.
	names := map[string]pipeline.Step{}
	for _, st := range edge.Steps {
		names[st.Name] = st
	}
	if _, ok := names["empty"]; ok {
		t.Fatalf("step without run/uses must be skipped: %+v", edge.Steps)
	}
	envStep, ok := names["envstep"]
	if !ok || envStep.Env["B"] != "2" || envStep.Shell != "python" {
		t.Fatalf("envstep = %+v", envStep)
	}
	if _, ok := names["cond"]; !ok {
		t.Fatalf("cond step missing: %+v", edge.Steps)
	}
	if !hasUnsupported(res, "step") {
		t.Fatalf("step-level unmappable condition not reported: %v", res.Unsupported)
	}
	if !hasTODO(res, "with") {
		t.Fatalf("with-parameters TODO missing: %v", res.TODOs)
	}
	var placeholder bool
	for _, st := range edge.Steps {
		if st.If == "false" && strings.Contains(st.Run, "build-push-action") {
			placeholder = true
		}
	}
	if !placeholder {
		t.Fatalf("unknown action placeholder missing: %+v", edge.Steps)
	}

	// stratonly: strategy without a matrix is ignored (no matrix emitted).
	stratonly := spec.Jobs["stratonly"]
	if stratonly.Matrix != nil {
		t.Fatalf("strategy without matrix must not emit a matrix: %v", stratonly.Matrix)
	}
	if !hasUnsupported(res, "strategy.fail-fast: false") {
		t.Fatalf("fail-fast: false not reported: %v", res.Unsupported)
	}

	// weird: the non-scalar matrix dimension is dropped whole (an empty
	// dimension must never reach the YAML) and the non-mapping step skipped.
	weird := spec.Jobs["weird"]
	if got, ok := weird.Matrix["bad"]; ok {
		t.Fatalf("non-scalar matrix dimension must be omitted, got %v", got)
	}
	if weird.Matrix != nil {
		t.Fatalf("include-only and dropped dimensions must collapse to nil, got %v", weird.Matrix)
	}
	if len(weird.Steps) != 1 || weird.Steps[0].Name != "ok" {
		t.Fatalf("non-mapping step must be skipped, got %+v", weird.Steps)
	}
	if !hasUnsupported(res, "not representable") {
		t.Fatalf("non-scalar matrix dimension not reported: %v", res.Unsupported)
	}
	if !hasUnsupportedSlice(res.Warnings, "non-scalar values") {
		t.Fatalf("non-scalar matrix dimension warning missing: %v", res.Warnings)
	}
	if res.Confidence <= 0 || res.Confidence >= 1 {
		t.Fatalf("confidence = %v, want in (0,1)", res.Confidence)
	}
}

// TestImportNonScalarAndEmptyMatrixDimensionsRoundTrip locks the fix for the
// empty-matrix-dimension defect: every unsupported/empty dimension is
// diagnosed and omitted, and the generated YAML always round-trips through
// pipeline.Parse.
func TestImportNonScalarAndEmptyMatrixDimensionsRoundTrip(t *testing.T) {
	const src = `name: matrix
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        go: ["1.22", "1.23"]
        bad: [{k: v}]
        empty: []
        mixed: [{k: v}, "ok"]
    steps:
      - name: ok
        run: "true"
`
	res, err := New().Import(src)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v\n%s", err, res.PipelineYAML)
	}
	matrix := spec.Jobs["build"].Matrix
	if len(matrix) != 1 {
		t.Fatalf("matrix = %v, want only the scalar dimension", matrix)
	}
	if got := matrix["go"]; len(got) != 2 || got[0] != "1.22" || got[1] != "1.23" {
		t.Fatalf("go dimension = %v", got)
	}
	for _, dim := range []string{"bad", "empty", "mixed"} {
		if !hasUnsupportedSlice(res.Unsupported, fmt.Sprintf("%q", dim)) {
			t.Fatalf("dimension %q not reported: %v", dim, res.Unsupported)
		}
		if !hasUnsupportedSlice(res.Warnings, fmt.Sprintf("%q", dim)) {
			t.Fatalf("dimension %q warning missing: %v", dim, res.Warnings)
		}
	}
	if !hasUnsupported(res, "not representable") || !hasUnsupported(res, "has no values") {
		t.Fatalf("diagnoses incomplete: %v", res.Unsupported)
	}
}

func TestImportRejectsMalformedInput(t *testing.T) {
	if _, err := New().Import("a: [unclosed\n"); err == nil {
		t.Fatal("malformed YAML must fail")
	} else if !strings.Contains(err.Error(), "parse workflow") {
		t.Fatalf("error = %v, want parse workflow", err)
	}
	if _, err := New().Import("- just\n- a\n- list\n"); err == nil {
		t.Fatal("non-mapping document must fail")
	} else if !strings.Contains(err.Error(), "must be a YAML mapping") {
		t.Fatalf("error = %v, want mapping error", err)
	}
}

func TestTriggerFromNilAndNull(t *testing.T) {
	if t0 := triggerFrom(nil); t0.Branches != nil || t0.Actions != nil {
		t.Fatalf("triggerFrom(nil) = %+v", t0)
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("on:\n  push:\n"), &root); err != nil {
		t.Fatal(err)
	}
	doc := importer.Document(&root)
	push := importer.Key(importer.Key(doc, "on"), "push")
	got := triggerFrom(push)
	if got.Branches != nil || got.Paths != nil {
		t.Fatalf("triggerFrom(null) = %+v", got)
	}
}

func TestConvertJobMissingDefinition(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("jobs:\n  real:\n    runs-on: ubuntu-latest\n"), &root); err != nil {
		t.Fatal(err)
	}
	jobs := importer.Key(importer.Document(&root), "jobs")
	res := &importer.Result{}
	j := convertJob(res, jobs, "absent", map[string]string{})
	if j.Needs != nil || len(j.Steps) != 0 {
		t.Fatalf("convertJob(absent) = %+v", j)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], `"absent"`) {
		t.Fatalf("warnings = %v", res.Warnings)
	}
}

func TestMapKeysSorted(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("with:\n  z: 1\n  a: 2\n  m: 3\n"), &root); err != nil {
		t.Fatal(err)
	}
	got := mapKeys(importer.Key(importer.Document(&root), "with"))
	want := []string{"a", "m", "z"}
	if len(got) != len(want) {
		t.Fatalf("mapKeys = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mapKeys = %v, want %v", got, want)
		}
	}
	if got := mapKeys(nil); got != nil {
		t.Fatalf("mapKeys(nil) = %v", got)
	}
}

// TestImportMatrixDimensionAllNonScalar locks the fix: a matrix dimension
// whose values are all non-scalar is diagnosed and omitted, so the generated
// document always parses with pipeline.Parse.
func TestImportMatrixDimensionAllNonScalar(t *testing.T) {
	const src = `name: non-scalar
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        bad: [{k: v}]
    steps:
      - name: ok
        run: "true"
`
	res, err := New().Import(src)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !hasUnsupported(res, "not representable") {
		t.Fatalf("non-scalar matrix dimension not reported: %v", res.Unsupported)
	}
	if !hasUnsupportedSlice(res.Warnings, `"bad"`) {
		t.Fatalf("non-scalar matrix dimension warning missing: %v", res.Warnings)
	}
	// The empty dimension must not be emitted, so the document parses and
	// the job carries no matrix at all.
	if _, perr := pipeline.Parse([]byte(res.PipelineYAML)); perr != nil {
		t.Fatalf("generated pipeline does not parse: %v\n%s", perr, res.PipelineYAML)
	}
	if strings.Contains(res.PipelineYAML, "bad") {
		t.Fatalf("dropped dimension leaked into the YAML:\n%s", res.PipelineYAML)
	}
}
