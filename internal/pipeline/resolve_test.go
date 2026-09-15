package pipeline

import (
	"strings"
	"testing"
)

func TestResolveInputsInterpolatesEffectiveSpec(t *testing.T) {
	s, err := Parse([]byte(`version: 1
inputs:
  target:
    type: string
  flavor:
    type: string
jobs:
  build:
    env:
      TARGET: "${{ inputs.target }}"
    cache:
      - key: "deps-${{ inputs.flavor }}"
        paths: [.cache]
    steps:
      - run: echo "${{ inputs.target }}"
`))
	if err != nil {
		t.Fatal(err)
	}
	effective, err := ResolveInputs(s, map[string]string{"target": "prod", "flavor": "big"})
	if err != nil {
		t.Fatal(err)
	}
	j := effective.Jobs["build"]
	if j.Env["TARGET"] != "prod" {
		t.Errorf("env TARGET = %q, want prod", j.Env["TARGET"])
	}
	if j.Cache[0].Key != "deps-big" {
		t.Errorf("cache key = %q, want deps-big", j.Cache[0].Key)
	}
	if j.Steps[0].Run != `echo "prod"` {
		t.Errorf("step run = %q, want interpolated", j.Steps[0].Run)
	}
	if j.Env["KIWI_INPUT_TARGET"] != "prod" || j.Env["KIWI_INPUT_FLAVOR"] != "big" {
		t.Errorf("input env injection missing: %v", j.Env)
	}
	if _, ok := effective.ProvidedInputs["target"]; !ok {
		t.Error("ProvidedInputs not recorded on the effective spec")
	}
	// The effective spec must round-trip through the canonical form and
	// re-parse: the stored pipeline text is the input-interpolated spec.
	b, err := CanonicalJSON(effective)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"TARGET":"prod"`) {
		t.Fatalf("canonical text does not carry the interpolated value:\n%s", b)
	}
	reparsed, err := Parse(b)
	if err != nil {
		t.Fatalf("effective spec does not re-parse: %v", err)
	}
	if reparsed.Jobs["build"].Env["TARGET"] != "prod" {
		t.Error("interpolation lost in canonical round-trip")
	}
}

func TestResolveInputsLeavesMatrixHolesLiteral(t *testing.T) {
	s, err := Parse([]byte(`version: 1
inputs:
  target: {type: string}
jobs:
  x:
    matrix:
      GO: ["1.23"]
    steps:
      - run: echo ${{ matrix.GO }} ${{ inputs.target }}
`))
	if err != nil {
		t.Fatal(err)
	}
	effective, err := ResolveInputs(s, map[string]string{"target": "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got := effective.Jobs["x"].Steps[0].Run; got != "echo ${{ matrix.GO }} t" {
		t.Fatalf("matrix hole must stay literal for the compile pass, got %q", got)
	}
	// Compile on the resolved spec interpolates the matrix per variant.
	g, err := Compile(effective)
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Jobs["x[GO=1.23]"].Job.Steps[0].Run; got != "echo 1.23 t" {
		t.Fatalf("compiled step = %q, want fully interpolated", got)
	}
}

func TestResolveInputsRejectsMissingInputs(t *testing.T) {
	s, err := Parse([]byte(`version: 1
inputs:
  target: {type: string}
jobs:
  x:
    steps:
      - run: echo ${{ inputs.target }} ${{ inputs.missing }}
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveInputs(s, map[string]string{"target": "t"}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing input error = %v, want missing-key rejection", err)
	}
}

func TestResolveInputsDoesNotMutateSource(t *testing.T) {
	s, err := Parse([]byte(`version: 1
inputs:
  target: {type: string}
jobs:
  x:
    env:
      TARGET: "${{ inputs.target }}"
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	before := s.Jobs["x"].Env["TARGET"]
	if _, err := ResolveInputs(s, map[string]string{"target": "prod"}); err != nil {
		t.Fatal(err)
	}
	if after := s.Jobs["x"].Env["TARGET"]; after != before {
		t.Fatalf("ResolveInputs mutated the source spec: %q -> %q", before, after)
	}
}

func TestParseWithComponentsRelaxesOnlyComponentJobs(t *testing.T) {
	// A component job without its own steps parses under the resolution
	// relaxation.
	spec, err := ParseWithComponents([]byte(`version: 1
jobs:
  build:
    component: build@sha256:` + strings.Repeat("a", 64) + `
    with:
      environment: staging
`))
	if err != nil {
		t.Fatalf("component job without steps rejected: %v", err)
	}
	if spec.Jobs["build"].Component == "" || spec.Jobs["build"].With["environment"] != "staging" {
		t.Fatalf("component reference lost: %+v", spec.Jobs["build"])
	}
	// A regular job without steps is still rejected.
	if _, err := ParseWithComponents([]byte(`version: 1
jobs:
  x:
    name: no steps
`)); err == nil || !strings.Contains(err.Error(), "no steps") {
		t.Fatalf("step-less non-component job error = %v, want rejection", err)
	}
	// Strictness on the original bytes: unknown fields are rejected with a
	// line number even in component-using pipelines.
	_, err = ParseWithComponents([]byte("version: 1\njobs:\n  build:\n    component: build@sha256:" + strings.Repeat("a", 64) + "\n    bogus_field: true\n"))
	if err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "line 5") {
		t.Fatalf("unknown field error = %v, want line-numbered rejection", err)
	}
	// Duplicate keys and aliases are rejected on the original bytes.
	_, err = ParseWithComponents([]byte("version: 1\njobs:\n  build:\n    component: a\n    component: b\n"))
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate key error = %v", err)
	}
	_, err = ParseWithComponents([]byte("version: 1\njobs:\n  build:\n    component: build@sha256:" + strings.Repeat("a", 64) + "\n  build2: &anchor\n    component: x\n  build3: *anchor\n"))
	if err == nil {
		t.Fatal("alias must be rejected")
	}
	// The full Parse still rejects component jobs without steps.
	if _, err := Parse([]byte(`version: 1
jobs:
  build:
    component: build@sha256:` + strings.Repeat("a", 64) + "\n")); err == nil || !strings.Contains(err.Error(), "no steps") {
		t.Fatalf("Parse component job without steps error = %v, want rejection", err)
	}
}

func TestParseWithComponentsValidatesEverythingElse(t *testing.T) {
	// Everything other than the step-presence rule applies on the original
	// bytes: an invalid runtime on a component job is still rejected.
	_, err := ParseWithComponents([]byte(`version: 1
jobs:
  build:
    runtime: spaceship
    component: build@sha256:` + strings.Repeat("a", 64) + `
`))
	if err == nil || !strings.Contains(err.Error(), "unsupported runtime") {
		t.Fatalf("component job runtime error = %v, want rejection", err)
	}
}
