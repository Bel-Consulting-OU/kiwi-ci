package pipeline

import (
	"strings"
	"testing"
)

const inputsSpecYAML = `version: 1
name: inputs
concurrency:
  group: "${{ repo.full_name }}:${{ git.branch }}"
jobs:
  build:
    matrix:
      GO: ["1.23", "1.24"]
    env:
      TARGET: "${{ inputs.target }}"
      LABEL: "go-${{ matrix.GO }}-${{ inputs.flavor }}"
    steps:
      - id: echo
        run: echo "${{ inputs.target }} ${{ matrix.GO }}"
  deploy:
    needs: [build]
    steps:
      - run: echo deploy
`

func TestInterpolateWithInputsMatrixAndInputs(t *testing.T) {
	m := map[string]string{"GO": "1.23"}
	inputs := map[string]string{"target": "prod", "flavor": "big"}
	cases := []struct {
		src  string
		want string
	}{
		{"${{ inputs.target }}", "prod"},
		{"${{inputs.target}}", "prod"},
		{"${{ matrix.GO }}", "1.23"},
		{"${{ inputs.target }}-${{ matrix.GO }}", "prod-1.23"},
		{"${{ inputs.missing }}", "${{ inputs.missing }}"},
		{"${{ needs.build.outputs.bin }}", "${{ needs.build.outputs.bin }}"},
		{"${{ env.VAR }}", "${{ env.VAR }}"},
		{"pre ${{ inputs.target }} post", "pre prod post"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := InterpolateWithInputs(tc.src, m, inputs); got != tc.want {
			t.Errorf("InterpolateWithInputs(%q) = %q, want %q", tc.src, got, tc.want)
		}
	}
}

func TestInterpolateWithInputsNilInputsKeepsLegacyParity(t *testing.T) {
	m := map[string]string{"GO": "1.23"}
	for _, src := range []string{
		"${{ inputs.target }}",
		"${{inputs.target}}",
		"${{ matrix.GO }}-${{ inputs.target }}",
	} {
		if got, want := InterpolateWithInputs(src, m, nil), Interpolate(src, m); got != want {
			t.Errorf("InterpolateWithInputs(%q, nil) = %q, want Interpolate parity %q", src, got, want)
		}
	}
}

func TestCompileWithInputsResolvesHoles(t *testing.T) {
	s, err := Parse([]byte(inputsSpecYAML))
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string]string{"target": "prod", "flavor": "big"}
	g, err := CompileWithInputs(s, inputs)
	if err != nil {
		t.Fatalf("CompileWithInputs: %v", err)
	}
	cj, ok := g.Jobs["build[GO=1.23]"]
	if !ok {
		t.Fatalf("compiled job build[GO=1.23] missing: %v", g.Jobs)
	}
	if got := cj.Job.Env["TARGET"]; got != "prod" {
		t.Errorf("env TARGET = %q, want prod", got)
	}
	if got := cj.Job.Env["LABEL"]; got != "go-1.23-big" {
		t.Errorf("env LABEL = %q, want go-1.23-big", got)
	}
	if got := cj.Job.Steps[0].Run; got != `echo "prod 1.23"` {
		t.Errorf("step run = %q, want interpolated", got)
	}
	if got := cj.Job.Env["KIWI_INPUT_TARGET"]; got != "prod" {
		t.Errorf("KIWI_INPUT_TARGET = %q, want prod", got)
	}
	if got := cj.Job.Env["KIWI_INPUT_FLAVOR"]; got != "big" {
		t.Errorf("KIWI_INPUT_FLAVOR = %q, want big", got)
	}
	if len(g.Jobs) != 3 {
		t.Errorf("compiled %d jobs, want 3 (2 matrix variants + deploy)", len(g.Jobs))
	}
}

func TestCompileWithInputsMissingInputIsCompileError(t *testing.T) {
	s, err := Parse([]byte(inputsSpecYAML))
	if err != nil {
		t.Fatal(err)
	}
	_, err = CompileWithInputs(s, map[string]string{"other": "x"})
	if err == nil {
		t.Fatal("missing input accepted")
	}
	if !strings.Contains(err.Error(), "inputs") {
		t.Errorf("error %q does not mention the inputs context", err)
	}
	if !strings.Contains(err.Error(), "flavor") {
		t.Errorf("error %q does not name the missing key", err)
	}
}

func TestCompileWithoutInputsIsLenient(t *testing.T) {
	s, err := Parse([]byte(inputsSpecYAML))
	if err != nil {
		t.Fatal(err)
	}
	g, err := Compile(s)
	if err != nil {
		t.Fatalf("Compile with inputs holes must stay lenient: %v", err)
	}
	cj := g.Jobs["build[GO=1.23]"]
	if got := cj.Job.Env["TARGET"]; got != "${{ inputs.target }}" {
		t.Errorf("inputs hole must stay literal without inputs, got %q", got)
	}
	if _, ok := cj.Job.Env["KIWI_INPUT_TARGET"]; ok {
		t.Error("KIWI_INPUT_TARGET must not be injected without inputs")
	}
}

func TestCompileWithInputsMatrixOnlyPipeline(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  x:
    matrix:
      GO: ["1.23"]
    steps:
      - run: go test ./...
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := CompileWithInputs(s, map[string]string{"unused": "v"})
	if err != nil {
		t.Fatalf("inputs unrelated to the pipeline must not break compile: %v", err)
	}
	if len(g.Jobs) != 1 {
		t.Fatalf("compiled %d jobs, want 1", len(g.Jobs))
	}
	if g.Jobs["x[GO=1.23]"].Job.Env["KIWI_INPUT_UNUSED"] != "v" {
		t.Error("provided inputs must still be injected as env")
	}
}
