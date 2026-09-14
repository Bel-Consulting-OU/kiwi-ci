package githubactions

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// workflowFixture is a realistic mid-size GitHub Actions workflow covering
// the constructs the importer maps and several it must refuse to
// approximate.
const workflowFixture = `name: go-ci

on:
  push:
    branches: [main]
    paths: ["src/**"]
    paths-ignore: ["docs/**"]
  pull_request:
    branches: ["**"]
  schedule:
    - cron: "0 3 * * 1"

env:
  GO_VERSION: "1.23"
  CGO_ENABLED: "0"

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: vet
        run: go vet ./...

  test:
    runs-on: ubuntu-latest
    needs: [lint]
    if: ${{ success() }}
    timeout-minutes: 15
    env:
      TEST_FLAGS: "-race"
    strategy:
      matrix:
        go: ["1.22", "1.23"]
        include:
          - go: "1.24"
      fail-fast: false
    container:
      image: golang:1.23
    services:
      postgres:
        image: postgres:16
        ports: ["5432:5432"]
    outputs:
      artifact_name: ${{ steps.build.outputs.name }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "${{ matrix.go }}"
      - name: build
        run: go build ./...
        working-directory: src
        continue-on-error: false
      - name: test
        run: go test ./...
        continue-on-error: true
        timeout-minutes: 5
        if: always()
      - uses: codecov/codecov-action@v4
        with:
          file: coverage.out

  cleanup:
    runs-on: ubuntu-latest
    needs: [test]
    if: ${{ failure() }}
    steps:
      - name: report failure
        run: echo "build failed"
`

func TestImportParsesAndMapsSemantics(t *testing.T) {
	res, err := New().Import(workflowFixture)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v\n%s", err, res.PipelineYAML)
	}

	// Triggers: push branches/paths/paths-ignore, pull_request branches;
	// the schedule cron is unsupported.
	push, ok := spec.On["push"]
	if !ok {
		t.Fatalf("missing push trigger: %+v", spec.On)
	}
	if len(push.Branches) != 1 || push.Branches[0] != "main" {
		t.Fatalf("push branches = %v", push.Branches)
	}
	if len(push.Paths) != 1 || push.Paths[0] != "src/**" {
		t.Fatalf("push paths = %v", push.Paths)
	}
	if len(push.PathsIgnore) != 1 || push.PathsIgnore[0] != "docs/**" {
		t.Fatalf("push paths_ignore = %v", push.PathsIgnore)
	}
	if _, ok := spec.On["pull_request"]; !ok {
		t.Fatalf("missing pull_request trigger: %+v", spec.On)
	}
	if !hasUnsupported(res, "schedule") {
		t.Fatalf("schedule trigger not reported: %v", res.Unsupported)
	}

	// Top-level env.
	if spec.Env["GO_VERSION"] != "1.23" || spec.Env["CGO_ENABLED"] != "0" {
		t.Fatalf("env = %v", spec.Env)
	}

	// Jobs and needs.
	test := spec.Jobs["test"]
	if len(test.Needs) != 1 || test.Needs[0] != "lint" {
		t.Fatalf("test needs = %v", test.Needs)
	}
	if test.If != "success()" {
		t.Fatalf("test if = %q, want success()", test.If)
	}
	if cleanup := spec.Jobs["cleanup"]; cleanup.If != "failure()" {
		t.Fatalf("cleanup if = %q, want failure()", cleanup.If)
	}

	// Timeout (minutes) round-trips as a duration string.
	if test.Timeout.Duration.String() != "15m0s" || !test.Timeout.Set {
		t.Fatalf("test timeout = %v (set=%v)", test.Timeout.Duration, test.Timeout.Set)
	}

	// Job env and outputs.
	if test.Env["TEST_FLAGS"] != "-race" {
		t.Fatalf("test env = %v", test.Env)
	}
	if test.Outputs["artifact_name"] == "" {
		t.Fatalf("test outputs = %v", test.Outputs)
	}

	// Matrix: only cartesian dims; include is unsupported.
	if got := len(test.Matrix["go"]); got != 2 {
		t.Fatalf("matrix go = %v", test.Matrix["go"])
	}

	// Runner labels.
	lint := spec.Jobs["lint"]
	if len(lint.Runner) != 1 || lint.Runner[0] != "ubuntu-latest" {
		t.Fatalf("lint runner = %v", lint.Runner)
	}

	// Steps: checkout/setup-go are TODOs; run steps map with env,
	// continue-on-error, timeout, working-directory, if.
	steps := test.Steps
	if len(steps) == 0 {
		t.Fatalf("no steps emitted")
	}
	var build, testStep *pipeline.Step
	for i := range steps {
		if steps[i].Name == "build" {
			build = &steps[i]
		}
		if steps[i].Name == "test" {
			testStep = &steps[i]
		}
	}
	if build == nil || build.WorkingDirectory != "src" {
		t.Fatalf("build step = %+v", build)
	}
	if build.ContinueOnError {
		t.Fatalf("build continue_on_error = true, want false")
	}
	if testStep == nil || !testStep.ContinueOnError {
		t.Fatalf("test step continue_on_error missing: %+v", testStep)
	}
	if testStep.If != "always()" {
		t.Fatalf("test step if = %q, want always()", testStep.If)
	}
	if testStep.Timeout.Duration.String() != "5m0s" {
		t.Fatalf("test step timeout = %v", testStep.Timeout.Duration)
	}

	// The codecov action must be a disabled placeholder that never runs.
	for i := range steps {
		if steps[i].If == "false" && strings.Contains(steps[i].Run, "codecov") {
			return // found
		}
	}
	t.Fatalf("unknown action not emitted as disabled placeholder: %+v", steps)

	// Unsupported constructs must be reported, never approximated.
	for _, want := range []string{"concurrency", "permissions", "container", "service", "fail-fast", "include"} {
		if !hasUnsupported(res, want) {
			t.Fatalf("construct %q not reported as unsupported: %v", want, res.Unsupported)
		}
	}
	if !hasTODO(res, "checkout") || !hasTODO(res, "setup-go") {
		t.Fatalf("checkout/setup-go TODOs missing: %v", res.TODOs)
	}
}

func TestImportConditionVariants(t *testing.T) {
	cases := map[string]string{
		"${{ success() }}":                       "success()",
		"${{ failure() }}":                       "failure()",
		"${{ always() }}":                        "always()",
		"${{ cancelled() }}":                     "cancelled()",
		"${{ !cancelled() }}":                    "!cancelled()",
		"${{ success() || failure() }}":          "success() || failure()",
		"${{ github.ref == 'refs/heads/main' }}": "",
	}
	for in, want := range cases {
		got, ok := importer.MapCondition(in)
		if want == "" {
			if ok {
				t.Errorf("MapCondition(%q) = %q, want not mappable", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("MapCondition(%q) = %q (ok=%v), want %q", in, got, ok, want)
		}
	}
}

func TestImportEmptyWorkflow(t *testing.T) {
	res, err := New().Import("jobs: {}\n")
	if err != nil {
		t.Fatalf("import empty: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("expected a warning for missing jobs")
	}
}

func hasUnsupported(res *importer.Result, sub string) bool {
	return hasUnsupportedSlice(res.Unsupported, sub)
}

func hasUnsupportedSlice(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func hasTODO(res *importer.Result, sub string) bool {
	for _, s := range res.TODOs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
