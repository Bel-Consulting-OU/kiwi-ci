package githubactions

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestImportUnmappableTriggerGetsSentinel covers the !mapped fallback: a
// workflow whose only triggers have no Kiwi equivalent must not come out with
// an EMPTY on (which matches every webhook), but with a never-matching branch
// sentinel plus an explicit diagnosis and TODO.
func TestImportUnmappableTriggerGetsSentinel(t *testing.T) {
	res, err := New().Import("on: workflow_dispatch\n" + edgeJobs)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !hasUnsupported(res, "no workflow trigger could be mapped") {
		t.Fatalf("sentinel diagnosis missing: %v", res.Unsupported)
	}
	if !hasTODO(res, "placeholder trigger") {
		t.Fatalf("placeholder TODO missing: %v", res.TODOs)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v\n%s", err, res.PipelineYAML)
	}
	push, ok := spec.On["push"]
	if !ok || len(spec.On) != 1 {
		t.Fatalf("on = %+v, want only the sentinel push trigger", spec.On)
	}
	if len(push.Branches) != 1 || push.Branches[0] != "kiwi-import-unsupported-trigger" {
		t.Fatalf("sentinel trigger = %+v, want the never-matching branch", push)
	}
}

const edgeJobs = "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"

// TestImportDisablesUnresolvedExpressions covers both guard sites: a job env
// value and a step script carrying an expression context Kiwi does not resolve
// must disable (not silently run) the affected job/step.
func TestImportDisablesUnresolvedExpressions(t *testing.T) {
	jobEnv := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n      TOKEN: ${{ secrets.TOKEN }}\n    steps:\n      - run: echo hi\n"
	res, err := New().Import(jobEnv)
	if err != nil {
		t.Fatalf("import job env: %v", err)
	}
	if !hasUnsupported(res, "env \"TOKEN\" uses an expression context") {
		t.Fatalf("job env diagnosis missing: %v", res.Unsupported)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v", err)
	}
	if spec.Jobs["build"].If != "false" {
		t.Fatalf("job if = %q, want the disabled sentinel", spec.Jobs["build"].If)
	}

	stepRun := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ vars.CACHE_KEY }}\n"
	res, err = New().Import(stepRun)
	if err != nil {
		t.Fatalf("import step run: %v", err)
	}
	if !hasUnsupported(res, "script uses an expression context") {
		t.Fatalf("step run diagnosis missing: %v", res.Unsupported)
	}
	spec, err = pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v", err)
	}
	steps := spec.Jobs["build"].Steps
	if len(steps) != 1 || steps[0].If != "false" {
		t.Fatalf("step = %+v, want exactly one disabled step", steps)
	}

	// Plain values stay enabled: the guard is not a blanket disable.
	plain, err := New().Import("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env:\n      A: \"1\"\n    steps:\n      - run: echo ok\n")
	if err != nil {
		t.Fatalf("import plain: %v", err)
	}
	if hasUnsupported(plain, "expression context") {
		t.Fatalf("plain workflow flagged: %v", plain.Unsupported)
	}
}

// TestContainsUnresolvedExpression pins the three guarded contexts and the
// negative case directly.
func TestContainsUnresolvedExpression(t *testing.T) {
	for _, v := range []string{"${{ secrets.X }}", "${{ vars.X }}", "${{ env.X }}"} {
		if !containsUnresolvedExpression(v) {
			t.Errorf("containsUnresolvedExpression(%q) = false", v)
		}
	}
	for _, v := range []string{"", "echo $HOME", "${{ github.ref }}", "x${{ secrets }}"} {
		if containsUnresolvedExpression(v) {
			t.Errorf("containsUnresolvedExpression(%q) = true", v)
		}
	}
}

// TestImportSequenceNonScalarTriggerEntry covers the per-entry guard: a
// mapping inside the event sequence is reported and skipped while the scalar
// entries still map.
func TestImportSequenceNonScalarTriggerEntry(t *testing.T) {
	res, err := New().Import("on:\n  - push\n  - {schedule: cron}\n" + edgeJobs)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !hasUnsupported(res, "is not a scalar event name") {
		t.Fatalf("non-scalar entry not reported: %v", res.Unsupported)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v", err)
	}
	if _, ok := spec.On["push"]; !ok || len(spec.On) != 1 {
		t.Fatalf("on = %+v, want only push", spec.On)
	}
}

// TestImportAliasTriggerNodeHitsDefaultShape covers an aliased `on` value: the
// node kind is neither scalar, sequence nor mapping, so the import must report
// the unsupported shape and fall back to the sentinel instead of crashing or
// widening the trigger.
func TestImportAliasTriggerNodeHitsDefaultShape(t *testing.T) {
	src := "shared: &events [push]\non: *events\n" + edgeJobs
	res, err := New().Import(src)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !hasUnsupported(res, "must be an event name, a list of event names, or an event mapping") {
		t.Fatalf("shape diagnosis missing: %v", res.Unsupported)
	}
	if !hasUnsupported(res, "no workflow trigger could be mapped") {
		t.Fatalf("sentinel diagnosis missing: %v", res.Unsupported)
	}
	if _, err := pipeline.Parse([]byte(res.PipelineYAML)); err != nil {
		t.Fatalf("generated pipeline does not parse: %v\n%s", err, res.PipelineYAML)
	}
}

// TestImportMatrixUndecodableScalarDropsDimension covers the decode-error
// branch of convertStrategy: a scalar value that yaml cannot decode (invalid
// !!binary) makes the whole dimension unrepresentable, so it is dropped with
// the standard diagnosis rather than half-converted.
func TestImportMatrixUndecodableScalarDropsDimension(t *testing.T) {
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        go: [1.22, !!binary \"@@@\"]\n    steps:\n      - run: echo hi\n"
	res, err := New().Import(src)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !hasUnsupported(res, "matrix dimension \"go\" is not representable") {
		t.Fatalf("dimension diagnosis missing: %v", res.Unsupported)
	}
	if !hasUnsupportedSlice(res.Warnings, "matrix dimension \"go\" contains non-scalar values") {
		t.Fatalf("dimension warning missing: %v", res.Warnings)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v\n%s", err, res.PipelineYAML)
	}
	if dims := spec.Jobs["build"].Matrix; len(dims) != 0 {
		t.Fatalf("matrix = %v, want the undecodable dimension dropped", dims)
	}
	if strings.Contains(res.PipelineYAML, "@@@") {
		t.Fatalf("undecodable value leaked into the pipeline: %s", res.PipelineYAML)
	}
}
