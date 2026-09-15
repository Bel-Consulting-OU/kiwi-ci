package executor

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// TestSecretCopiedIntoStepOutputFailsTaintCheck drives a job whose step
// copies a registered secret value into its KIWI_OUTPUT file and whose job
// outputs interpolate that step output. The taint gate must fail the job
// with a clear error and persist NO outputs: secret values never leave the
// executor in JobResult.Outputs.
func TestSecretCopiedIntoStepOutputFailsTaintCheck(t *testing.T) {
	const value = "super-secret-token-9f8a"
	ws := t.TempDir()
	provider := secrets.MapProvider{"token": value}
	// The step writes TOKEN=<secret value> into the output file with the
	// native shell: POSIX on Unix, PowerShell on Windows.
	script := nativeScript(
		`echo "TOKEN=$KIWI_SECRET_TOKEN" > "$KIWI_OUTPUT"`,
		`"TOKEN=$env:KIWI_SECRET_TOKEN" | Out-File -Encoding utf8 $env:KIWI_OUTPUT`,
	)
	s, err := pipeline.Parse([]byte(`version: 1
secrets: [token]
jobs:
  probe:
    outputs:
      token: ${{ steps.out.outputs.TOKEN }}
    steps:
      - id: out
        run: ` + script + `
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{Workspace: ws, SecretProvider: provider}}
	res, err := ex.Run(context.Background(), g)
	if err == nil {
		t.Fatal("expected job failure")
	}
	r := res["probe"]
	if r.Status != model.StatusFailure {
		t.Fatalf("status = %s (%s), want failure", r.Status, r.Error)
	}
	if !strings.Contains(r.Error, "registered secret") {
		t.Fatalf("error = %q, want taint error", r.Error)
	}
	if len(r.Outputs) != 0 {
		t.Fatalf("outputs = %v, want empty (tainted outputs must never persist)", r.Outputs)
	}
	// The taint error must name the offending output without embedding the
	// secret value itself.
	if strings.Contains(r.Error, value) {
		t.Fatalf("secret value leaked into the job error: %q", r.Error)
	}
}

// TestSecretMaskerCapacityOverflowFailsJob bypasses pipeline admission
// (which caps declared secret names at secrets.MaxSecretNames) by feeding a
// hand-built compiled job with 129 job-level secrets directly to
// RunCompiledJob. The masker's strict registration must fail the job closed
// once its capacity is exhausted: an unmaskable secret set must never run.
func TestSecretMaskerCapacityOverflowFailsJob(t *testing.T) {
	ws := t.TempDir()
	provider := secrets.MapProvider{}
	names := make([]string, 0, secrets.MaxSecretNames+1)
	for i := 0; i < secrets.MaxSecretNames+1; i++ {
		name := fmt.Sprintf("secret-%03d", i)
		names = append(names, name)
		provider[name] = fmt.Sprintf("value-%03d", i)
	}
	spec := &pipeline.Spec{
		Version: 1,
		Secrets: names,
	}
	cj := pipeline.CompiledJob{
		ID: "probe", BaseID: "probe",
		Job: pipeline.Job{Steps: []pipeline.Step{{ID: "s", Run: "echo hi"}}},
	}
	ex := Executor{Opt: Options{Workspace: ws, SecretProvider: provider}}
	res := ex.RunCompiledJob(context.Background(), spec, cj)
	if res.Status != model.StatusFailure {
		t.Fatalf("status = %s (%s), want failure", res.Status, res.Error)
	}
	if !strings.Contains(res.Error, "cannot be masked") || !strings.Contains(res.Error, "refusing to run") {
		t.Fatalf("error = %q, want strict masking refusal", res.Error)
	}
	if !strings.Contains(res.Error, "capacity") {
		t.Fatalf("error = %q, want capacity cause", res.Error)
	}
	if len(res.Outputs) != 0 {
		t.Fatalf("outputs = %v, want empty", res.Outputs)
	}
}

// TestStepSecretMaskStrictnessFailsStep verifies a step-level secret whose
// value the masker refuses (capacity exhausted by the job-level secrets)
// fails the job instead of silently running unmasked.
func TestStepSecretMaskStrictnessFailsStep(t *testing.T) {
	ws := t.TempDir()
	provider := secrets.MapProvider{}
	names := make([]string, 0, secrets.MaxSecretNames+1)
	for i := 0; i < secrets.MaxSecretNames+1; i++ {
		name := fmt.Sprintf("secret-%03d", i)
		names = append(names, name)
		provider[name] = fmt.Sprintf("value-%03d", i)
	}
	spec := &pipeline.Spec{
		Version: 1,
		Secrets: names[:secrets.MaxSecretNames],
	}
	cj := pipeline.CompiledJob{
		ID: "probe", BaseID: "probe",
		Job: pipeline.Job{
			Steps: []pipeline.Step{{
				ID:      "s",
				Run:     "echo hi",
				Secrets: []string{names[secrets.MaxSecretNames]},
			}},
		},
	}
	ex := Executor{Opt: Options{Workspace: ws, SecretProvider: provider}}
	res := ex.RunCompiledJob(context.Background(), spec, cj)
	if res.Status != model.StatusFailure {
		t.Fatalf("status = %s (%s), want failure", res.Status, res.Error)
	}
	if !strings.Contains(res.Error, "cannot be masked") {
		t.Fatalf("error = %q, want strict masking refusal", res.Error)
	}
}
