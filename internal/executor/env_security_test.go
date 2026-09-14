package executor

import (
	"context"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

func envProbeSpec(script string) *pipeline.Graph {
	s, err := pipeline.Parse([]byte("version: 1\njobs:\n  probe:\n    steps:\n      - run: |\n" + script))
	if err != nil {
		panic(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		panic(err)
	}
	return g
}

// The env probes below run through the native backend's real shell, so each
// fixture carries both syntaxes: POSIX for Unix hosts, PowerShell for
// Windows hosts (the native default shell).

const cleanEnvProbePOSIX = `          [ -z "$KIWI_SENTINEL_LEAK" ] || { echo "host env leaked"; exit 1; }
          [ "$KIWI_PASS_SENTINEL" = "allowlisted" ] || { echo "PassEnv missing"; exit 1; }
          [ "$CI" = "true" ] || { echo "CI missing"; exit 1; }
          [ "$KIWI" = "true" ] || { echo "KIWI missing"; exit 1; }
          [ -n "$PATH" ] || { echo "PATH missing"; exit 1; }
          [ -z "$KIWI_SENTINEL_OTHER" ] || { echo "unlisted var leaked"; exit 1; }
`

const cleanEnvProbeWindows = `          if ($env:KIWI_SENTINEL_LEAK) { "host env leaked"; exit 1 }
          if ($env:KIWI_PASS_SENTINEL -ne "allowlisted") { "PassEnv missing"; exit 1 }
          if ($env:CI -ne "true") { "CI missing"; exit 1 }
          if ($env:KIWI -ne "true") { "KIWI missing"; exit 1 }
          if (-not $env:PATH) { "PATH missing"; exit 1 }
          if ($env:KIWI_SENTINEL_OTHER) { "unlisted var leaked"; exit 1 }
`

func TestCleanEnvNoHostSecrets(t *testing.T) {
	t.Setenv("KIWI_SENTINEL_LEAK", "do-not-leak")
	t.Setenv("KIWI_PASS_SENTINEL", "allowlisted")
	g := envProbeSpec(nativeScript(cleanEnvProbePOSIX, cleanEnvProbeWindows))
	t.Setenv("KIWI_SENTINEL_OTHER", "also-secret")
	ex := Executor{Opt: Options{Workspace: t.TempDir(), PassEnv: []string{"KIWI_PASS_SENTINEL"}}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if r := res["probe"]; r.Status != model.StatusSuccess {
		t.Fatalf("job failed: %v", r.Error)
	}
}

const inheritEnvProbePOSIX = `          [ "$KIWI_SENTINEL_LEAK" = "present" ] || { echo "sentinel missing"; exit 1; }
          [ "$KIWI" = "true" ] || { echo "KIWI missing"; exit 1; }
`

const inheritEnvProbeWindows = `          if ($env:KIWI_SENTINEL_LEAK -ne "present") { "sentinel missing"; exit 1 }
          if ($env:KIWI -ne "true") { "KIWI missing"; exit 1 }
`

func TestInheritEnvOptIn(t *testing.T) {
	t.Setenv("KIWI_SENTINEL_LEAK", "present")
	g := envProbeSpec(nativeScript(inheritEnvProbePOSIX, inheritEnvProbeWindows))
	ex := Executor{Opt: Options{Workspace: t.TempDir(), InheritEnv: true}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if r := res["probe"]; r.Status != model.StatusSuccess {
		t.Fatalf("job failed: %v", r.Error)
	}
}

func TestStepSecretScoping(t *testing.T) {
	provider := secrets.MapProvider{
		"job-secret": "jobs",
		"step-one":   "one",
		"step-two":   "two",
	}
	stepA := nativeScript(
		`          [ "$KIWI_SECRET_JOB_SECRET" = "jobs" ] || { echo "job secret missing in step a"; exit 1; }
          [ "$KIWI_SECRET_STEP_ONE" = "one" ] || { echo "step-one secret missing"; exit 1; }
          [ -z "$KIWI_SECRET_STEP_TWO" ] || { echo "step-two secret leaked into step a"; exit 1; }
`,
		`          if ($env:KIWI_SECRET_JOB_SECRET -ne "jobs") { "job secret missing in step a"; exit 1 }
          if ($env:KIWI_SECRET_STEP_ONE -ne "one") { "step-one secret missing"; exit 1 }
          if ($env:KIWI_SECRET_STEP_TWO) { "step-two secret leaked into step a"; exit 1 }
`)
	stepB := nativeScript(
		`          [ "$KIWI_SECRET_JOB_SECRET" = "jobs" ] || { echo "job secret missing in step b"; exit 1; }
          [ "$KIWI_SECRET_STEP_TWO" = "two" ] || { echo "step-two secret missing"; exit 1; }
          [ -z "$KIWI_SECRET_STEP_ONE" ] || { echo "step-one secret leaked into step b"; exit 1; }
`,
		`          if ($env:KIWI_SECRET_JOB_SECRET -ne "jobs") { "job secret missing in step b"; exit 1 }
          if ($env:KIWI_SECRET_STEP_TWO -ne "two") { "step-two secret missing"; exit 1 }
          if ($env:KIWI_SECRET_STEP_ONE) { "step-one secret leaked into step b"; exit 1 }
`)
	s, err := pipeline.Parse([]byte(`version: 1
secrets: [job-secret]
jobs:
  probe:
    steps:
      - id: a
        secrets: [step-one]
        run: |
` + stepA + `      - id: b
        secrets: [step-two]
        run: |
` + stepB))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{Workspace: t.TempDir(), SecretProvider: provider}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if r := res["probe"]; r.Status != model.StatusSuccess {
		t.Fatalf("job failed: %v", r.Error)
	}
}
