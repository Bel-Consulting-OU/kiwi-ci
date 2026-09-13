package executor

import (
	"context"
	"testing"

	"github.com/kiwici/kiwi/internal/model"
	"github.com/kiwici/kiwi/internal/pipeline"
	"github.com/kiwici/kiwi/internal/secrets"
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

func TestCleanEnvNoHostSecrets(t *testing.T) {
	t.Setenv("KIWI_SENTINEL_LEAK", "do-not-leak")
	t.Setenv("KIWI_PASS_SENTINEL", "allowlisted")
	g := envProbeSpec(`          [ -z "$KIWI_SENTINEL_LEAK" ] || { echo "host env leaked"; exit 1; }
          [ "$KIWI_PASS_SENTINEL" = "allowlisted" ] || { echo "PassEnv missing"; exit 1; }
          [ "$CI" = "true" ] || { echo "CI missing"; exit 1; }
          [ "$KIWI" = "true" ] || { echo "KIWI missing"; exit 1; }
          [ -n "$PATH" ] || { echo "PATH missing"; exit 1; }
          [ -z "$KIWI_SENTINEL_OTHER" ] || { echo "unlisted var leaked"; exit 1; }
`)
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

func TestInheritEnvOptIn(t *testing.T) {
	t.Setenv("KIWI_SENTINEL_LEAK", "present")
	g := envProbeSpec(`          [ "$KIWI_SENTINEL_LEAK" = "present" ] || { echo "sentinel missing"; exit 1; }
          [ "$KIWI" = "true" ] || { echo "KIWI missing"; exit 1; }
`)
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
	s, err := pipeline.Parse([]byte(`version: 1
secrets: [job-secret]
jobs:
  probe:
    steps:
      - id: a
        secrets: [step-one]
        run: |
          [ "$KIWI_SECRET_JOB_SECRET" = "jobs" ] || { echo "job secret missing in step a"; exit 1; }
          [ "$KIWI_SECRET_STEP_ONE" = "one" ] || { echo "step-one secret missing"; exit 1; }
          [ -z "$KIWI_SECRET_STEP_TWO" ] || { echo "step-two secret leaked into step a"; exit 1; }
      - id: b
        secrets: [step-two]
        run: |
          [ "$KIWI_SECRET_JOB_SECRET" = "jobs" ] || { echo "job secret missing in step b"; exit 1; }
          [ "$KIWI_SECRET_STEP_TWO" = "two" ] || { echo "step-two secret missing"; exit 1; }
          [ -z "$KIWI_SECRET_STEP_ONE" ] || { echo "step-one secret leaked into step b"; exit 1; }
`))
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
