package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// cancel_job_on_failure (Woodpecker failure: cancel) stops the job at the
// failing step — later always()/failure() steps must NOT run.

func TestCancelJobOnFailureStopsRemainingSteps(t *testing.T) {
	ws := t.TempDir()
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  build:
    steps:
      - name: boom
        run: exit 1
        cancel_job_on_failure: true
      - name: later
        run: touch later.txt
        if: always()
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if res["build"].Status != "cancelled" {
		t.Fatalf("status = %q, want cancelled", res["build"].Status)
	}
	if _, err := os.Stat(filepath.Join(ws, "later.txt")); err == nil {
		t.Fatal("later step ran after cancel_job_on_failure")
	}
}

func TestContinueOnErrorAndCancelAreExclusive(t *testing.T) {
	_, err := pipeline.Parse([]byte(`version: 1
jobs:
  build:
    steps:
      - run: exit 1
        continue_on_error: true
        cancel_job_on_failure: true
`))
	if err == nil {
		// Parse may succeed; Validate must refuse.
		s, _ := pipeline.Parse([]byte(`version: 1
jobs:
  build:
    steps:
      - run: exit 1
        continue_on_error: true
        cancel_job_on_failure: true
`))
		if err := pipeline.Validate(s); err == nil {
			t.Fatal("continue_on_error + cancel_job_on_failure must be refused")
		}
	}
}

// background (Woodpecker detach) starts the step and does not wait; the job
// continues to the next step immediately.
func TestBackgroundStepDoesNotBlock(t *testing.T) {
	ws := t.TempDir()
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  build:
    steps:
      - name: bg
        run: sleep 30
        background: true
      - name: after
        run: touch after.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if res["build"].Status != "success" {
		t.Fatalf("status = %+v", res["build"])
	}
	if _, err := os.Stat(filepath.Join(ws, "after.txt")); err != nil {
		t.Fatalf("step after background did not run: %v", err)
	}
}

// Registry credentials resolve through the secret provider into a
// job-scoped DOCKER_CONFIG — never the runner's ~/.docker.
func TestProvisionRegistryAuthWritesScopedConfig(t *testing.T) {
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  build:
    runtime: container
    image: private.example.com/app:1
    registries:
      - host: private.example.com
        username_secret: reg_user
        password_secret: reg_pass
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{
		SecretProvider: mapSecrets{"reg_user": "alice", "reg_pass": "s3cret"},
	}}
	dir, cleanup, err := ex.provisionRegistryAuth(context.Background(), g.Jobs["build"])
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "private.example.com") || !strings.Contains(string(raw), "YWxpY2U6czNjcmV0") {
		t.Fatalf("config.json = %s", raw)
	}
	// Missing secret fails closed.
	ex2 := Executor{Opt: Options{SecretProvider: mapSecrets{}}}
	if _, _, err := ex2.provisionRegistryAuth(context.Background(), g.Jobs["build"]); err == nil {
		t.Fatal("unresolved registry secret must fail closed")
	}
}

type mapSecrets map[string]string

func (m mapSecrets) Get(_ context.Context, name string) (string, error) {
	if v, ok := m[name]; ok {
		return v, nil
	}
	return "", os.ErrNotExist
}
