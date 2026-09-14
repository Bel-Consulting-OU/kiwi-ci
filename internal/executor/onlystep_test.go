package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

func TestOnlyStepRunsExactlyOneStep(t *testing.T) {
	ws := t.TempDir()
	spec, err := pipeline.Parse([]byte(`version: 1
jobs:
  build:
    steps:
      - id: one
        run: echo one > one.txt
      - id: two
        run: echo two > two.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var cj pipeline.CompiledJob
	for _, c := range g.Jobs {
		cj = c
	}
	e := &Executor{Opt: Options{Workspace: ws, OnlyStep: "one", Logs: logging.Func(func(_, _, _ string) {})}, Masker: &secrets.Masker{}}
	res := e.RunCompiledJob(context.Background(), g.Spec, cj)
	if res.Status != model.StatusSuccess {
		t.Fatalf("status = %s: %s", res.Status, res.Error)
	}
	if _, err := os.Stat(filepath.Join(ws, "one.txt")); err != nil {
		t.Fatal("selected step did not run")
	}
	if _, err := os.Stat(filepath.Join(ws, "two.txt")); !os.IsNotExist(err) {
		t.Fatal("non-selected step ran")
	}
}

func TestOnlyStepUnknownIDFails(t *testing.T) {
	ws := t.TempDir()
	spec, err := pipeline.Parse([]byte(`version: 1
jobs:
  build:
    steps:
      - id: one
        run: echo ok > out.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var cj pipeline.CompiledJob
	for _, c := range g.Jobs {
		cj = c
	}
	e := &Executor{Opt: Options{Workspace: ws, OnlyStep: "nonexistent", Logs: logging.Func(func(_, _, _ string) {})}, Masker: &secrets.Masker{}}
	res := e.RunCompiledJob(context.Background(), g.Spec, cj)
	if res.Status != model.StatusFailure {
		t.Fatalf("status = %s, want failure for unknown step", res.Status)
	}
}
