package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestToolFingerprintGate: tools: is checked before step 1; a missing or
// wrong-version tool fails the job closed.
func TestToolFingerprintGate(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "faketool")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho 'faketool 1.2.3'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	// matching version
	g := envProbeSpec(nativeScript("          echo ok\n", "          echo ok\n"))
	{
		cj := g.Jobs["probe"]
		cj.Job.Tools = []string{"faketool=1.2"}
		g.Jobs["probe"] = cj
	}
	ex := Executor{Opt: Options{Workspace: t.TempDir()}}
	res, err := ex.Run(t.Context(), g)
	if err != nil {
		t.Fatal(err)
	}
	if res["probe"].Status != model.StatusSuccess {
		t.Fatalf("matching tools: %v", res["probe"].Error)
	}

	// wrong version
	g2 := envProbeSpec(nativeScript("          echo ok\n", "          echo ok\n"))
	{
		cj := g2.Jobs["probe"]
		cj.Job.Tools = []string{"faketool=9.9"}
		g2.Jobs["probe"] = cj
	}
	ex2 := Executor{Opt: Options{Workspace: t.TempDir()}}
	// A tools-gate failure surfaces as a failed job (Run error and/or
	// result status). Either is fail-closed.
	res2, _ := ex2.Run(t.Context(), g2)
	if res2["probe"].Status != model.StatusFailure {
		t.Fatalf("wrong tool version must fail closed: %+v", res2["probe"])
	}
	if !strings.Contains(res2["probe"].Error, "does not match") {
		t.Fatalf("error = %q", res2["probe"].Error)
	}

	// missing tool
	g3 := envProbeSpec(nativeScript("          echo ok\n", "          echo ok\n"))
	{
		cj := g3.Jobs["probe"]
		cj.Job.Tools = []string{"no-such-tool=1"}
		g3.Jobs["probe"] = cj
	}
	ex3 := Executor{Opt: Options{Workspace: t.TempDir()}}
	res3, _ := ex3.Run(t.Context(), g3)
	if res3["probe"].Status != model.StatusFailure {
		t.Fatal("missing tool must fail closed")
	}
	if !strings.Contains(res3["probe"].Error, "not on PATH") {
		t.Fatalf("error = %q", res3["probe"].Error)
	}
}

// TestJobToolsParses: tools: survives schema validation and parse.
func TestJobToolsParses(t *testing.T) {
	const src = `version: 1
jobs:
  t:
    image: alpine
    tools: ["docker=29", "psql=17"]
    steps:
      - run: echo hi
`
	spec, err := pipeline.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(spec.Jobs["t"].Tools) != 2 {
		t.Fatalf("tools = %v", spec.Jobs["t"].Tools)
	}
}
