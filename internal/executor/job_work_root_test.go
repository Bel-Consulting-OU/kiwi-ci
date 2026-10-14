package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Job work root (workspace.base/path): steps with no working_directory and
// relative cache/artifact paths resolve under the declared base, matching
// Woodpecker workspace semantics. The runner-owned workspace root stays the
// quota and bind-mount root.

func TestJobWorkRootHonorsWorkspaceBasePath(t *testing.T) {
	ws := t.TempDir()
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  build:
    workspace:
      base: repo
      path: src
    steps:
      - run: echo hi > out.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{Workspace: filepath.Join(ws, "ws"), MaxParallel: 1}}
	if err := os.MkdirAll(filepath.Join(ws, "ws"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if res["build"].Status != "success" {
		t.Fatalf("status = %+v", res["build"])
	}
	// The step must have written under base/path, not the workspace root.
	if _, err := os.Stat(filepath.Join(ws, "ws", "repo", "src", "out.txt")); err != nil {
		t.Fatalf("step did not run in workspace.base/path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ws, "ws", "out.txt")); err == nil {
		t.Fatal("step wrote at workspace root; workspace.base/path ignored")
	}
}

func TestJobWorkRootDefaultIsWorkspaceRoot(t *testing.T) {
	ws := t.TempDir()
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  build:
    steps:
      - run: echo hi > out.txt
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
	if _, err := os.Stat(filepath.Join(ws, "out.txt")); err != nil {
		t.Fatalf("default work root must be the workspace root: %v", err)
	}
}

func TestJobWorkRootRejectsEscape(t *testing.T) {
	if _, err := jobWorkRoot("/ws", pipeline.Workspace{Base: ".."}); err == nil {
		t.Fatal("workspace.base=.. must be refused")
	}
	if _, err := jobWorkRoot("/ws", pipeline.Workspace{Path: "../x"}); err == nil {
		t.Fatal("workspace.path=../x must be refused")
	}
	got, err := jobWorkRoot("/ws", pipeline.Workspace{Base: "repo", Path: "src"})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.ToSlash(got) != "/ws/repo/src" {
		t.Fatalf("jobWorkRoot = %q", got)
	}
	if workSubdirRel(pipeline.Workspace{Base: "repo", Path: "src"}) != "repo/src" {
		t.Fatal("workSubdirRel")
	}
	if workSubdirRel(pipeline.Workspace{}) != "" {
		t.Fatal("empty workspace must map to empty subdir")
	}
}
