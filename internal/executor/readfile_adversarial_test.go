package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestGeneratePathIntermediateSymlinkNeverLeaks plants a symlinked directory
// in the workspace and points generate.path through it at a host file. The
// root-anchored native read must reject the symlink component and the host
// content must never reach the upload hook.
func TestGeneratePathIntermediateSymlinkNeverLeaks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	ws := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "fragment.json"), []byte(`{"jobs":{"leak":{"steps":[{"run":"echo leaked"}]}},"deps":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	spec, err := pipeline.Parse([]byte(`version: 1
jobs:
  gen:
    generate:
      path: link/fragment.json
    steps:
      - run: echo ok
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
	uploads := 0
	ex := Executor{Opt: Options{
		Workspace: ws, MaxParallel: 1,
		GenerateUpload: func(jobID, path string, data []byte) error {
			uploads++
			t.Errorf("host content uploaded through symlink: job=%s path=%s data=%q", jobID, path, data)
			return nil
		},
	}}
	res := ex.RunCompiledJob(context.Background(), &pipeline.Spec{Version: 1}, cj)
	if res.Status != model.StatusFailure {
		t.Fatalf("status = %s, want failure (error: %s)", res.Status, res.Error)
	}
	if uploads != 0 {
		t.Fatalf("GenerateUpload called %d times for a rejected fragment", uploads)
	}
	if !strings.Contains(res.Error, "generate.path") {
		t.Fatalf("error = %q, want it to mention generate.path", res.Error)
	}
}

// TestStepOutputIntermediateSymlinkRepointerRejected swaps a working
// directory for a symlink after the step wrote its output file. The
// root-anchored read must fail instead of following the re-pointed path and
// leaking the outside file into job outputs.
func TestStepOutputIntermediateSymlinkRepointerRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink swap needs unix semantics")
	}
	ws := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, ".kiwi-output-1"), []byte("KEY=stolen\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := pipeline.Parse([]byte(`version: 1
jobs:
  attack:
    env:
      OUTSIDE: ` + outside + `
    steps:
      - id: out
        working_directory: sub
        run: |
          echo 'KEY=good' > .kiwi-output-1
          cd ..
          mv sub sub.real
          ln -s "$OUTSIDE" sub
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1}}
	res, err := ex.Run(context.Background(), g)
	if err == nil {
		t.Fatal("expected job failure")
	}
	r := res["attack"]
	if r.Status != model.StatusFailure || !strings.Contains(r.Error, "step outputs") {
		t.Fatalf("expected step outputs failure, got status=%v error=%v", r.Status, r.Error)
	}
	if _, ok := r.Outputs["KEY"]; ok {
		t.Fatal("symlink target content leaked into job outputs")
	}
}

// TestReadFileWithinRootMissingFileAndParent verifies missing files and
// missing parents surface as os.ErrNotExist so "step wrote no outputs" keeps
// working, and that a path outside the root is rejected.
func TestReadFileWithinRootMissingFileAndParent(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "present"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileWithinRoot(ws, filepath.Join(ws, "present"), 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileWithinRoot(ws, filepath.Join(ws, "missing"), 1<<20); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: want os.ErrNotExist, got %v", err)
	}
	if _, err := readFileWithinRoot(ws, filepath.Join(ws, "gone", "file"), 1<<20); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing parent: want os.ErrNotExist, got %v", err)
	}
	outside := t.TempDir()
	if _, err := readFileWithinRoot(ws, filepath.Join(outside, "secret"), 1<<20); err == nil {
		t.Fatal("path outside the root must be rejected")
	}
}

// TestReadFileWithinRootRespectsCap verifies the read cap is still enforced
// through the root-anchored path.
func TestReadFileWithinRootRespectsCap(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "big"), []byte(strings.Repeat("x", 1024)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileWithinRoot(ws, filepath.Join(ws, "big"), 16); err == nil {
		t.Fatal("oversized read must be rejected")
	}
}
