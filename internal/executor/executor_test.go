package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestDAGAndRetry(t *testing.T) {
	ws := t.TempDir()
	// The first step fails while the marker is absent and succeeds on
	// retry once it has created it. The shell syntax is per-host: POSIX on
	// Unix, PowerShell on Windows (the native default shell).
	first := nativeScript(
		`if [ ! -f marker ]; then touch marker; exit 1; fi`,
		`if (-not (Test-Path marker)) { Set-Content marker x; exit 1 }`,
	)
	s, err := pipeline.Parse([]byte(`version: 1
defaults:
  retry:
    max: 1
    on: [failure]
jobs:
  first:
    steps:
      - run: |
          ` + first + `
  second:
    needs: [first]
    steps:
      - run: echo ok > result.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 2}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if res["first"].Attempts != 2 {
		t.Fatalf("expected retry, got %d attempts", res["first"].Attempts)
	}
	if _, err := os.Stat(filepath.Join(ws, "result.txt")); err != nil {
		t.Fatal("dependent job did not run")
	}
}
