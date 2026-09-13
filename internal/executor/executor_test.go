package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kiwici/kiwi/internal/pipeline"
)

func TestDAGAndRetry(t *testing.T) {
	ws := t.TempDir()
	s, err := pipeline.Parse([]byte(`version: 1
defaults:
  retry:
    max: 1
    on: [failure]
jobs:
  first:
    steps:
      - run: |
          if [ ! -f marker ]; then touch marker; exit 1; fi
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
