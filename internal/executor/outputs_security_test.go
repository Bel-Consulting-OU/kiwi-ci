package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kiwici/kiwi/internal/model"
	"github.com/kiwici/kiwi/internal/pipeline"
)

// TestReadFileNoFollowDirect verifies the native ReadFile refuses a symlink
// instead of silently reading the link target.
func TestReadFileNoFollowDirect(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(target, []byte("KEY=stolen\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	nb := &NativeBackend{}
	if _, err := nb.ReadFile(context.Background(), link, 1<<20); err == nil {
		t.Fatal("ReadFile followed a symlink")
	}
}

// TestStepOutputSymlinkRejected plants a symlink at .kiwi-output-1 that points
// outside the workspace. The step output read must fail rather than follow the
// symlink and leak the outside file into job outputs.
func TestStepOutputSymlinkRejected(t *testing.T) {
	ws := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("KEY=stolen\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  attack:
    env:
      OUTSIDE_TARGET: ` + outside + `
    steps:
      - id: out
        run: ln -s "$OUTSIDE_TARGET" .kiwi-output-1
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{Workspace: ws}}
	res, err := ex.Run(context.Background(), g)
	if err == nil {
		t.Fatal("expected job failure")
	}
	if r := res["attack"]; r.Status != model.StatusFailure || !strings.Contains(r.Error, "step outputs") {
		t.Fatalf("expected step outputs failure, got status=%v error=%v", r.Status, r.Error)
	}
	// The outside file must not have been surfaced as an output.
	if outs := res["attack"].Outputs; len(outs) > 0 {
		if _, ok := outs["KEY"]; ok {
			t.Fatal("symlink target content leaked into job outputs")
		}
	}
}

// TestOutputFileTooLarge verifies an oversized output file is rejected by the
// ReadFile cap instead of being buffered and parsed.
func TestOutputFileTooLarge(t *testing.T) {
	ws := t.TempDir()
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  big:
    steps:
      - id: out
        run: dd if=/dev/zero of=.kiwi-output-1 bs=1048577 count=1 2>/dev/null
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{Workspace: ws}}
	res, err := ex.Run(context.Background(), g)
	if err == nil {
		t.Fatal("expected job failure")
	}
	if r := res["big"]; r.Status != model.StatusFailure || !strings.Contains(r.Error, "step outputs") {
		t.Fatalf("expected step outputs failure, got status=%v error=%v", r.Status, r.Error)
	}
}
