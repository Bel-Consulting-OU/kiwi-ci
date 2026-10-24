package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/workspace"
)

// After freeze, the live pipeline file may disappear (editor, branch switch);
// RunLocal must load the frozen copy under the run-base.
func TestRunLocalUsesFrozenPipelineIfLiveRemoved(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, ".kiwi", "pipeline.yaml")
	body := "version: 1\njobs:\n  hello:\n    steps:\n      - run: echo frozen_ok\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	wm, err := workspace.NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()
	if err := wm.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	frozen := filepath.Join(wm.BasePath(), ".kiwi", "pipeline.yaml")
	if _, err := os.Stat(frozen); err != nil {
		t.Fatalf("frozen pipeline missing: %v", err)
	}
	if _, err := pipeline.Load(frozen); err != nil {
		t.Fatalf("load frozen pipeline: %v", err)
	}
	// Live file gone as intended.
	if _, err := os.Stat(p); err == nil {
		t.Fatal("live pipeline still present")
	}
}
