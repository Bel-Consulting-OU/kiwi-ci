package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLockRootFollowsFrozenPipelinePath(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(base, ".kiwi", "pipeline.yaml")
	if err := os.WriteFile(p, []byte("version: 1\njobs:\n  a:\n    steps: [{run: \"true\"}]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := lockRootFor(p)
	if filepath.Base(root) != filepath.Base(base) {
		// root should be the frozen base directory itself
		if root != base {
			t.Fatalf("lockRootFor(frozen) = %q, want %q", root, base)
		}
	}
	if root != base {
		t.Fatalf("lockRootFor(frozen pipeline) = %q, want %q", root, base)
	}
}
