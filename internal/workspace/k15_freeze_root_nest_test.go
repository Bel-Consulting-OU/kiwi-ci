package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// If Root is inside Source, freeze must not copy sibling workspace state
// (other run dirs / leftover job trees) into the run-base.
func TestFreezeDoesNotNestSiblingWorkspaces(t *testing.T) {
	src := t.TempDir()
	writeK15(t, filepath.Join(src, "app.txt"), "x")
	m := &Manager{Source: src, Root: filepath.Join(src, ".kiwi", "workspaces")}
	// Simulate another run's leftover job workspace under the same Root.
	junk := filepath.Join(m.Root, "run-OTHER", "leftover-job")
	if err := os.MkdirAll(junk, 0o755); err != nil {
		t.Fatal(err)
	}
	writeK15(t, filepath.Join(junk, "STALE.txt"), "should-not-be-in-base")
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.BasePath(), "app.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.BasePath(), ".kiwi", "workspaces", "run-OTHER", "leftover-job", "STALE.txt")); err == nil {
		t.Fatal("run-base nested sibling workspaces from Root-inside-Source")
	}
	// Broader: no STALE.txt anywhere under base
	var found bool
	_ = filepath.Walk(m.BasePath(), func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.Name() == "STALE.txt" {
			found = true
		}
		return nil
	})
	if found {
		t.Fatal("STALE.txt leaked into run-base")
	}
}
