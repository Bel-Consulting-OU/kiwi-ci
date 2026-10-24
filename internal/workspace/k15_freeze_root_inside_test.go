package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// When the manager Root lives inside Source (TMPDIR=project, HOME=project),
// creating run-base under Root must not make freeze's A/B manifests differ.
func TestFreezeRootInsideSource(t *testing.T) {
	src := t.TempDir()
	writeK15(t, filepath.Join(src, "app.txt"), "x")
	writeK15(t, filepath.Join(src, "services", "m", "001.sql"), "s")
	m := &Manager{Source: src, Root: filepath.Join(src, ".kiwi", "workspaces")}
	if err := os.MkdirAll(m.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatalf("freeze with Root inside Source: %v", err)
	}
	dir, cleanup, err := m.Prepare(context.Background(), "j")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(dir, "app.txt")); err != nil {
		t.Fatal(err)
	}
}
