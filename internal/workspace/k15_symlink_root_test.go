package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// K15: staging a symlinked source directory must copy the tree, not a
// zero-file "success". macOS /tmp is a symlink; a real /tmp cwd must
// produce a non-empty workspace.
func TestPrepareSymlinkedSourceStagesFiles(t *testing.T) {
	base := t.TempDir() // real dir
	if err := os.WriteFile(filepath.Join(base, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "services", "migrations"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "services", "migrations", "1.sql"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Symlink to the real tree
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(base, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	m, err := NewManager(link)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if m.Source == link {
		t.Fatalf("Source was not resolved: %q", m.Source)
	}
	dir, cleanup, err := m.Prepare(context.Background(), "job")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(dir, "a.txt")); err != nil {
		t.Fatalf("missing a.txt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "services", "migrations", "1.sql")); err != nil {
		t.Fatalf("missing migrations: %v", err)
	}
}
