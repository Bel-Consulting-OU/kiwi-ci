package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFreezeIncludesRootFiles(t *testing.T) {
	src := t.TempDir()
	writeK15(t, filepath.Join(src, "a.txt"), "a")
	writeK15(t, filepath.Join(src, "untracked.tmp"), "u")
	writeK15(t, filepath.Join(src, "services", "m", "001.sql"), "s")
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	base := m.BasePath()
	if base == "" {
		t.Fatal("no base")
	}
	for _, rel := range []string{"a.txt", "untracked.tmp", filepath.Join("services", "m", "001.sql")} {
		if _, err := os.Stat(filepath.Join(base, rel)); err != nil {
			t.Fatalf("base missing %s: %v", rel, err)
		}
	}
	dir, cleanup, err := m.Prepare(context.Background(), "j")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(dir, "untracked.tmp")); err != nil {
		t.Fatalf("job missing untracked.tmp: %v", err)
	}
}
