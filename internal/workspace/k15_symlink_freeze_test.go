package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Absolute symlink into another live file must not remain a live pointer
// after freeze: bytes are snapshotted so jobs cannot see later edits.
func TestFreezeSnapshotsExternalFileSymlink(t *testing.T) {
	src := t.TempDir()
	ext := t.TempDir()
	if err := os.WriteFile(filepath.Join(ext, "secret.json"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ext, "secret.json"), filepath.Join(src, "cfg.json")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	writeK15(t, filepath.Join(src, "a.txt"), "a")
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Mutate external after freeze
	if err := os.WriteFile(filepath.Join(ext, "secret.json"), []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir, cleanup, err := m.Prepare(context.Background(), "j")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	b, err := os.ReadFile(filepath.Join(dir, "cfg.json"))
	if err != nil {
		t.Fatalf("cfg.json: %v", err)
	}
	if string(b) != "v1" {
		t.Fatalf("job saw %q, want frozen snapshot v1", b)
	}
}

// Internal absolute symlink is rewritten relative so it still resolves
// inside the run-base.
func TestFreezeRewritesInternalAbsoluteSymlink(t *testing.T) {
	src := t.TempDir()
	writeK15(t, filepath.Join(src, "real.txt"), "real")
	if err := os.Symlink(filepath.Join(src, "real.txt"), filepath.Join(src, "alias.txt")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir, cleanup, err := m.Prepare(context.Background(), "j")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	b, err := os.ReadFile(filepath.Join(dir, "alias.txt"))
	if err != nil {
		// follow symlink via ReadFile on dir path
		t.Fatalf("alias: %v", err)
	}
	if string(b) != "real" {
		t.Fatalf("alias content = %q", b)
	}
}

// External directory symlink must refuse freeze (non-deterministic).
func TestFreezeRefusesExternalDirSymlink(t *testing.T) {
	src := t.TempDir()
	ext := t.TempDir()
	if err := os.WriteFile(filepath.Join(ext, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ext, filepath.Join(src, "linkdir")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	writeK15(t, filepath.Join(src, "a.txt"), "a")
	m := &Manager{Source: src, Root: filepath.Join(t.TempDir(), "wr")}
	if err := os.MkdirAll(m.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.Freeze(context.Background()); err == nil {
		t.Fatal("external dir symlink must fail freeze")
	}
}
