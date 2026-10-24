package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A symlink loop under the source must not hang freeze or create a
// recursive copy bomb: filepath.Walk does not follow directory symlinks.
func TestFreezeSymlinkLoop(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(src, "loop")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	done := make(chan error, 1)
	go func() { done <- m.Freeze(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("freeze with symlink loop: %v", err)
		}
	case <-context.Background().Done():
		t.Fatal("unreachable")
	}
	// timeout via test deadline: go test -timeout covers hang
	dir, cleanup, err := m.Prepare(context.Background(), "j")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(dir, "a.txt")); err != nil {
		t.Fatal(err)
	}
}
