// Package lifecycle owns the freeze-authority oracle as a named discovery
// test so CI can run `go test ./internal/lifecycle` as one entry point.
package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/workspace"
)

// TestFreezeAuthorityOracle: after Freeze, Prepare never observes later
// source edits (the class of bug that made one `kiwi run` mean two trees).
func TestFreezeAuthorityOracle(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := workspace.NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "b.txt"), []byte("late"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		dir, cleanup, err := m.Prepare(context.Background(), "job-"+string(rune('a'+i)))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "a.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "v1" {
			t.Fatalf("job %d saw %q want v1", i, b)
		}
		if _, err := os.Stat(filepath.Join(dir, "b.txt")); err == nil {
			t.Fatalf("job %d saw post-freeze b.txt", i)
		}
		cleanup()
	}
}
