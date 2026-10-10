package workspace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCopyTreeExcludesDestinationPresentBeforeWalk covers both destination
// exclusion outcomes: a destination directory under the source is pruned
// (SkipDir) when it already exists before the walk, and a regular file at the
// destination path is skipped without aborting the walk.
func TestCopyTreeExcludesDestinationPresentBeforeWalk(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "keep.txt"), "keep")

	// Destination directory pre-created under the source: the walk must see
	// it and SkipDir, never copy it into itself.
	dstDir := filepath.Join(src, "a-workspace")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(src, dstDir); err != nil {
		t.Fatalf("copyTree with pre-created destination dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "a-workspace")); !os.IsNotExist(err) {
		t.Fatalf("destination subtree copied into itself: %v", err)
	}
	if got := readFile(t, filepath.Join(dstDir, "keep.txt")); got != "keep" {
		t.Fatalf("keep.txt = %q", got)
	}

	// Destination is a regular file that already exists inside the source:
	// the walk skips exactly that path (rather than clobbering it) and the
	// remaining siblings then fail because the destination cannot hold them.
	src2 := t.TempDir()
	writeFile(t, filepath.Join(src2, "a-out"), "pre-existing")
	writeFile(t, filepath.Join(src2, "z.txt"), "z")
	dstFile := filepath.Join(src2, "a-out")
	if err := copyTree(src2, dstFile); err == nil {
		t.Fatal("copyTree with a file destination must fail on the siblings it cannot place")
	}
	if got := readFile(t, dstFile); got != "pre-existing" {
		t.Fatalf("destination file overwritten: %q", got)
	}
}

// TestGitStatusCleanTruncatedPorcelain proves a working tree with more
// changes than the bounded capture limit is reported DIRTY (never clean just
// because the output was truncated).
func TestGitStatusCleanTruncatedPorcelain(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	src := t.TempDir()
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "config", "user.email", "test@example.com")
	runGit(t, src, "config", "user.name", "test")

	// A tracked file keeps the directory from being collapsed to one
	// `?? many/` porcelain line, so every untracked file produces a line.
	if err := os.MkdirAll(filepath.Join(src, "many"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "many", "keep.txt"), "tracked")
	runGit(t, src, "add", "many/keep.txt")
	runGit(t, src, "commit", "-m", "init")

	long := strings.Repeat("n", 180)
	for i := 0; i < 9000; i++ {
		name := fmt.Sprintf("%s-%05d.txt", long, i)
		if err := os.WriteFile(filepath.Join(src, "many", name), []byte("x"), 0o644); err != nil {
			t.Fatalf("seed untracked file %d: %v", i, err)
		}
	}

	clean, err := gitStatusClean(context.Background(), src)
	if err != nil {
		t.Fatalf("gitStatusClean: %v", err)
	}
	if clean {
		t.Fatal("truncated porcelain output reported a clean tree")
	}
}
