package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Source is a linked worktree (.git is a file, not a directory). Freeze
// must still capture the working tree including untracked files.
func TestFreezeLinkedWorktreeSource(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	main := t.TempDir()
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run(main, "init", "-b", "main")
	run(main, "config", "user.email", "t@example.com")
	run(main, "config", "user.name", "t")
	writeK15(t, filepath.Join(main, "tracked.txt"), "v")
	run(main, "add", ".")
	run(main, "commit", "-m", "init")
	wt := filepath.Join(t.TempDir(), "wt")
	run(main, "worktree", "add", "--detach", wt, "HEAD")
	writeK15(t, filepath.Join(wt, "untracked.txt"), "u")

	m, err := NewManager(wt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatalf("freeze worktree: %v", err)
	}
	dir, cleanup, err := m.Prepare(context.Background(), "j")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, rel := range []string{"tracked.txt", "untracked.txt"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
	}
}
