package workspace

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// Linked worktree: after freeze, captured SHA must be the freeze-time HEAD,
// not whatever the live worktree moves to next.
func TestFrozenGitCapturesSourceHEAD(t *testing.T) {
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
	writeK15(t, filepath.Join(main, "a.txt"), "v1")
	run(main, "add", ".")
	run(main, "commit", "-m", "v1")
	sha1 := gitRev(t, main)
	wt := filepath.Join(t.TempDir(), "wt")
	run(main, "worktree", "add", "--detach", wt, sha1)

	m, err := NewManager(wt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	fg := m.FrozenGitInfo()
	if !fg.Captured || fg.SHA != sha1 {
		t.Fatalf("frozen git = %+v, want sha %s", fg, sha1)
	}
	// Move the LIVE worktree forward.
	writeK15(t, filepath.Join(wt, "a.txt"), "v2")
	run(wt, "add", ".")
	run(wt, "commit", "-m", "v2")
	sha2 := gitRev(t, wt)
	if sha2 == sha1 {
		t.Fatal("expected live worktree HEAD to move")
	}
	fg2 := m.FrozenGitInfo()
	if fg2.SHA != sha1 {
		t.Fatalf("frozen SHA changed to %q after live commit; want %q", fg2.SHA, sha1)
	}
}

func gitRev(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out[:len(out)-1])
}
