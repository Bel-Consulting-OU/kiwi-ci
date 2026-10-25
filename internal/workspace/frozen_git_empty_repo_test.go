package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestFreezeEmptyGitRepositorySucceeds: `git init` with no commits has no
// HEAD to freeze. That is NOT an unstable capture (no identity could have
// moved) — Freeze must succeed. The previous Unstable-on-HEAD-error path
// refused every fresh repository before the first commit.
func TestFreezeEmptyGitRepositorySucceeds(t *testing.T) {
	src := t.TempDir()
	if err := exec.Command("git", "init", "-q", src).Run(); err != nil {
		t.Skipf("git init: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(t.Context()); err != nil {
		t.Fatalf("empty-repo Freeze must succeed (no HEAD is not Unstable): %v", err)
	}
	fg := m.FrozenGitInfo()
	if fg.CaptureFailed() {
		t.Fatalf("empty repo must not be CaptureFailed: %+v", fg)
	}
	if fg.Captured {
		t.Fatalf("empty repo must not claim Captured: %+v", fg)
	}
	if m.BasePath() == "" {
		t.Fatal("Freeze did not publish a run-base")
	}
}

// TestCaptureFrozenGitUnstableOnlyWhenHeadMoves: first sample succeeds and
// a later HEAD check fails → Unstable; empty repo (never sampled) is not.
func TestCaptureFrozenGitOnlyHeadMovementIsUnstable(t *testing.T) {
	// Empty: no commits → neither Captured nor Unstable.
	src := t.TempDir()
	if err := exec.Command("git", "init", "-q", src).Run(); err != nil {
		t.Skipf("git init: %v", err)
	}
	g := captureFrozenGitSource(src)
	if g.Captured || g.Unstable {
		t.Fatalf("empty repo capture = %+v, want zero state", g)
	}
	// Real repo with a commit → Captured, not Unstable.
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		c := exec.Command("git", append([]string{"-C", src}, args...)...)
		c.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("add", "a.txt")
	run("commit", "-qm", "init")
	g2 := captureFrozenGitSource(src)
	if !g2.Captured || g2.Unstable {
		t.Fatalf("committed repo capture = %+v, want Captured", g2)
	}
	if g2.SHA == "" {
		t.Fatal("captured SHA empty")
	}
}

// TestCaptureFrozenGitCorruptHEADNotCaptured: a repository whose HEAD is
// unreadable is never reported as Captured. Git itself rejects the
// directory (rev-parse --git-dir fails), so the capture is the zero
// state — Freeze must not invent a SHA, and RunLocal must not treat it
// as a successful identity.
func TestCaptureFrozenGitCorruptHEADNotCaptured(t *testing.T) {
	src := t.TempDir()
	if err := exec.Command("git", "init", "-q", src).Run(); err != nil {
		t.Skipf("git init: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		c := exec.Command("git", append([]string{"-C", src}, args...)...)
		c.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("add", "a.txt")
	run("commit", "-qm", "init")
	headPath := filepath.Join(src, ".git", "HEAD")
	if err := os.WriteFile(headPath, []byte("not-a-ref-or-sha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := captureFrozenGitSource(src)
	if g.Captured {
		t.Fatalf("corrupt HEAD must not be Captured: %+v", g)
	}
	if g.SHA != "" {
		t.Fatalf("corrupt HEAD must not yield a SHA: %+v", g)
	}
	// Freeze must still succeed: the working-tree snapshot does not depend
	// on Git identity, and !Captured is the honest "no identity" state.
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(t.Context()); err != nil {
		t.Fatalf("Freeze with unreadable HEAD: %v", err)
	}
	fg := m.FrozenGitInfo()
	if fg.Captured || fg.CaptureFailed() {
		t.Fatalf("frozen git = %+v, want zero state", fg)
	}
}
