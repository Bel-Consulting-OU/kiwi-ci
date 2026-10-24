package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// Even with KIWI_WORKSPACE_STRATEGY=worktree, Freeze must capture the
// working tree (untracked/ignored), not HEAD-only worktree contents.
func TestFreezeIgnoresWorktreeStrategy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	t.Setenv(workspaceStrategyEnv, "worktree")
	src := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", src}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-b", "main")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")
	writeK15(t, filepath.Join(src, "tracked.txt"), "v")
	run("add", ".")
	run("commit", "-m", "init")
	writeK15(t, filepath.Join(src, "ignored-or-untracked.tmp"), "u")
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.BasePath(), "ignored-or-untracked.tmp")); err != nil {
		t.Fatalf("freeze under worktree strategy dropped working-tree file: %v", err)
	}
}

// After Freeze, rewriting the live pipeline file must not change what
// later job workspaces (and thus frozen loads) see.
func TestFreezePinsFileContent(t *testing.T) {
	src := t.TempDir()
	writeK15(t, filepath.Join(src, ".kiwi", "pipeline.yaml"), "version: 1\njobs:\n  a:\n    steps: [{run: \"echo v1\"}]\n")
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeK15(t, filepath.Join(src, ".kiwi", "pipeline.yaml"), "version: 1\njobs:\n  a:\n    steps: [{run: \"echo CHANGED\"}]\n")
	dir, cleanup, err := m.Prepare(context.Background(), "j")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	b, err := os.ReadFile(filepath.Join(dir, ".kiwi", "pipeline.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "CHANGED") {
		t.Fatal("post-freeze pipeline edit leaked into the job workspace")
	}
	if !strings.Contains(string(b), "echo v1") {
		t.Fatalf("frozen pipeline content = %s", b)
	}
}
