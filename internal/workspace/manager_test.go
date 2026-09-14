package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestSanitizeJobID(t *testing.T) {
	cases := map[string]string{
		"build":           "build",
		"build[go=1.21]":  "build-go-1-21",
		"a/b":             "a-b",
		"a\\b":            "a-b",
		"..":              "job",
		"../evil":         "evil",
		"":                "job",
		"matrix[x=1,y=2]": "matrix-x-1-y-2",
		"UPPER_case-1":    "UPPER_case-1",
		"  spaced  out ":  "spaced-out",
	}
	for in, want := range cases {
		got := sanitizeJobID(in)
		if got != want {
			t.Errorf("sanitizeJobID(%q) = %q, want %q", in, got, want)
		}
		if got == "" || got == "." || got == ".." {
			t.Errorf("sanitizeJobID(%q) = %q is not a safe path component", in, got)
		}
		if strings.ContainsAny(got, `/\`) || filepath.Base(got) != got {
			t.Errorf("sanitizeJobID(%q) = %q contains a separator or extra component", in, got)
		}
	}
}

func TestPrepareIsolatedCopy(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "nested", "source.txt"), "source-content")
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	dir, cleanup, err := m.Prepare(context.Background(), "job-one")
	if err != nil {
		t.Fatal(err)
	}
	if dir == src || strings.HasPrefix(src, dir+string(filepath.Separator)) || strings.HasPrefix(dir, src+string(filepath.Separator)) {
		t.Fatalf("workspace %q is not isolated from source %q", dir, src)
	}
	if got := readFile(t, filepath.Join(dir, "nested", "source.txt")); got != "source-content" {
		t.Fatalf("snapshot content = %q, want source-content", got)
	}

	// Writes in the job workspace never appear in the source.
	writeFile(t, filepath.Join(dir, "job-only.txt"), "job")
	if _, err := os.Stat(filepath.Join(src, "job-only.txt")); !os.IsNotExist(err) {
		t.Fatal("job workspace write leaked into the source tree")
	}
	// Writes in the source never appear in an existing job workspace.
	writeFile(t, filepath.Join(src, "source-only.txt"), "src")
	if _, err := os.Stat(filepath.Join(dir, "source-only.txt")); !os.IsNotExist(err) {
		t.Fatal("source write leaked into the job workspace")
	}

	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("cleanup did not remove %q", dir)
	}
	// Cleanup is idempotent.
	cleanup()
}

func TestPrepareSkipsGitAndKiwiCache(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "app.txt"), "app")
	writeFile(t, filepath.Join(src, ".git", "objects", "deadbeef"), "git-internal")
	writeFile(t, filepath.Join(src, ".kiwi", "pipeline.yaml"), "version: 1")
	writeFile(t, filepath.Join(src, ".kiwi", "cache", "big.bin"), "cache-internal")
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	dir, cleanup, err := m.Prepare(context.Background(), "job-skip")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	for _, absent := range []string{".git", ".kiwi/cache"} {
		if _, err := os.Stat(filepath.Join(dir, absent)); !os.IsNotExist(err) {
			t.Fatalf("workspace copied excluded path %q", absent)
		}
	}
	for _, present := range []string{"app.txt", ".kiwi/pipeline.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, present)); err != nil {
			t.Fatalf("workspace missing %q: %v", present, err)
		}
	}
}

func TestPrepareGitWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	src := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", src}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	runGit("init", "-b", "main")
	runGit("config", "user.email", "test@example.com")
	runGit("config", "user.name", "test")
	writeFile(t, filepath.Join(src, "tracked.txt"), "v1")
	runGit("add", ".")
	runGit("commit", "-m", "init")

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	dir, cleanup, err := m.Prepare(context.Background(), "job-git")
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "tracked.txt")); got != "v1" {
		t.Fatalf("worktree content = %q, want v1", got)
	}
	gitDir, err := exec.Command("git", "-C", dir, "rev-parse", "--git-dir").Output()
	if err != nil {
		t.Fatalf("workspace is not a git worktree: %v", err)
	}
	if !strings.HasSuffix(strings.TrimSpace(string(gitDir)), ".git/worktrees/"+filepath.Base(dir)) {
		t.Fatalf("workspace git-dir = %q, want a worktree dir", strings.TrimSpace(string(gitDir)))
	}

	// Writes in the worktree never appear in the source.
	writeFile(t, filepath.Join(dir, "untracked.txt"), "x")
	if _, err := os.Stat(filepath.Join(src, "untracked.txt")); !os.IsNotExist(err) {
		t.Fatal("worktree write leaked into the source tree")
	}

	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("cleanup did not remove worktree %q", dir)
	}
	out, err := exec.Command("git", "-C", src, "worktree", "list").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), filepath.Base(dir)) {
		t.Fatalf("worktree registration survived cleanup: %s", out)
	}
}

func TestPrepareFallsBackWhenGitFails(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "plain.txt"), "plain")
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	dir, cleanup, err := m.Prepare(context.Background(), "job-plain")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got := readFile(t, filepath.Join(dir, "plain.txt")); got != "plain" {
		t.Fatalf("fallback copy content = %q, want plain", got)
	}
}
