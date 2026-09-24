package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	// Safe IDs sanitize to themselves exactly (no suffix), so existing
	// workspace paths are unchanged.
	for _, in := range []string{"build", "UPPER_case-1", "job-1", "a-b"} {
		if got := sanitizeJobID(in); got != in {
			t.Errorf("sanitizeJobID(%q) = %q, want the input unchanged", in, got)
		}
	}
	// Lossy IDs stay safe and deterministic while carrying a stable hash
	// suffix so distinct raw IDs can never collapse to the same component.
	lossy := []string{"build[go=1.21]", "a/b", "a\\b", "..", "../evil", "", "matrix[x=1,y=2]", "  spaced  out "}
	seen := map[string]string{}
	for _, in := range lossy {
		got := sanitizeJobID(in)
		if got == "" || got == "." || got == ".." {
			t.Errorf("sanitizeJobID(%q) = %q is not a safe path component", in, got)
		}
		if strings.ContainsAny(got, `/\`) || filepath.Base(got) != got {
			t.Errorf("sanitizeJobID(%q) = %q contains a separator or extra component", in, got)
		}
		if prev, ok := seen[got]; ok {
			t.Errorf("sanitizeJobID collision: %q and %q both map to %q", prev, in, got)
		}
		seen[got] = in
		if again := sanitizeJobID(in); again != got {
			t.Errorf("sanitizeJobID(%q) not deterministic: %q then %q", in, got, again)
		}
	}
	// The auditor's collision pair must now be distinct.
	if sanitizeJobID("a/b") == sanitizeJobID("a.b") {
		t.Fatalf("a/b and a.b still collide: %q", sanitizeJobID("a/b"))
	}
	// Safe IDs keep the historical human-readable form.
	for in, want := range map[string]string{"build": "build", "a-b": "a-b"} {
		if got := sanitizeJobID(in); got != want {
			t.Errorf("sanitizeJobID(%q) = %q, want %q", in, got, want)
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
	// git prints --git-dir with forward slashes on every platform (including
	// Windows), so compare after normalizing separators.
	gitDirPath := filepath.ToSlash(strings.TrimSpace(string(gitDir)))
	if !strings.HasSuffix(gitDirPath, ".git/worktrees/"+filepath.Base(dir)) {
		t.Fatalf("workspace git-dir = %q, want a worktree dir", gitDirPath)
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

// TestCloseSerializesWithPrepare is the H1-E workspace regression: Close must
// take Manager.mu, so it can never RemoveAll the run Root while a concurrent
// Prepare is materializing a workspace under it. The test holds the lock and
// proves Close blocks until it is released (the pre-fix Close ignored mu and
// returned immediately).
func TestCloseSerializesWithPrepare(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "file.txt"), "x")
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- m.Close() }()
	select {
	case <-done:
		m.mu.Unlock()
		t.Fatal("Close returned without waiting for Manager.mu")
	case <-time.After(200 * time.Millisecond):
	}
	m.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("Close after unlock = %v", err)
	}
	if _, err := os.Stat(m.Root); !os.IsNotExist(err) {
		t.Fatalf("workspace root survived Close: %v", err)
	}
}
