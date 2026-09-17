package workspace

import (
	"context"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// shimCP installs a fake `cp` as the first PATH entry. mode is "fail" (exit 1
// immediately) or "block" (create the marker file, then sleep long enough for
// the test to cancel the context). The original PATH is preserved so `git`
// stays reachable.
func shimCP(t *testing.T, mode, marker string) {
	t.Helper()
	dir := t.TempDir()
	var body string
	switch mode {
	case "fail":
		body = "#!/bin/sh\nexit 1\n"
	case "block":
		body = "#!/bin/sh\n: > " + marker + "\nsleep 30\nexit 1\n"
	default:
		t.Fatalf("unknown shim mode %q", mode)
	}
	if err := os.WriteFile(filepath.Join(dir, "cp"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestSnapshotCopyFallback(t *testing.T) {
	shimCP(t, "fail", "")
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "app.txt"), "app")
	writeFile(t, filepath.Join(src, "nested", "deep.txt"), "deep")
	writeFile(t, filepath.Join(src, ".git", "config"), "git-file-entry")
	if err := os.MkdirAll(filepath.Join(src, ".kiwi", "cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, ".kiwi", "cache", "blob"), "cached")
	writeFile(t, filepath.Join(src, ".kiwi", "pipeline.yaml"), "version: 1")
	if err := os.Symlink("app.txt", filepath.Join(src, "link.txt")); err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	dir, cleanup, err := m.Prepare(context.Background(), "copy-fallback")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer cleanup()

	if got := readFile(t, filepath.Join(dir, "app.txt")); got != "app" {
		t.Fatalf("copied app.txt = %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "nested", "deep.txt")); got != "deep" {
		t.Fatalf("copied nested file = %q", got)
	}
	link, err := os.Readlink(filepath.Join(dir, "link.txt"))
	if err != nil || link != "app.txt" {
		t.Fatalf("symlink not preserved: %q %v", link, err)
	}
	for _, absent := range []string{".git", filepath.Join(".kiwi", "cache")} {
		if _, err := os.Stat(filepath.Join(dir, absent)); !os.IsNotExist(err) {
			t.Fatalf("copy fallback must skip %q", absent)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".kiwi", "pipeline.yaml")); err != nil {
		t.Fatalf(".kiwi/pipeline.yaml must be copied: %v", err)
	}
	// The copied workspace is a plain directory, not a worktree.
	if _, err := os.Stat(filepath.Join(dir, ".git")); !os.IsNotExist(err) {
		t.Fatal("copy fallback must not carry .git")
	}
}

// TestSnapshotWorktreeAddFailure exercises the branch where `git worktree
// add` fails while the context is still live: the target is removed and the
// snapshot falls through to the copy strategies.
func TestSnapshotWorktreeAddFailure(t *testing.T) {
	testutil.UnixChmod(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	src := t.TempDir()
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "config", "user.email", "test@example.com")
	runGit(t, src, "config", "user.name", "test")
	writeFile(t, filepath.Join(src, "tracked.txt"), "v1")
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-m", "init")

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := os.Chmod(m.Root, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(m.Root, 0o755) })

	if _, _, err := m.Prepare(context.Background(), "readonly-root"); err == nil {
		t.Fatal("prepare must fail when the run root is not writable")
	}
}

func TestSnapshotCancelDuringReflink(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("reflink path is darwin-only")
	}
	marker := filepath.Join(t.TempDir(), "cp-started")
	shimCP(t, "block", marker)
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "app.txt"), "app")

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, _, err := m.Prepare(ctx, "cancelled-reflink")
		errCh <- err
	}()
	waitFor(t, marker)
	cancel()
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("prepare error = %v, want context canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Prepare did not return after context cancellation")
	}
}

// TestSnapshotCancelDuringWorktree cancels the context while `git worktree
// add` is running: the worktree strategy must report the context error.
func TestSnapshotCancelDuringWorktree(t *testing.T) {
	testutil.UnixShell(t)
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	marker := filepath.Join(t.TempDir(), "git-worktree-started")
	shimDir := t.TempDir()
	script := "#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in worktree) : > " + marker + "; sleep 30; exit 1;; esac\ndone\nexec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	src := t.TempDir()
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "config", "user.email", "test@example.com")
	runGit(t, src, "config", "user.name", "test")
	writeFile(t, filepath.Join(src, "tracked.txt"), "v1")
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-m", "init")

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, _, err := m.Prepare(ctx, "cancelled-worktree")
		errCh <- err
	}()
	waitFor(t, marker)
	cancel()
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("prepare error = %v, want context canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Prepare did not return after context cancellation")
	}
}

func TestPrepareContextAlreadyCancelled(t *testing.T) {
	src := t.TempDir()
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := m.Prepare(ctx, "job"); err != context.Canceled {
		t.Fatalf("Prepare(cancelled) = %v, want context.Canceled", err)
	}
}

func TestPrepareCancelledWhileWaitingForLock(t *testing.T) {
	src := t.TempDir()
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	m.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, _, err := m.Prepare(ctx, "blocked")
		errCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	m.mu.Unlock()

	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Fatalf("Prepare = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Prepare did not return")
	}
}

func TestPrepareTargetExists(t *testing.T) {
	src := t.TempDir()
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if err := os.MkdirAll(filepath.Join(m.Root, "occupied"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err = m.Prepare(context.Background(), "occupied")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Prepare = %v, want already exists", err)
	}
}

func TestPrepareSnapshotFailure(t *testing.T) {
	src := t.TempDir()
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := os.RemoveAll(src); err != nil {
		t.Fatal(err)
	}
	_, _, err = m.Prepare(context.Background(), "gone")
	if err == nil || !strings.Contains(err.Error(), "prepare workspace") {
		t.Fatalf("Prepare = %v, want a wrapped snapshot error", err)
	}
}

func TestNewManagerSourceErrors(t *testing.T) {
	if _, err := NewManager(filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "workspace source") {
		t.Fatalf("NewManager(missing) = %v", err)
	}
	file := filepath.Join(t.TempDir(), "file.txt")
	writeFile(t, file, "x")
	if _, err := NewManager(file); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("NewManager(file) = %v", err)
	}
}

func TestNewManagerRootError(t *testing.T) {
	src := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing-root"))
	if _, err := NewManager(src); err == nil || !strings.Contains(err.Error(), "workspace root") {
		t.Fatalf("NewManager = %v, want workspace root error", err)
	}
}

func TestManagerCloseWithoutRoot(t *testing.T) {
	m := &Manager{}
	if err := m.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
}

func TestGitStatusCleanError(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	if _, err := gitStatusClean(context.Background(), dir); err == nil {
		t.Fatal("gitStatusClean outside a repo must fail")
	}
}

func TestGitStatusCleanDirtyRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	src := t.TempDir()
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "config", "user.email", "test@example.com")
	runGit(t, src, "config", "user.name", "test")
	writeFile(t, filepath.Join(src, "tracked.txt"), "v1")
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-m", "init")

	clean, err := gitStatusClean(context.Background(), src)
	if err != nil || !clean {
		t.Fatalf("clean repo = %v (err %v)", clean, err)
	}
	writeFile(t, filepath.Join(src, "untracked.txt"), "x")
	clean, err = gitStatusClean(context.Background(), src)
	if err != nil || clean {
		t.Fatalf("dirty repo reported clean (err %v)", err)
	}
}

func TestCopyTreeErrors(t *testing.T) {
	if err := copyTree(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "dst")); err == nil {
		t.Fatal("copyTree from a missing source must fail")
	}

	// Destination is an existing file: every MkdirAll below it fails.
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "sub", "a.txt"), "a")
	dst := filepath.Join(t.TempDir(), "dst-file")
	writeFile(t, dst, "not a directory")
	if err := copyTree(src, dst); err == nil {
		t.Fatal("copyTree into a file destination must fail")
	}

	// A symlink whose parent cannot be created.
	linkSrc := t.TempDir()
	if err := os.Symlink("nowhere", filepath.Join(linkSrc, "a-link")); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(linkSrc, dst); err == nil {
		t.Fatal("copyTree symlink into a file destination must fail")
	}
}

func TestCopyTreeSkipsGitAndCacheFiles(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, ".git"), "gitfile")
	writeFile(t, filepath.Join(src, ".kiwi", "cache"), "cachefile")
	writeFile(t, filepath.Join(src, "keep.txt"), "keep")
	dst := filepath.Join(t.TempDir(), "out")
	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".git")); !os.IsNotExist(err) {
		t.Fatal(".git file must be skipped")
	}
	if _, err := os.Stat(filepath.Join(dst, ".kiwi", "cache")); !os.IsNotExist(err) {
		t.Fatal(".kiwi/cache file must be skipped")
	}
	if got := readFile(t, filepath.Join(dst, "keep.txt")); got != "keep" {
		t.Fatalf("keep.txt = %q", got)
	}
}

func TestCopyFileErrors(t *testing.T) {
	dir := t.TempDir()
	if err := copyFile(filepath.Join(dir, "missing"), filepath.Join(dir, "out"), 0o644); err == nil {
		t.Fatal("copyFile from a missing source must fail")
	}
	src := filepath.Join(dir, "src.txt")
	writeFile(t, src, "content")
	if err := copyFile(src, filepath.Join(dir, "src.txt", "child"), 0o644); err == nil {
		t.Fatal("copyFile with a file as parent directory must fail")
	}
	if err := copyFile(src, dir, 0o644); err == nil {
		t.Fatal("copyFile onto a directory must fail")
	}
	if err := copyFile(dir, filepath.Join(dir, "out-dir"), 0o644); err == nil {
		t.Fatal("copyFile from a directory must fail")
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func waitFor(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
