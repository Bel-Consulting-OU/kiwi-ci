package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeK15(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func countK15Files(t *testing.T, root string) (n int, tops map[string]bool) {
	t.Helper()
	tops = map[string]bool{}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		tops[e.Name()] = true
	}
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			n++
		}
		return nil
	})
	return n, tops
}

// TestK15DefaultStagingIncludesIgnoredAndUntracked: a clean git tree whose
// ignored (.env) and untracked files exist on disk MUST appear in the job
// workspace. The historical worktree-of-HEAD path dropped them, so identical
// probes flipped between "has .env" and "missing .env" (K15).
func TestK15DefaultStagingIncludesIgnoredAndUntracked(t *testing.T) {
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
	writeK15(t, filepath.Join(src, ".gitignore"), ".env\nlocal.txt\n")
	writeK15(t, filepath.Join(src, "tracked.txt"), "v1")
	writeK15(t, filepath.Join(src, "services", "mail-server", "migrations", "001.sql"), "select 1;")
	writeK15(t, filepath.Join(src, "services", "mail-server", "src", "main.rs"), "fn main() {}")
	runGit("add", ".")
	runGit("commit", "-m", "init")
	// Ignored + untracked on disk after the commit (tree is still "clean"
	// for porcelain: ignored files do not appear).
	writeK15(t, filepath.Join(src, ".env"), "SECRET=1")
	writeK15(t, filepath.Join(src, "local.txt"), "untracked-but-ignored")

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	dir, cleanup, err := m.Prepare(context.Background(), "k15-ignored")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	for _, rel := range []string{
		"tracked.txt",
		".env",
		"local.txt",
		filepath.Join("services", "mail-server", "migrations", "001.sql"),
		filepath.Join("services", "mail-server", "src", "main.rs"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Fatalf("staged workspace missing %q (ignored/untracked must survive): %v", rel, err)
		}
	}
}

// TestK15StagingIsDeterministicAcrossProbes: two Prepare calls on the same
// source must stage the same file set. K15's smoking gun was 23 files vs
// 35,924 for identical probes.
func TestK15StagingIsDeterministicAcrossProbes(t *testing.T) {
	src := t.TempDir()
	writeK15(t, filepath.Join(src, "a.txt"), "a")
	writeK15(t, filepath.Join(src, "services", "migrations", "001.sql"), "x")
	writeK15(t, filepath.Join(src, ".env"), "E=1")
	writeK15(t, filepath.Join(src, "apps", "web", "index.html"), "<html>")

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	var first map[string]bool
	var firstN int
	for i := 0; i < 3; i++ {
		dir, cleanup, err := m.Prepare(context.Background(), "probe-"+string(rune('a'+i)))
		if err != nil {
			t.Fatal(err)
		}
		n, tops := countK15Files(t, dir)
		if _, ok := tops["services"]; !ok {
			t.Fatalf("probe %d lost top-level services/ (tops=%v n=%d)", i, tops, n)
		}
		if _, ok := tops["apps"]; !ok {
			t.Fatalf("probe %d lost top-level apps/ (tops=%v n=%d)", i, tops, n)
		}
		if first == nil {
			first, firstN = tops, n
		} else if n != firstN {
			t.Fatalf("probe %d staged %d files, first staged %d — staging is non-deterministic", i, n, firstN)
		}
		cleanup()
	}
}

// TestK15VerifyRejectsTruncatedTree: verifyStagedTree must fail closed when
// the staged tree is missing source top-level directories (the 23-file stub).
func TestK15VerifyRejectsTruncatedTree(t *testing.T) {
	src := t.TempDir()
	writeK15(t, filepath.Join(src, "services", "migrations", "001.sql"), "x")
	writeK15(t, filepath.Join(src, "apps", "x.txt"), "x")
	writeK15(t, filepath.Join(src, "root.txt"), "x")

	// Simulate the bad staging: only root files, no top-level dirs.
	bad := t.TempDir()
	writeK15(t, filepath.Join(bad, "root.txt"), "x")
	writeK15(t, filepath.Join(bad, "orphan1.txt"), "x")

	err := verifyStagedTree(src, bad, "copy")
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("verifyStagedTree(truncated) = %v, want truncated error", err)
	}

	// A correct staging passes.
	good := t.TempDir()
	writeK15(t, filepath.Join(good, "services", "migrations", "001.sql"), "x")
	writeK15(t, filepath.Join(good, "apps", "x.txt"), "x")
	writeK15(t, filepath.Join(good, "root.txt"), "x")
	if err := verifyStagedTree(src, good, "copy"); err != nil {
		t.Fatalf("verifyStagedTree(good) = %v", err)
	}
}

// TestK15HasTrackedFilesKeepsDirOnGitError: a git failure must not be
// read as "no tracked files" (which silently SkipDir'd source dirs).
func TestK15HasTrackedFilesKeepsDirOnGitError(t *testing.T) {
	src := t.TempDir()
	if !hasTrackedFiles(src, "target") {
		t.Fatal("hasTrackedFiles on git failure must return true (keep the directory), got false — that path SkipDir'd source")
	}
}

// TestK15CleanAndDirtyProduceSameTrackedLayout: even when the tree flips
// clean/dirty, top-level directories and migrations must always be staged.
func TestK15CleanAndDirtyProduceSameTrackedLayout(t *testing.T) {
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
	writeK15(t, filepath.Join(src, "services", "migrations", "001.sql"), "select 1;")
	writeK15(t, filepath.Join(src, "README.md"), "hi")
	runGit("add", ".")
	runGit("commit", "-m", "init")

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// Clean
	dir1, c1, err := m.Prepare(context.Background(), "clean")
	if err != nil {
		t.Fatal(err)
	}
	n1, tops1 := countK15Files(t, dir1)
	c1()

	// Dirty
	writeK15(t, filepath.Join(src, "untracked.tmp"), "x")
	dir2, c2, err := m.Prepare(context.Background(), "dirty")
	if err != nil {
		t.Fatal(err)
	}
	n2, tops2 := countK15Files(t, dir2)
	c2()

	for _, d := range []string{"services", "README.md"} {
		if !tops1[d] {
			t.Fatalf("clean staging missing %q (tops=%v n=%d)", d, tops1, n1)
		}
		if !tops2[d] {
			t.Fatalf("dirty staging missing %q (tops=%v n=%d)", d, tops2, n2)
		}
	}
	// Dirty must be a SUPERSET (has the untracked file) of clean's tracked layout.
	if n2 <= n1 {
		t.Fatalf("dirty staging (%d files) is not larger than clean (%d) — untracked content missing", n2, n1)
	}
}
