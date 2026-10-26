package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestLinkedWorktreeTrackedDistSurvivesPrepare is the item-5 functional
// bug: Freeze correctly keeps git-tracked files inside skip-name
// directories (dist/), but Prepare used to RE-APPLY Git-aware filtering on
// the run-base — whose linked-worktree .git pointer was stripped — so
// `git ls-files` failed, isGitTracked answered false, and the tracked
// release asset silently vanished from the job workspace. A stripped base
// must be copied VERBATIM; filtering happens only while constructing it.
//
// The untracked node_modules half pins the companion verify failure: the
// old verify asked hasTrackedFiles against the stripped base (git failure
// → keep → required), demanded the directory the freeze had correctly
// dropped, and failed the whole Prepare.
func TestLinkedWorktreeTrackedDistSurvivesPrepare(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	main := t.TempDir()
	runGit(t, main, "init", "-b", "main")
	runGit(t, main, "config", "user.email", "t@example.com")
	runGit(t, main, "config", "user.name", "t")
	writeFile(t, filepath.Join(main, "app.go"), "package main")
	runGit(t, main, "add", ".")
	runGit(t, main, "commit", "-m", "init")
	// Tracked release asset (committed, so the linked worktree checks it out).
	writeFile(t, filepath.Join(main, "dist", "asset.txt"), "tracked-asset")
	runGit(t, main, "add", "dist/asset.txt")
	runGit(t, main, "commit", "-m", "track asset")

	wt := filepath.Join(t.TempDir(), "wt")
	runGit(t, main, "worktree", "add", "--detach", wt, "HEAD")
	// Untracked build junk INSIDE the worktree (the realistic post-checkout
	// state: a vendor install and a local build output).
	writeFile(t, filepath.Join(wt, "dist", "scratch.bin"), "untracked-junk")
	writeFile(t, filepath.Join(wt, "node_modules", "pkg", "index.js"), "// vendor")

	m, err := NewManager(wt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	// The frozen base must have lost the live worktree pointer (that is
	// the stripping that used to break all later Git queries).
	if _, err := os.Lstat(filepath.Join(m.BasePath(), ".git")); err == nil {
		t.Fatal("linked-worktree .git pointer must be stripped from the run-base")
	}
	dir, cleanup, err := m.Prepare(context.Background(), "job")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer cleanup()
	if got := readFile(t, filepath.Join(dir, "dist", "asset.txt")); got != "tracked-asset" {
		t.Fatalf("tracked dist/asset.txt in job workspace = %q, want tracked-asset (exact copy of run-base)", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist", "scratch.bin")); err == nil {
		t.Fatal("untracked dist output must not enter the workspace (filtering was resolved at Freeze)")
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules")); err == nil {
		t.Fatal("untracked node_modules must stay dropped — and Prepare must still succeed without verify demanding it back")
	}
	// The workspace is an exact copy of the canonical base: same file set.
	assertSameFileSet(t, m.BasePath(), dir)
}

// TestRepoNoHeadStaysSHAEmptyAfterFirstCommit pins the item-6 state
// machine: an unborn HEAD is repo-no-head (its own state, NOT "not a
// repository"), and its SHA stays empty for the whole run even after the
// first commit lands in the live source — the run must never re-read Git
// to discover identity B for tree A.
func TestRepoNoHeadStaysSHAEmptyAfterFirstCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	src := t.TempDir()
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "config", "user.email", "t@example.com")
	runGit(t, src, "config", "user.name", "t")
	writeFile(t, filepath.Join(src, "a.txt"), "x")

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatalf("freeze of unborn repo: %v", err)
	}
	fg := m.FrozenGitInfo()
	if fg.State() != FrozenGitRepoNoHead {
		t.Fatalf("state = %q, want %q (unborn HEAD is not not-repo)", fg.State(), FrozenGitRepoNoHead)
	}
	if fg.Captured || fg.SHA != "" {
		t.Fatalf("unborn capture = %+v, want empty SHA", fg)
	}
	if fg.Branch != "main" || fg.Ref != "refs/heads/main" {
		t.Fatalf("repo-no-head must still carry branch/ref: %+v", fg)
	}
	if !fg.Repo {
		t.Fatal("repo-no-head must record that a repository exists")
	}
	// The audited race: commit AFTER freeze. The frozen identity must not
	// move with it.
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-m", "first")
	fg2 := m.FrozenGitInfo()
	if fg2.State() != FrozenGitRepoNoHead || fg2.SHA != "" || fg2.Captured {
		t.Fatalf("after the first commit the frozen state moved: %+v (live Git was re-read)", fg2)
	}
}

// TestLinkedWorktreeCapturesRepoIdentity pins item 6's identity loss: the
// freeze strips the linked worktree's .git pointer, so a post-Freeze
// detectGitRepo(base) answers nothing and CI_REPO/GITHUB_REPOSITORY go
// empty. Repo coordinates must travel inside FrozenGit, captured from the
// SOURCE remote before the pointer is removed.
func TestLinkedWorktreeCapturesRepoIdentity(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	main := t.TempDir()
	runGit(t, main, "init", "-b", "main")
	runGit(t, main, "config", "user.email", "t@example.com")
	runGit(t, main, "config", "user.name", "t")
	writeFile(t, filepath.Join(main, "a.txt"), "x")
	runGit(t, main, "add", ".")
	runGit(t, main, "commit", "-m", "init")
	runGit(t, main, "remote", "add", "origin", "https://github.com/acme/widgets.git")

	wt := filepath.Join(t.TempDir(), "wt")
	runGit(t, main, "worktree", "add", "--detach", wt, "HEAD")

	m, err := NewManager(wt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	fg := m.FrozenGitInfo()
	if fg.RepoURL != "https://github.com/acme/widgets.git" {
		t.Fatalf("RepoURL = %q, want the source remote (stripped base cannot answer it)", fg.RepoURL)
	}
	if fg.RepoFullName != "acme/widgets" {
		t.Fatalf("RepoFullName = %q, want acme/widgets", fg.RepoFullName)
	}
}

// TestFreezeCapturesExplicitRefsTransactionally: --base/--head/--merge-base
// are resolved from the SOURCE inside the freeze transaction. After the
// run-base seals Git away, the resolved set must not move even when the
// live repository advances — a stripped worktree could not even answer the
// query anymore.
func TestFreezeCapturesExplicitRefsTransactionally(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	src := t.TempDir()
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "config", "user.email", "t@example.com")
	runGit(t, src, "config", "user.name", "t")
	writeFile(t, filepath.Join(src, "base.txt"), "b")
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-m", "base")
	writeFile(t, filepath.Join(src, "feature.txt"), "f")
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-m", "feature")

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.CaptureRefs(RefQuery{Base: "HEAD~1", Head: "HEAD"})
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	fg := m.FrozenGitInfo()
	if fg.Explicit == nil || !fg.Explicit.Known {
		t.Fatalf("explicit refs not captured: %+v", fg.Explicit)
	}
	if len(fg.Explicit.Files) != 1 || fg.Explicit.Files[0] != "feature.txt" {
		t.Fatalf("explicit files = %v, want [feature.txt]", fg.Explicit.Files)
	}
	// Advance the live repo: the frozen resolution must not follow.
	writeFile(t, filepath.Join(src, "later.txt"), "l")
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-m", "later")
	fg2 := m.FrozenGitInfo()
	if fg2.Explicit == nil || len(fg2.Explicit.Files) != 1 || fg2.Explicit.Files[0] != "feature.txt" {
		t.Fatalf("frozen explicit refs moved after a live commit: %+v", fg2.Explicit)
	}
}

// TestFreezeUsesSingleTrackedIndexCapture pins item 7 structurally: the
// freeze transaction captures `git ls-files` EXACTLY ONCE. Manifest and
// copy both read that captured set; the old design re-queried the live
// index per directory (manifest) and per file (copy), so index churn
// mid-freeze could change the snapshot while the before/after manifests
// stayed identical.
func TestFreezeUsesSingleTrackedIndexCapture(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	src := t.TempDir()
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "config", "user.email", "t@example.com")
	runGit(t, src, "config", "user.name", "t")
	writeFile(t, filepath.Join(src, "app.txt"), "app")
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-m", "init")
	writeFile(t, filepath.Join(src, "dist", "asset.txt"), "tracked")
	runGit(t, src, "add", "dist/asset.txt")
	runGit(t, src, "commit", "-m", "asset")
	writeFile(t, filepath.Join(src, "dist", "scratch.bin"), "junk")
	writeFile(t, filepath.Join(src, "target", "debug", "bin"), "cargo")

	// git shim: log every invocation, then forward to the real git.
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	shimDir := t.TempDir()
	logFile := filepath.Join(t.TempDir(), "git-invocations.log")
	script := "#!/bin/sh\necho \"$@\" >> " + logFile + "\nexec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("shim log: %v", err)
	}
	lsFiles := 0
	for _, line := range strings.Split(string(blob), "\n") {
		if strings.Contains(line, "ls-files") {
			lsFiles++
		}
	}
	if lsFiles != 1 {
		t.Fatalf("git ls-files invoked %d times during Freeze, want exactly 1 (one captured index for manifest AND copy)\ninvocations:\n%s", lsFiles, blob)
	}
}

// TestFreezeManifestAndCopyShareOneInclusionSet pins item 7's stability
// claim: an untracked file churning inside a preserved skip directory
// (dist/temp.js) must NOT flip the freeze manifest — the manifest digests
// exactly what the copy takes from the captured index — while a tracked
// file's content change still must.
func TestFreezeManifestAndCopyShareOneInclusionSet(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	src := t.TempDir()
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "config", "user.email", "t@example.com")
	runGit(t, src, "config", "user.name", "t")
	writeFile(t, filepath.Join(src, "dist", "asset.txt"), "tracked")
	runGit(t, src, "add", "dist/asset.txt")
	runGit(t, src, "commit", "-m", "asset")
	writeFile(t, filepath.Join(src, "dist", "temp.js"), "untracked-v1")

	idx, err := captureTrackedIndex(t.Context(), src)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := freezeManifestIndex(src, "", idx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Churn the untracked file (bytes and mtime): manifest must hold.
	writeFile(t, filepath.Join(src, "dist", "temp.js"), "untracked-v2-changed")
	m2, err := freezeManifestIndex(src, "", idx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m1 != m2 {
		t.Fatal("untracked dist churn flipped the freeze manifest — manifest and copy do not share one inclusion set")
	}
	// Tracked content still must flip it (not over-stable).
	writeFile(t, filepath.Join(src, "dist", "asset.txt"), "tracked-changed")
	m3, err := freezeManifestIndex(src, "", idx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m3 == m2 {
		t.Fatal("tracked content change was invisible to the freeze manifest")
	}
	// The copy with the same index takes the same set.
	dst := filepath.Join(t.TempDir(), "copy")
	if err := copyTreeSkipIndex(src, dst, "", idx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "dist", "asset.txt")); err != nil {
		t.Fatalf("tracked dist file missing from indexed copy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "dist", "temp.js")); err == nil {
		t.Fatal("untracked dist file entered the indexed copy")
	}
}

// TestRunBaseSkipDirMembershipEqualsCapturedIndex pins the inclusion-set
// contract on the ARTIFACT: every file the frozen run-base carries inside
// a skip-name directory is exactly the captured-index set for that
// directory — nothing untracked slipped in (manifest-only membership), and
// nothing tracked was dropped (copy-only membership). One index, one set,
// materialized.
func TestRunBaseSkipDirMembershipEqualsCapturedIndex(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	src := t.TempDir()
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "config", "user.email", "t@example.com")
	runGit(t, src, "config", "user.name", "t")
	writeFile(t, filepath.Join(src, "seed.txt"), "s")
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-m", "init")
	// Tracked content nested under two skip-name roots, plus untracked
	// noise beside and beneath them.
	writeFile(t, filepath.Join(src, "dist", "release.js"), "r")
	writeFile(t, filepath.Join(src, "dist", "nested", "deep.txt"), "d")
	writeFile(t, filepath.Join(src, "tools", "redteam", "target", "keep.txt"), "k")
	runGit(t, src, "add", "-A")
	runGit(t, src, "commit", "-m", "tracked skip content")
	writeFile(t, filepath.Join(src, "dist", "temp.js"), "junk")
	writeFile(t, filepath.Join(src, "dist", "nested", "scratch.tmp"), "junk")
	writeFile(t, filepath.Join(src, "tools", "redteam", "target", "debug", "bin"), "cargo")
	writeFile(t, filepath.Join(src, "node_modules", "pkg", "index.js"), "vendor")

	idx, err := captureTrackedIndex(t.Context(), src)
	if err != nil {
		t.Fatal(err)
	}
	// The captured set itself: exactly the three tracked files.
	wantTracked := map[string]bool{
		"dist/release.js":               true,
		"dist/nested/deep.txt":          true,
		"tools/redteam/target/keep.txt": true,
	}
	gotTracked := map[string]bool{}
	for p := range idx.(*capturedTrackedIndex).files {
		if isUnderSkipName(p) {
			gotTracked[p] = true
		}
	}
	for p := range wantTracked {
		if !gotTracked[p] {
			t.Fatalf("captured index missing tracked skip file %q (have %v)", p, keysOfSet(gotTracked))
		}
	}
	if len(gotTracked) != len(wantTracked) {
		t.Fatalf("captured skip membership = %v, want exactly %v", keysOfSet(gotTracked), keysOfSet(wantTracked))
	}

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	base := m.BasePath()
	// Materialized set under skip-name dirs == captured set.
	materialized := map[string]bool{}
	_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(base, path)
		if rerr != nil {
			return rerr
		}
		slash := filepath.ToSlash(rel)
		if isUnderSkipName(slash) {
			materialized[slash] = true
		}
		return nil
	})
	if len(materialized) != len(wantTracked) {
		t.Fatalf("run-base skip files = %v, want exactly the tracked set %v", keysOfSet(materialized), keysOfSet(wantTracked))
	}
	for p := range wantTracked {
		if !materialized[p] {
			t.Fatalf("tracked %q missing from the run-base", p)
		}
	}
	// Untracked noise must be gone from the base...
	for _, junk := range []string{"dist/temp.js", "dist/nested/scratch.tmp", "tools/redteam/target/debug/bin", "node_modules/pkg/index.js"} {
		if _, err := os.Stat(filepath.Join(base, filepath.FromSlash(junk))); err == nil {
			t.Fatalf("untracked %q entered the run-base", junk)
		}
	}
	// ...and the job workspace is an exact copy of that set.
	dir, cleanup, err := m.Prepare(context.Background(), "job")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	assertSameFileSet(t, base, dir)
}

// isUnderSkipName reports whether slash-path lives inside one of the
// build-output directory names copyTreeSkipDirs excludes (at any depth —
// tools/redteam/target/… counts as under target/).
func isUnderSkipName(slashPath string) bool {
	padded := "/" + slashPath
	for part := range copyTreeSkipDirs {
		if strings.Contains(padded, "/"+part+"/") {
			return true
		}
	}
	return false
}

func keysOfSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assertSameFileSet fails when two trees differ in relative file content
// paths (symlinks count as entries).
func assertSameFileSet(t *testing.T, a, b string) {
	t.Helper()
	collect := func(root string) map[string]bool {
		set := map[string]bool{}
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil || rel == "." {
				return nil
			}
			set[filepath.ToSlash(rel)] = !info.IsDir()
			return nil
		})
		return set
	}
	sa, sb := collect(a), collect(b)
	for k, isFile := range sa {
		if _, ok := sb[k]; !ok {
			t.Fatalf("run-base entry %q missing from job workspace", k)
		}
		if isFile {
			if !sb[k] {
				t.Fatalf("%q is a file in the base but not in the workspace", k)
			}
			ga, errA := os.ReadFile(filepath.Join(a, filepath.FromSlash(k)))
			gb, errB := os.ReadFile(filepath.Join(b, filepath.FromSlash(k)))
			if errA != nil || errB != nil {
				t.Fatalf("read %q: %v / %v", k, errA, errB)
			}
			if string(ga) != string(gb) {
				t.Fatalf("content of %q differs between base and workspace", k)
			}
		}
	}
	for k := range sb {
		if _, ok := sa[k]; !ok {
			t.Fatalf("job workspace entry %q not present in the run-base (workspace is not an exact copy)", k)
		}
	}
}
