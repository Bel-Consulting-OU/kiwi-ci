package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCopyTreeKeepsTrackedTargetDir pins the tools/redteam/target fix: a
// skip-named directory that carries git-tracked paths is source, not build
// output, and must survive the workspace snapshot.
func TestCopyTreeKeepsTrackedTargetDir(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "ws")
	writeFile(t, filepath.Join(src, "tools/redteam/target/keep.txt"), "tracked-source")
	writeFile(t, filepath.Join(src, "target/debug/app"), "cargo-output")

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", src}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init")
	run("add", "tools/redteam/target/keep.txt")
	run("commit", "-m", "tracked target source")

	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	kept := filepath.Join(dst, "tools/redteam/target/keep.txt")
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("tracked tools/redteam/target must be copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "target")); err == nil {
		t.Fatal("untracked cargo target/ must still be skipped")
	}
}

// TestCopyTreeKeepsTrackedDistDir pins the dist/ half of the same fix:
// release assets that are git-tracked must survive the snapshot; untracked
// dist output is still omitted.
func TestCopyTreeKeepsTrackedDistDir(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "ws")
	writeFile(t, filepath.Join(src, "dist/asset.txt"), "tracked-asset")
	writeFile(t, filepath.Join(src, "dist/scratch.bin"), "untracked-output")

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", src}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init")
	run("add", "dist/asset.txt")
	run("commit", "-m", "tracked dist asset")

	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "dist/asset.txt")); err != nil {
		t.Fatalf("tracked dist/asset.txt must be copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "dist/scratch.bin")); err == nil {
		t.Fatal("untracked dist/scratch.bin must be skipped")
	}
}

// TestCopyFilePreservesSourceMode: parent dirs are no longer forced to 0755.
func TestCopyFilePreservesSourceMode(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "ws")
	writeFile(t, filepath.Join(src, "sub/keep.txt"), "x")
	if err := os.Chmod(filepath.Join(src, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	info, err := os.Stat(filepath.Join(dst, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("sub mode = %v, want 0750 (no forced 0755)", info.Mode().Perm())
	}
}
