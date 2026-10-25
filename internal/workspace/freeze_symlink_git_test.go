package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStripLiveGitPointer: a linked-worktree .git FILE is removed from the
// frozen tree so jobs cannot re-read the live original checkout; a real
// .git directory is kept.
func TestStripLiveGitPointer(t *testing.T) {
	base := t.TempDir()
	gitFile := filepath.Join(base, ".git")
	if err := os.WriteFile(gitFile, []byte("gitdir: /live/admin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := stripLiveGitPointer(base); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(gitFile); !os.IsNotExist(err) {
		t.Fatal("linked-worktree .git file must be stripped")
	}
	gitDir := filepath.Join(base, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := stripLiveGitPointer(base); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(gitDir); err != nil || !st.IsDir() {
		t.Fatal("real .git directory must be kept")
	}
}

// TestFreezeManifestSkipsKiwiCache: once .kiwi exists, churning cache
// contents must not change the freeze stability digest (copyTree never
// copies cache into the snapshot).
func TestFreezeManifestSkipsKiwiCache(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "keep.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(src, ".kiwi", "cache")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "blob"), []byte("noise"), 0o644); err != nil {
		t.Fatal(err)
	}
	m1, err := freezeManifest(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "blob2"), []byte("more"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "blob"), []byte("rewritten"), 0o644); err != nil {
		t.Fatal(err)
	}
	m2, err := freezeManifest(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if m1 != m2 {
		t.Fatal("freezeManifest must ignore .kiwi/cache like copyTree")
	}
}

// TestMaterializeSymlinkDanglingEscapeRefused: a dangling absolute or
// ../-escaping link fails closed instead of becoming valid after Freeze.
func TestMaterializeSymlinkDanglingEscapeRefused(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.Symlink("../../outside-secrets", filepath.Join(src, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "abs"), filepath.Join(src, "abs")); err != nil {
		t.Fatal(err)
	}
	if err := materializeSymlink(filepath.Join(src, "escape"), "../../outside-secrets", src, dst, filepath.Join(dst, "escape")); err == nil {
		t.Fatal("dangling relative escape must fail closed")
	}
	link, _ := os.Readlink(filepath.Join(src, "abs"))
	if err := materializeSymlink(filepath.Join(src, "abs"), link, src, dst, filepath.Join(dst, "abs")); err == nil {
		t.Fatal("dangling absolute link must fail closed")
	}
}

// TestMaterializeSymlinkExternalFileStaysSymlink: external regular-file
// targets are snapshotted into a hidden store and the run-base entry stays
// a symlink (not a regular file).
func TestMaterializeSymlinkExternalFileStaysSymlink(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	ext := filepath.Join(t.TempDir(), "shared.conf")
	if err := os.WriteFile(ext, []byte("v=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(src, "conf")
	if err := os.Symlink(ext, linkPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dst, "conf")
	if err := materializeSymlink(linkPath, ext, src, dst, target); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("external file freeze must keep a symlink entry")
	}
	// The rewritten link must point inside dst (snapshot store).
	res, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(res) || res == ext {
		t.Fatalf("symlink must resolve to the snapshot store, got %q", res)
	}
	b, err := os.ReadFile(res)
	if err != nil || string(b) != "v=1\n" {
		t.Fatalf("snapshot content = %q err=%v", b, err)
	}
}
