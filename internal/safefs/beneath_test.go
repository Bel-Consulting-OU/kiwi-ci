package safefs

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestOpenRootBeneathRejectsSymlinkedAncestor proves a symlink in a parent
// component of the destination is rejected outright and nothing is created
// through it, even though the symlink resolves to a real directory.
func TestOpenRootBeneathRejectsSymlinkedAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	ws := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(ws, "evil")); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := OpenRootBeneath(root.Root, "evil/.ssh"); !errors.Is(err, ErrSymlinkParent) {
		t.Fatalf("symlinked ancestor = %v, want ErrSymlinkParent", err)
	}
	if _, err := os.Stat(filepath.Join(outside, ".ssh")); !os.IsNotExist(err) {
		t.Fatal("directory created through a symlinked ancestor")
	}
}

// TestOpenRootBeneathRejectsSymlinkedFinal proves a symlink in the final
// component is rejected instead of opened as the extraction root.
func TestOpenRootBeneathRejectsSymlinkedFinal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	ws := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(ws, "evil")); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := OpenRootBeneath(root.Root, "evil"); !errors.Is(err, ErrSymlinkParent) {
		t.Fatalf("symlinked destination = %v, want ErrSymlinkParent", err)
	}
}

// TestOpenRootBeneathTOCTOUBarrier proves the returned root is anchored to the
// held descriptor: swapping a validated ancestor for a symlink after the walk
// must not redirect a later extraction.
func TestOpenRootBeneathTOCTOUBarrier(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink/rename swap needs unix semantics")
	}
	ws := t.TempDir()
	outside := t.TempDir()
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	dest, err := OpenRootBeneath(root.Root, "deps")
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// The attacker swaps the validated destination for a symlink to an
	// outside directory after the check.
	if err := os.Rename(filepath.Join(ws, "deps"), filepath.Join(ws, "deps-held")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ws, "deps")); err != nil {
		t.Fatal(err)
	}

	data := tarGz(t, []tarEntry{{name: "payload.txt", data: []byte("safe"), typeflag: tar.TypeReg}})
	limits := DefaultLimits()
	limits.AllowAll = true
	if _, err := Extract(dest, bytes.NewReader(data), limits); err != nil {
		t.Fatalf("extract through held root: %v", err)
	}
	// The held descriptor still addresses the original directory (now named
	// deps-held); the symlink target is untouched.
	if b, err := os.ReadFile(filepath.Join(ws, "deps-held", "payload.txt")); err != nil || string(b) != "safe" {
		t.Fatalf("held-directory content = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "payload.txt")); !os.IsNotExist(err) {
		t.Fatal("extraction escaped through the swapped symlink")
	}
}

// TestOpenRootBeneathNestedNormalPath proves normal nested destinations are
// still created and returned, and that "" resolves to the root itself.
func TestOpenRootBeneathNestedNormalPath(t *testing.T) {
	ws := t.TempDir()
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	dest, err := OpenRootBeneath(root.Root, "a/b/c")
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	fi, err := os.Stat(filepath.Join(ws, "a", "b", "c"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("nested destination not created: %v", err)
	}
	if dest.Canonical != filepath.Join(root.Canonical, "a", "b", "c") {
		t.Fatalf("canonical = %q", dest.Canonical)
	}

	same, err := OpenRootBeneath(root.Root, "")
	if err != nil {
		t.Fatal(err)
	}
	defer same.Close()
	if same.Canonical != root.Canonical {
		t.Fatalf("root-relative canonical = %q, want %q", same.Canonical, root.Canonical)
	}
	if _, err := OpenRootBeneath(root.Root, "."); err != nil {
		t.Fatalf("dot destination = %v", err)
	}
}

// TestOpenRootBeneathRejectsUnsafe proves absolute paths, parent traversal,
// backslashes and NUL bytes are rejected before any syscall.
func TestOpenRootBeneathRejectsUnsafe(t *testing.T) {
	ws := t.TempDir()
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, rel := range []string{"../x", "a/../../x", "/abs", `a\b`, "a\x00b"} {
		if _, err := OpenRootBeneath(root.Root, rel); err == nil {
			t.Errorf("relative path %q accepted", rel)
		}
	}
	if _, err := OpenRootBeneath(nil, ""); err == nil {
		t.Fatal("nil root accepted")
	}
	if _, err := OpenRootBeneath(&Root{}, ""); err == nil {
		t.Fatal("handle-less root accepted")
	}
}
