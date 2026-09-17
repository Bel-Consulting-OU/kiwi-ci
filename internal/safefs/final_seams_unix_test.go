//go:build !windows

package safefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFinalExtractExpandedLimit(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxExpandedBytes = 1024
	lim.MaxFileBytes = 1 << 20
	lim.MaxArchiveBytes = 1 << 20
	data := tarGz(t, []tarEntry{{name: "big.bin", data: bytes.Repeat([]byte("x"), 4096), typeflag: tar.TypeReg}})
	if err := extractWith(t, data, t.TempDir(), lim); !errors.Is(err, ErrLimits) {
		t.Fatalf("expanded limit = %v, want ErrLimits", err)
	}
}

// TestFinalCollectRejectsTraversal pins the containment checks in both
// capture collectors: a caller-supplied path that cleans outside the
// workspace is refused, never archived.
func TestFinalCollectRejectsTraversal(t *testing.T) {
	parent := t.TempDir()
	ws := filepath.Join(parent, "ws")
	if err := os.Mkdir(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "outside.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var buf bytes.Buffer
	if _, err := WriteTarGzFromRootEntries(&buf, root, []string{"../outside.txt"}); err == nil || !strings.Contains(err.Error(), "escapes workspace") {
		t.Fatalf("root-anchored traversal = %v", err)
	}
	if err := WriteTarGz(&buf, ws, []string{"../outside.txt"}, true); err == nil || !strings.Contains(err.Error(), "escapes workspace") {
		t.Fatalf("legacy traversal = %v", err)
	}
}

// TestFinalCaptureDirectoryDeterministically walks a directory capture root
// so the walk callback's directory arm is exercised regardless of the
// hardening tests' intentional mutation races.
func TestFinalCaptureDirectoryDeterministically(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "sub", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "sub", "deep", "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var buf bytes.Buffer
	files, err := WriteTarGzFromRootEntries(&buf, root, []string{"."})
	if err != nil {
		t.Fatalf("directory capture: %v", err)
	}
	names := map[string]bool{}
	gz, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names[h.Name] = true
	}
	for _, want := range []string{"sub/", "sub/deep/", "sub/deep/f.txt"} {
		if !names[want] {
			t.Fatalf("archive entries %v missing %q", names, want)
		}
	}
	if len(files) != 1 || files[0].Path != "sub/deep/f.txt" {
		t.Fatalf("archive files = %+v", files)
	}
}

// failingInfoEntry is a directory entry whose metadata read fails, modelling
// an entry removed between the directory read and the info lookup.
type failingInfoEntry struct{}

func (failingInfoEntry) Name() string               { return "ghost" }
func (failingInfoEntry) IsDir() bool                { return false }
func (failingInfoEntry) Type() fs.FileMode          { return 0 }
func (failingInfoEntry) Info() (os.FileInfo, error) { return nil, fmt.Errorf("entry vanished") }

func TestFinalSeamWalkEntryInfoRaceGuard(t *testing.T) {
	ws := t.TempDir()
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	orig := walkDirFn
	walkDirFn = func(walkRoot string, fn fs.WalkDirFunc) error {
		return fn(filepath.Join(root.Canonical, "ghost"), failingInfoEntry{}, nil)
	}
	t.Cleanup(func() { walkDirFn = orig })
	if _, err := collectFromRoot(root, []string{"."}); err == nil || !strings.Contains(err.Error(), "entry vanished") {
		t.Fatalf("vanished entry = %v, want the info error", err)
	}
}

func TestFinalSeamArchiveEntryStat(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	orig := statArchiveEntry
	t.Cleanup(func() { statArchiveEntry = orig })

	statArchiveEntry = func(*os.File) (os.FileInfo, error) { return nil, fmt.Errorf("stat refused") }
	if _, err := WriteTarGzFromRootEntries(&bytes.Buffer{}, root, []string{"file.txt"}); err == nil || !strings.Contains(err.Error(), "stat refused") {
		t.Fatalf("stat failure = %v", err)
	}

	dirInfo, err := os.Stat(ws)
	if err != nil {
		t.Fatal(err)
	}
	statArchiveEntry = func(*os.File) (os.FileInfo, error) { return dirInfo, nil }
	if _, err := WriteTarGzFromRootEntries(&bytes.Buffer{}, root, []string{"file.txt"}); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("non-regular entry = %v, want ErrNotRegular", err)
	}
}

func TestFinalSeamFoldCaseSensitive(t *testing.T) {
	orig := foldCaseInsensitive
	foldCaseInsensitive = false
	t.Cleanup(func() { foldCaseInsensitive = orig })
	if got := foldPath("MiXeD"); got != "MiXeD" {
		t.Fatalf("case-sensitive fold = %q", got)
	}
	foldCaseInsensitive = true
	if got := foldPath("MiXeD"); got != "mixed" {
		t.Fatalf("case-insensitive fold = %q", got)
	}
}

func TestFinalMkdirNoFollowEmptyComponentAndSymlinkBase(t *testing.T) {
	ws := t.TempDir()
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// An empty path component is skipped rather than passed to mkdirat.
	if err := mkdirNoFollow(root.Root, "a//b"); err != nil {
		t.Fatalf("mkdirNoFollow with an empty component: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(ws, "a", "b")); err != nil || !fi.IsDir() {
		t.Fatalf("directory not created: %v", err)
	}
	// A symlink as the final component is refused after the mkdirat EEXIST.
	// Measured on darwin: the O_DIRECTORY|O_NOFOLLOW re-open of a symlink
	// reports ENOTDIR, not ELOOP, so the ELOOP->ErrSymlinkParent mapping in
	// mkdirNoFollow cannot fire here (it is the Linux shape).
	if err := os.Mkdir(filepath.Join(ws, "target"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ws, "target"), filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	err = mkdirNoFollow(root.Root, "link")
	if err == nil {
		t.Fatal("symlink base accepted")
	}
	if !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, ErrSymlinkParent) {
		t.Fatalf("symlink base = %v, want ENOTDIR (darwin) or ErrSymlinkParent", err)
	}
}

func TestFinalSeamOpenatReopenFailures(t *testing.T) {
	ws := t.TempDir()
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	orig := openatFn
	t.Cleanup(func() { openatFn = orig })

	// A component that appears as a symlink between the failed openat and the
	// mkdirat: the re-open reports ELOOP and is mapped to ErrSymlinkParent.
	calls := 0
	openatFn = func(dirfd int, path string, flags int, mode uint32) (int, error) {
		calls++
		switch calls {
		case 1:
			return -1, unix.ENOENT
		case 2:
			return -1, unix.ELOOP
		}
		return unix.Openat(dirfd, path, flags, mode)
	}
	if _, err := openParentChain(root.Root, "race/sub"); !errors.Is(err, ErrSymlinkParent) {
		t.Fatalf("re-open ELOOP = %v, want ErrSymlinkParent", err)
	}

	calls = 0
	openatFn = func(dirfd int, path string, flags int, mode uint32) (int, error) {
		calls++
		switch calls {
		case 1:
			return -1, unix.ENOENT
		case 2:
			return -1, unix.ENOTDIR
		}
		return unix.Openat(dirfd, path, flags, mode)
	}
	if _, err := openParentChain(root.Root, "race/sub"); !errors.Is(err, unix.ENOTDIR) {
		t.Fatalf("re-open ENOTDIR = %v, want ENOTDIR", err)
	}

	// A symlink loop as an intermediate component reports ELOOP on platforms
	// that resolve the loop (Linux); darwin's O_NOFOLLOW shape reports
	// ENOTDIR instead, so the seam supplies the platform's errno.
	calls = 0
	openatFn = func(dirfd int, path string, flags int, mode uint32) (int, error) {
		calls++
		if calls == 1 {
			return -1, unix.ELOOP
		}
		return unix.Openat(dirfd, path, flags, mode)
	}
	if _, err := openParentChain(root.Root, "loop/sub"); !errors.Is(err, ErrSymlinkParent) {
		t.Fatalf("first-open ELOOP = %v, want ErrSymlinkParent", err)
	}

	// The final-component O_NOFOLLOW|O_DIRECTORY re-open in mkdirNoFollow:
	// ELOOP maps to ErrSymlinkParent.
	if err := os.Mkdir(filepath.Join(ws, "target2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ws, "target2"), filepath.Join(ws, "link2")); err != nil {
		t.Fatal(err)
	}
	openatFn = func(dirfd int, path string, flags int, mode uint32) (int, error) {
		return -1, unix.ELOOP
	}
	if err := mkdirNoFollow(root.Root, "link2"); !errors.Is(err, ErrSymlinkParent) {
		t.Fatalf("mkdir re-open ELOOP = %v, want ErrSymlinkParent", err)
	}
}

func TestFinalVerifiedFileBadDescriptor(t *testing.T) {
	root, err := OpenWorkspaceRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.verifiedFile(-1, "rel"); err == nil {
		t.Fatal("fstat on a bad descriptor accepted")
	}
}

// TestFinalSeamOpenRelPlatform exercises the openat2 platform fast path
// branches on a host without openat2: the error, the success (verified) and
// the unhandled-fallback shapes.
func TestFinalSeamOpenRelPlatform(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	orig := openRelPlatformHook
	t.Cleanup(func() { openRelPlatformHook = orig })

	openRelPlatformHook = func(int, string) (int, bool, error) {
		return -1, true, unix.ENXIO
	}
	if _, err := root.OpenRel("file.txt"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("mapped platform error = %v, want ErrNotRegular", err)
	}

	openRelPlatformHook = func(rootFd int, rel string) (int, bool, error) {
		fd, err := unix.Openat(rootFd, rel, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, true, err
		}
		return fd, true, nil
	}
	f, err := root.OpenRel("file.txt")
	if err != nil {
		t.Fatalf("platform fast path: %v", err)
	}
	_ = f.Close()

	openRelPlatformHook = func(int, string) (int, bool, error) {
		return -1, false, unix.EPERM
	}
	if _, err := root.OpenRel("file.txt"); !errors.Is(err, unix.EPERM) {
		t.Fatalf("unhandled platform error = %v, want EPERM", err)
	}
}

func TestFinalSeamStatfsLowFreeSpace(t *testing.T) {
	orig := statfsFn
	statfsFn = func(string, *syscall.Statfs_t) error {
		return nil
	}
	t.Cleanup(func() { statfsFn = orig })
	if err := FitsAvailable(t.TempDir(), 0); err != nil {
		t.Fatalf("empty statfs: %v", err)
	}

	orig2 := statfsFn
	statfsFn = func(_ string, st *syscall.Statfs_t) error {
		st.Blocks = 1000
		st.Bavail = 10
		st.Bsize = 4096
		return nil
	}
	t.Cleanup(func() { statfsFn = orig2 })
	if err := FitsAvailable(t.TempDir(), 0); err == nil || !strings.Contains(err.Error(), "less than 5% free space") {
		t.Fatalf("low free space = %v", err)
	}
}
