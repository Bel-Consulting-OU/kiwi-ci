package safefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func requireNonRootSafefs(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection does not apply to root")
	}
}

// errAfterWriter fails the callNth write (1-based) and succeeds before that.
type errAfterWriter struct {
	failOn int
	calls  int
}

func (w *errAfterWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls >= w.failOn {
		return 0, errors.New("writer refused")
	}
	return len(p), nil
}

// TestRootCloseGuards proves Close is nil-safe and releases the handle.
func TestRootCloseGuards(t *testing.T) {
	var nilRoot *Root
	if err := nilRoot.Close(); err != nil {
		t.Fatalf("nil root close = %v", err)
	}
	if err := (&Root{}).Close(); err != nil {
		t.Fatalf("root without handle close = %v", err)
	}
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Root{F: f}).Close(); err != nil {
		t.Fatalf("handle close = %v", err)
	}
	if err := f.Close(); err == nil {
		t.Fatal("handle was not closed")
	}
}

// TestOpenCanonicalizationFailure proves both root openers surface a
// canonicalization failure and release the descriptor (test seam).
func TestOpenCanonicalizationFailure(t *testing.T) {
	orig := evalSymlinks
	evalSymlinks = func(string) (string, error) { return "", errors.New("canonicalize refused") }
	defer func() { evalSymlinks = orig }()

	dir := t.TempDir()
	if _, err := OpenRootNoFollow(dir); err == nil || !strings.Contains(err.Error(), "canonicalize refused") {
		t.Fatalf("OpenRootNoFollow = %v, want canonicalization error", err)
	}
	if _, err := OpenWorkspaceRoot(dir); err == nil || !strings.Contains(err.Error(), "canonicalize refused") {
		t.Fatalf("OpenWorkspaceRoot = %v, want canonicalization error", err)
	}
}

// TestCappedWriterEmptyWrite proves an empty write under an active limit is a
// no-op.
func TestCappedWriterEmptyWrite(t *testing.T) {
	var sink bytes.Buffer
	cw := NewCappedWriter(&sink, 4)
	if n, err := cw.Write(nil); n != 0 || err != nil {
		t.Fatalf("empty write = (%d, %v)", n, err)
	}
	if n, err := cw.Write([]byte{}); n != 0 || err != nil {
		t.Fatalf("zero-length write = (%d, %v)", n, err)
	}
	// The budget is untouched.
	if n, err := cw.Write([]byte("abcd")); n != 4 || err != nil {
		t.Fatalf("full write = (%d, %v)", n, err)
	}
}

// TestExtractNilRoot proves a nil or handle-less root is rejected.
func TestExtractNilRoot(t *testing.T) {
	_, err := Extract(nil, bytes.NewReader(nil), ExtractLimits{})
	if err == nil || !strings.Contains(err.Error(), "nil extraction root") {
		t.Fatalf("nil root = %v", err)
	}
	_, err = Extract(&Root{}, bytes.NewReader(nil), ExtractLimits{})
	if err == nil || !strings.Contains(err.Error(), "nil extraction root") {
		t.Fatalf("handle-less root = %v", err)
	}
}

// TestExtractLimitBranches proves each resource bound is enforced.
func TestExtractLimitBranches(t *testing.T) {
	files := tarGz(t, []tarEntry{
		{name: "a.txt", data: bytes.Repeat([]byte("x"), 16), typeflag: tar.TypeReg},
		{name: "b.txt", data: bytes.Repeat([]byte("y"), 16), typeflag: tar.TypeReg},
	})

	// Corrupt tar stream inside a valid gzip container.
	dest := t.TempDir()
	if err := extractWith(t, gzipBytes(t, []byte(strings.Repeat("q", 4096))), dest, ExtractLimits{}); err == nil {
		t.Fatal("garbage tar must fail")
	}

	// Compressed-archive bound.
	if err := extractWith(t, files, t.TempDir(), ExtractLimits{MaxArchiveBytes: 1}); !errors.Is(err, ErrLimits) {
		t.Fatalf("archive bound = %v, want ErrLimits", err)
	}
	// Per-file bound.
	if err := extractWith(t, files, t.TempDir(), ExtractLimits{MaxFileBytes: 8}); !errors.Is(err, ErrLimits) {
		t.Fatalf("file bound = %v, want ErrLimits", err)
	}
	// Expanded bound (smaller than one entry but larger than MaxFileBytes).
	if err := extractWith(t, files, t.TempDir(), ExtractLimits{MaxFileBytes: 16, MaxExpandedBytes: 16}); !errors.Is(err, ErrLimits) {
		t.Fatalf("expanded bound = %v, want ErrLimits", err)
	}
	// Path length bound.
	long := strings.Repeat("d", 10) + "/f.txt"
	if err := extractWith(t, tarGz(t, []tarEntry{{name: long, data: []byte("x"), typeflag: tar.TypeReg}}), t.TempDir(), ExtractLimits{MaxPathLength: 3}); !errors.Is(err, ErrLimits) {
		t.Fatalf("path length bound = %v, want ErrLimits", err)
	}
	// Skip-entry copy failure: the entry is filtered out but its body is
	// truncated, so the skip read fails.
	truncated := truncatedTarGz(t, "skip.txt", 64, []byte("short"))
	limits := ExtractLimits{Allowed: []string{"other"}}
	if err := extractWith(t, truncated, t.TempDir(), limits); err == nil || !strings.Contains(err.Error(), "skip entry") {
		t.Fatalf("truncated skipped entry = %v, want skip error", err)
	}
}

// gzipBytes wraps raw bytes in a complete gzip stream.
func gzipBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// truncatedTarGz builds a tar.gz whose named entry declares size bytes but
// carries only body bytes, with a closed gzip stream.
func truncatedTarGz(t *testing.T, name string, size int64, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: size}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	// Close only the gzip stream: the tar entry never completes.
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestApplyDefaults proves zero and negative bounds fall back to defaults.
func TestApplyDefaults(t *testing.T) {
	zero := applyDefaults(ExtractLimits{})
	def := DefaultLimits()
	if zero.MaxArchiveBytes != def.MaxArchiveBytes || zero.MaxExpandedBytes != def.MaxExpandedBytes ||
		zero.MaxFileBytes != def.MaxFileBytes || zero.MaxEntries != def.MaxEntries ||
		zero.MaxPathLength != def.MaxPathLength || zero.MaxDepth != def.MaxDepth ||
		zero.MaxCompressionRatio != def.MaxCompressionRatio {
		t.Fatalf("zero limits = %+v, want %+v", zero, def)
	}
	neg := applyDefaults(ExtractLimits{
		MaxArchiveBytes: -1, MaxExpandedBytes: -1, MaxFileBytes: -1, MaxEntries: -1,
		MaxPathLength: -1, MaxDepth: -1, MaxCompressionRatio: -1,
	})
	if neg.MaxArchiveBytes != zero.MaxArchiveBytes || neg.MaxExpandedBytes != zero.MaxExpandedBytes ||
		neg.MaxFileBytes != zero.MaxFileBytes || neg.MaxEntries != zero.MaxEntries ||
		neg.MaxPathLength != zero.MaxPathLength || neg.MaxDepth != zero.MaxDepth ||
		neg.MaxCompressionRatio != zero.MaxCompressionRatio {
		t.Fatalf("negative limits = %+v, want defaults", neg)
	}
	// Explicit values are preserved.
	explicit := applyDefaults(ExtractLimits{MaxEntries: 5, MaxDepth: 2, MaxPathLength: 9, MaxCompressionRatio: 3})
	if explicit.MaxEntries != 5 || explicit.MaxDepth != 2 || explicit.MaxPathLength != 9 || explicit.MaxCompressionRatio != 3 {
		t.Fatalf("explicit limits altered: %+v", explicit)
	}
}

// TestCleanEntryNameNUL proves a NUL byte in a name is rejected.
func TestCleanEntryNameNUL(t *testing.T) {
	if _, err := cleanEntryName("a\x00b"); err == nil {
		t.Fatal("NUL byte accepted")
	}
}

// TestCheckNameComponentEmpty proves an empty component is rejected.
func TestCheckNameComponentEmpty(t *testing.T) {
	if err := checkNameComponent(""); err == nil {
		t.Fatal("empty component accepted")
	}
	// The reserved-device and suffix rules are exercised elsewhere; pin the
	// accepted boundary here.
	if err := checkNameComponent("com10"); err != nil {
		t.Fatalf("com10 rejected: %v", err)
	}
	if err := checkNameComponent("COM1"); err == nil {
		t.Fatal("COM1 accepted")
	}
}

// TestUnderAllowedBlankRoots proves blank and dot roots allow everything.
func TestUnderAllowedBlankRoots(t *testing.T) {
	for _, roots := range [][]string{{""}, {"."}, {"   "}} {
		if !underAllowed("any/path", roots) {
			t.Fatalf("roots %q must allow everything", roots)
		}
	}
	if underAllowed("b/x", []string{"a"}) {
		t.Fatal("outside root allowed")
	}
	if !underAllowed("a", []string{"a"}) || !underAllowed("a/b", []string{"a"}) {
		t.Fatal("root and descendants must be allowed")
	}
}

// TestExtractPathOpenError proves the deprecated path entry point surfaces
// open failures.
func TestExtractPathOpenError(t *testing.T) {
	if _, err := ExtractPath(filepath.Join(t.TempDir(), "missing"), bytes.NewReader(nil), ExtractLimits{}); err == nil {
		t.Fatal("missing destination accepted")
	}
}

// TestWriteTarGzShimErrors proves the deprecated shim surfaces workspace
// open failures and archives through the following writer.
func TestWriteTarGzShimErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTarGz(&buf, filepath.Join(t.TempDir(), "missing"), nil, false); err == nil {
		t.Fatal("missing workspace accepted")
	}

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "sub", "g.txt"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f.txt", filepath.Join(ws, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink("sub", filepath.Join(ws, "linkdir")); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscallMkfifo(t, filepath.Join(ws, "fifo")); err != nil {
		t.Logf("fifo unsupported: %v", err)
	}

	buf.Reset()
	if err := WriteTarGz(&buf, ws, []string{".", "link.txt", "linkdir", "missing"}, true); err != nil {
		t.Fatalf("following writer: %v", err)
	}
	entries := readTarGzEntries(t, buf.Bytes())
	if string(entries["f.txt"]) != "data" || string(entries["sub/g.txt"]) != "nested" {
		t.Fatalf("entries = %v", entries)
	}
	if _, ok := entries["fifo"]; ok {
		t.Fatal("fifo archived")
	}
	// The symlink is followed, so its target content appears under the link
	// path for a regular file target.
	if string(entries["link.txt"]) != "data" {
		t.Fatalf("followed symlink content = %q", entries["link.txt"])
	}
}

// TestWriteTarGzFollowingDanglingSymlink proves a dangling symlink capture
// root fails the legacy following writer.
func TestWriteTarGzFollowingDanglingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	ws := t.TempDir()
	if err := os.Symlink("nowhere", filepath.Join(ws, "dangling")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteTarGz(&buf, ws, []string{"dangling"}, true); err == nil {
		t.Fatal("dangling symlink root accepted")
	}
}

// TestWriteTarGzFollowingCollectErrors proves path-shape errors surface from
// the legacy collector.
func TestWriteTarGzFollowingCollectErrors(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "a"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	// A path under a regular file is not a not-exist error.
	if err := WriteTarGz(&buf, ws, []string{"file/sub"}, true); err == nil {
		t.Fatal("path under a regular file accepted")
	}
	// Duplicate capture roots are rejected.
	if err := WriteTarGz(&buf, ws, []string{"a", "a"}, true); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate roots = %v, want duplicate error", err)
	}
	// A missing path is skipped.
	buf.Reset()
	if err := WriteTarGz(&buf, ws, []string{"missing"}, true); err != nil {
		t.Fatalf("missing path: %v", err)
	}
}

// TestLegacyCollectSymlinkModes proves the legacy collector's symlink
// handling with and without following.
func TestLegacyCollectSymlinkModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "sub", "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}

	// Not following: the symlink root is skipped entirely.
	skipped, err := collect(ws, []string{"link"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped symlink root collected %+v", skipped)
	}

	// Following: the target tree is collected.
	followed, err := collect(ws, []string{"link"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(followed) == 0 {
		t.Fatal("followed symlink root collected nothing")
	}
}

// TestLegacyCollectReadDirError proves an unreadable directory surfaces from
// the legacy walker.
func TestLegacyCollectReadDirError(t *testing.T) {
	testutil.UnixChmod(t)
	requireNonRootSafefs(t)
	ws := t.TempDir()
	locked := filepath.Join(ws, "sub", "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if _, err := collect(ws, []string{"sub"}, true); err == nil {
		t.Fatal("unreadable directory collected without error")
	}
}

// TestWriteTarGzFollowingOpenError proves an unreadable regular file fails
// the legacy writer (non-root).
func TestWriteTarGzFollowingOpenError(t *testing.T) {
	testutil.UnixChmod(t)
	requireNonRootSafefs(t)
	ws := t.TempDir()
	locked := filepath.Join(ws, "locked.txt")
	if err := os.WriteFile(locked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
	var buf bytes.Buffer
	if err := WriteTarGz(&buf, ws, []string{"locked.txt"}, true); err == nil {
		t.Fatal("unreadable file archived")
	}
}

// TestLegacyWriterSinkFailures proves writer failures surface from the
// legacy writer at write, tar-close, and gzip-close stages.
func TestLegacyWriterSinkFailures(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "big"), bytes.Repeat([]byte("x"), 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "small"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][]string{{"big"}, {"small"}, {}} {
		for failOn := 1; failOn <= 3; failOn++ {
			w := &errAfterWriter{failOn: failOn}
			if err := WriteTarGz(w, ws, paths, true); err == nil {
				t.Fatalf("paths=%v failOn=%d: writer failure not surfaced", paths, failOn)
			}
		}
	}
}

// TestWriteTarGzFromRootEntriesNilRoot proves the nil-root guard.
func TestWriteTarGzFromRootEntriesNilRoot(t *testing.T) {
	if _, err := WriteTarGzFromRootEntries(io.Discard, nil, nil); err == nil {
		t.Fatal("nil root accepted")
	}
}

// TestWriteTarGzFromRootEntriesZeroValueRoot proves a zero-value
// WorkspaceRoot (nil embedded *Root) and a handle-less root are rejected
// with the guard error instead of panicking.
func TestWriteTarGzFromRootEntriesZeroValueRoot(t *testing.T) {
	for name, root := range map[string]*WorkspaceRoot{
		"zero value":      {},
		"nil embedded":    {Root: nil},
		"nil handle":      {Root: &Root{}},
		"nil handle file": {Root: &Root{F: nil}},
	} {
		files, err := WriteTarGzFromRootEntries(io.Discard, root, nil)
		if err == nil {
			t.Fatalf("%s: nil workspace root accepted", name)
		}
		if files != nil {
			t.Fatalf("%s: files = %v, want nil", name, files)
		}
		if !strings.Contains(err.Error(), "nil workspace root") {
			t.Fatalf("%s: error = %v, want nil workspace root", name, err)
		}
	}
	if err := WriteTarGzFromRoot(io.Discard, &WorkspaceRoot{}, nil); err == nil {
		t.Fatal("WriteTarGzFromRoot(zero-value root) accepted")
	}
}

// TestWriteTarGzFromRootCollectErrors proves the root-anchored collector's
// path-shape errors and skips.
func TestWriteTarGzFromRootCollectErrors(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "sub", "f.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "a"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink("sub", filepath.Join(ws, "link")); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscallMkfifo(t, filepath.Join(ws, "fifo")); err != nil {
		t.Logf("fifo unsupported: %v", err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	// Non-empty relative capture root.
	var buf bytes.Buffer
	files, err := WriteTarGzFromRootEntries(&buf, root, []string{"sub"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "sub/f.txt" {
		t.Fatalf("files = %+v", files)
	}
	entries := readTarGzEntries(t, buf.Bytes())
	if string(entries["sub/f.txt"]) != "payload" {
		t.Fatalf("entry content = %q", entries["sub/f.txt"])
	}

	// Missing path is skipped.
	buf.Reset()
	if _, err := WriteTarGzFromRootEntries(&buf, root, []string{"missing"}); err != nil {
		t.Fatalf("missing path: %v", err)
	}
	// Path under a regular file is an error.
	if _, err := WriteTarGzFromRootEntries(io.Discard, root, []string{"file/sub"}); err == nil {
		t.Fatal("path under a file accepted")
	}
	// Duplicate roots are rejected.
	if _, err := WriteTarGzFromRootEntries(io.Discard, root, []string{"a", "a"}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate roots = %v, want duplicate error", err)
	}
	// A symlinked capture root is skipped without error.
	buf.Reset()
	if _, err := WriteTarGzFromRootEntries(&buf, root, []string{"link"}); err != nil {
		t.Fatalf("symlink root: %v", err)
	}
	if len(buf.Bytes()) == 0 {
		t.Fatal("empty archive not written")
	}
	// Special files inside a captured tree are skipped.
	buf.Reset()
	if _, err := WriteTarGzFromRootEntries(&buf, root, []string{"."}); err != nil {
		t.Fatalf("full tree: %v", err)
	}
	if _, ok := readTarGzEntries(t, buf.Bytes())["fifo"]; ok {
		t.Fatal("fifo archived")
	}
}

// TestWriteTarGzFromRootCollectWalkError proves an unreadable directory
// surfaces from the root-anchored collector (non-root).
func TestWriteTarGzFromRootCollectWalkError(t *testing.T) {
	testutil.UnixChmod(t)
	requireNonRootSafefs(t)
	ws := t.TempDir()
	locked := filepath.Join(ws, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := WriteTarGzFromRootEntries(io.Discard, root, []string{"."}); err == nil {
		t.Fatal("unreadable directory archived without error")
	}
}

// TestWriteTarGzFromRootCopyCloseSeams proves the post-copy close failure and
// short-entry-read guard (test seams).
func TestWriteTarGzFromRootCopyCloseSeams(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	origClose := closeEntryFile
	closeEntryFile = func(*os.File) error { return errors.New("close refused") }
	_, err = WriteTarGzFromRootEntries(io.Discard, root, []string{"f"})
	closeEntryFile = origClose
	if err == nil || !strings.Contains(err.Error(), "close refused") {
		t.Fatalf("close failure = %v", err)
	}

	origCopy := copyEntryBytes
	copyEntryBytes = func(io.Writer, io.Reader, int64) (int64, error) { return 0, errors.New("copy refused") }
	_, err = WriteTarGzFromRootEntries(io.Discard, root, []string{"f"})
	copyEntryBytes = func(dst io.Writer, src io.Reader, n int64) (int64, error) { return n - 1, nil }
	_, err2 := WriteTarGzFromRootEntries(io.Discard, root, []string{"f"})
	copyEntryBytes = origCopy
	if err == nil || !strings.Contains(err.Error(), "copy refused") {
		t.Fatalf("copy failure = %v", err)
	}
	if err2 == nil || !strings.Contains(err2.Error(), "short read") {
		t.Fatalf("short read = %v", err2)
	}
}

// TestWriteTarGzFromRootSinkFailures proves writer failures surface from the
// root-anchored writer at tar-close and gzip-close stages.
func TestWriteTarGzFromRootSinkFailures(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "big"), bytes.Repeat([]byte("x"), 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "small"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, paths := range [][]string{{"big"}, {"small"}, {}} {
		for failOn := 1; failOn <= 3; failOn++ {
			w := &errAfterWriter{failOn: failOn}
			if _, err := WriteTarGzFromRootEntries(w, root, paths); err == nil {
				t.Fatalf("paths=%v failOn=%d: writer failure not surfaced", paths, failOn)
			}
		}
	}
}

// TestFitsAvailable proves the free-space checker: statfs failures, the
// quota bound, and the default-accept case.
func TestFitsAvailable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if err := FitsAvailable(missing, 0); err == nil {
		t.Fatal("statfs on a missing path must fail")
	}
	dir := t.TempDir()
	if err := FitsAvailable(dir, 0); err != nil {
		t.Fatalf("normal filesystem rejected: %v", err)
	}
	if err := FitsAvailable(dir, math.MaxInt64); err == nil {
		t.Fatal("impossible quota accepted")
	}
	if err := FitsAvailable(dir, 1); err != nil {
		t.Fatalf("tiny quota rejected: %v", err)
	}
}

// TestValidateRelNUL proves OpenRel rejects a NUL byte before any syscall.
func TestValidateRelNUL(t *testing.T) {
	root, err := OpenWorkspaceRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.OpenRel("a\x00b"); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("NUL path = %v, want NUL error", err)
	}
}

// TestOpenRelWalkError proves a missing relative path surfaces from the
// component walk.
func TestOpenRelWalkError(t *testing.T) {
	root, err := OpenWorkspaceRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.OpenRel("missing.txt"); err == nil {
		t.Fatal("missing path opened")
	}
}

// TestExtractLongNameMkdirErrors proves over-long path components surface
// from the creation helpers.
func TestExtractLongNameMkdirErrors(t *testing.T) {
	long := strings.Repeat("a", 300)
	// A directory entry with an over-long component: the final mkdirat fails.
	dirArchive := tarGz(t, []tarEntry{{name: long + "/", typeflag: tar.TypeDir}})
	if err := extract(t, dirArchive, t.TempDir()); err == nil {
		t.Fatal("over-long directory component accepted")
	}
	// A file entry whose missing parent has an over-long component: the
	// parent mkdirat fails first.
	fileArchive := tarGz(t, []tarEntry{{name: long + "/f.txt", data: []byte("x"), typeflag: tar.TypeReg}})
	if err := extract(t, fileArchive, t.TempDir()); err == nil {
		t.Fatal("over-long parent component accepted")
	}
}

// TestExtractExistingEntryConflicts proves pre-existing symlinks and files at
// archive paths are surfaced as errors instead of being followed or merged.
func TestExtractExistingEntryConflicts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	outside := t.TempDir()

	// Directory entry over an existing symlink.
	dest := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dest, "s")); err != nil {
		t.Fatal(err)
	}
	if err := extract(t, tarGz(t, []tarEntry{{name: "s/", typeflag: tar.TypeDir}}), dest); err == nil {
		t.Fatal("directory over symlink accepted")
	}

	// File entry over an existing symlink.
	dest2 := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "target"), filepath.Join(dest2, "s")); err != nil {
		t.Fatal(err)
	}
	if err := extract(t, tarGz(t, []tarEntry{{name: "s", data: []byte("pwned"), typeflag: tar.TypeReg}}), dest2); err == nil {
		t.Fatal("file over symlink accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "target")); !os.IsNotExist(err) {
		t.Fatal("content written through the symlink")
	}

	// File entry over an existing regular file (O_EXCL).
	dest3 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest3, "f"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extract(t, tarGz(t, []tarEntry{{name: "f", data: []byte("new"), typeflag: tar.TypeReg}}), dest3); err == nil {
		t.Fatal("file over an existing file accepted")
	}
}

// TestExtractFileOpenPermissionError proves a non-O_EXCL OS failure surfaces
// from the file creation (non-root).
func TestExtractFileOpenPermissionError(t *testing.T) {
	testutil.UnixChmod(t)
	requireNonRootSafefs(t)
	dest := t.TempDir()
	if err := os.Chmod(dest, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dest, 0o755) })
	if err := extract(t, tarGz(t, []tarEntry{{name: "f", data: []byte("x"), typeflag: tar.TypeReg}}), dest); err == nil {
		t.Fatal("unwritable destination accepted a file")
	}
}

// TestExtractMkdirParentConflict proves a directory entry whose parent is a
// regular file fails before any write.
func TestExtractMkdirParentConflict(t *testing.T) {
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "parent"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extract(t, tarGz(t, []tarEntry{{name: "parent/child/", typeflag: tar.TypeDir}}), dest); err == nil {
		t.Fatal("directory under a regular file accepted")
	}
}

// TestExtractMkdirPermissionError proves a mkdirat failure other than EEXIST
// surfaces (non-root, read-only destination).
func TestExtractMkdirPermissionError(t *testing.T) {
	testutil.UnixChmod(t)
	requireNonRootSafefs(t)
	dest := t.TempDir()
	if err := os.Chmod(dest, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dest, 0o755) })
	if err := extract(t, tarGz(t, []tarEntry{{name: "sub/f.txt", data: []byte("x"), typeflag: tar.TypeReg}}), dest); err == nil {
		t.Fatal("missing parent created in a read-only destination")
	}
}

// TestExtractTruncatedEntry proves a truncated regular entry fails the
// extraction copy.
func TestExtractTruncatedEntry(t *testing.T) {
	data := truncatedTarGz(t, "f.txt", 64, []byte("short"))
	if err := extract(t, data, t.TempDir()); err == nil {
		t.Fatal("truncated entry accepted")
	}
}

// TestExtractDirOverExistingFile proves a directory entry colliding with an
// existing regular file fails.
func TestExtractDirOverExistingFile(t *testing.T) {
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "d"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extract(t, tarGz(t, []tarEntry{{name: "d/f", data: []byte("x"), typeflag: tar.TypeReg}}), dest); err == nil {
		t.Fatal("file under an existing regular directory path accepted")
	}
}

// TestExtractSymlinkParentDeep proves a symlink parent below the capture
// path fails (non-final component).
func TestExtractSymlinkParentDeep(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	dest := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dest, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dest, "sub", "link")); err != nil {
		t.Fatal(err)
	}
	if err := extract(t, tarGz(t, []tarEntry{{name: "sub/link/evil", data: []byte("x"), typeflag: tar.TypeReg}}), dest); err == nil {
		t.Fatal("deep symlink parent accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "evil")); !os.IsNotExist(err) {
		t.Fatal("content escaped through the symlink")
	}
}

// TestExtractMkdirOverExistingSymlink proves a directory entry over an
// existing symlink is rejected at the no-follow reopen.
func TestExtractMkdirOverExistingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	dest := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(dest, "link")); err != nil {
		t.Fatal(err)
	}
	if err := extract(t, tarGz(t, []tarEntry{{name: "link/", typeflag: tar.TypeDir}}), dest); err == nil {
		t.Fatal("mkdir over symlink accepted")
	}
}

// TestWriteTarGzFromRootEmptyRel proves the "./" skip path in both writers.
func TestWriteTarGzFromRootEmptyRel(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var buf bytes.Buffer
	if err := WriteTarGz(&buf, ws, []string{"."}, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := readTarGzEntries(t, buf.Bytes())["./"]; ok {
		t.Fatal("root entry written")
	}
	buf.Reset()
	if _, err := WriteTarGzFromRootEntries(&buf, root, []string{""}); err != nil {
		t.Fatal(err)
	}
	if _, ok := readTarGzEntries(t, buf.Bytes())[""]; ok {
		t.Fatal("empty-name entry written")
	}
}

// TestCollectRootAndEscapeGuards pins the escape guards' defensive shapes.
func TestCollectRootAndEscapeGuards(t *testing.T) {
	// A path that cleans to the workspace root is equivalent to ".".
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	entries, err := collectFromRoot(root, []string{"./f"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].rel != "f" {
		t.Fatalf("entries = %+v", entries)
	}
	if _, err := collectFromRoot(root, []string{""}); err != nil {
		t.Fatal(err)
	}
}

// TestErrorFormatting covers the exported sentinels' identities.
func TestErrorFormatting(t *testing.T) {
	for _, err := range []error{ErrSymlinkParent, ErrUnsafeEntry, ErrDuplicateEntry, ErrLimits, ErrCompression, ErrCapExceeded, ErrNotRegular} {
		if err == nil || err.Error() == "" {
			t.Fatalf("empty sentinel: %v", err)
		}
	}
	if !errors.Is(fmt.Errorf("wrap: %w", ErrLimits), ErrLimits) {
		t.Fatal("sentinel wrapping broken")
	}
}
