package snapshot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

func requireNonRootSnapshot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection does not apply to root")
	}
}

// TestManifestForOpenWorkspaceErrors proves a missing or non-directory
// workspace is rejected before any enumeration.
func TestManifestForOpenWorkspaceErrors(t *testing.T) {
	if _, err := ManifestFor(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing workspace must fail")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ManifestFor(file); err == nil {
		t.Fatal("file workspace must fail")
	}
}

// TestManifestForUnreadableDir proves a walk error surfaces (and that the
// walk error path is reported once).
func TestManifestForUnreadableDir(t *testing.T) {
	testutil.UnixChmod(t)
	requireNonRootSnapshot(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "locked"), 0o755); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(root, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if _, err := ManifestFor(root); err == nil {
		t.Fatal("unreadable subdirectory must fail the walk")
	}
}

// TestManifestForUnreadableFile proves an unopenable regular file surfaces
// from the no-follow open.
func TestManifestForUnreadableFile(t *testing.T) {
	testutil.UnixChmod(t)
	requireNonRootSnapshot(t)
	root := t.TempDir()
	locked := filepath.Join(root, "locked.txt")
	if err := os.WriteFile(locked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
	if _, err := ManifestFor(root); err == nil {
		t.Fatal("unreadable file must fail the manifest")
	}
}

func gzBytes(t *testing.T, raw []byte) []byte {
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

// TestParseDecodeErrors proves non-gzip input and corrupt tar streams are
// rejected.
func TestParseDecodeErrors(t *testing.T) {
	if _, err := Parse(bytes.NewReader([]byte("not gzip"))); err == nil {
		t.Fatal("non-gzip input must fail")
	}
	if _, err := Parse(bytes.NewReader(gzBytes(t, []byte(strings.Repeat("q", 4096))))); err == nil {
		t.Fatal("garbage tar stream must fail")
	}
}

// TestParseExpandedBudget proves the cumulative expanded-bytes bound is
// enforced across entries.
func TestParseExpandedBudget(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := 0; i < 3; i++ {
		if err := tw.WriteHeader(&tar.Header{Name: "f" + string(rune('a'+i)), Typeflag: tar.TypeReg, Mode: 0o644, Size: 4}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("aaaa")); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	limits := safefs.ExtractLimits{MaxExpandedBytes: 8, MaxFileBytes: 4}
	if _, err := ParseWithLimits(bytes.NewReader(buf.Bytes()), limits); err == nil || !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("expanded budget = %v, want ErrLimits", err)
	}
	// Exactly at the budget passes.
	limits = safefs.ExtractLimits{MaxExpandedBytes: 12, MaxFileBytes: 4}
	if _, err := ParseWithLimits(bytes.NewReader(buf.Bytes()), limits); err != nil {
		t.Fatalf("at budget: %v", err)
	}
}

// TestParseTruncatedEntry proves an entry whose declared body is cut short
// is rejected while hashing.
func TestParseTruncatedEntry(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 64}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	// Close only the gzip stream: the tar entry never completes.
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("truncated entry must fail")
	}
}

// TestRestoreArgumentErrors proves the empty destination, uncreatable
// destination, and symlinked destination are all rejected.
func TestRestoreArgumentErrors(t *testing.T) {
	valid, _ := makeArchive(t, map[string]string{"a.txt": "x"})

	if _, err := Restore(bytes.NewReader(valid), ""); err == nil {
		t.Fatal("empty destination must fail")
	}

	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(bytes.NewReader(valid), filepath.Join(blocker, "dest")); err == nil {
		t.Fatal("destination under a regular file must fail")
	}

	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(bytes.NewReader(valid), link); err == nil {
		t.Fatal("symlinked destination must fail")
	}

	// Valid destination still works.
	if _, err := Restore(bytes.NewReader(valid), t.TempDir()); err != nil {
		t.Fatalf("valid restore: %v", err)
	}
}

// TestRestoreManifestFailure proves a manifest failure after a successful
// extraction is reported as such (injected through the test seam).
func TestRestoreManifestFailure(t *testing.T) {
	valid, _ := makeArchive(t, map[string]string{"a.txt": "x"})
	orig := manifestAfterRestore
	manifestAfterRestore = func(string) (Manifest, error) { return Manifest{}, errors.New("manifest refused") }
	defer func() { manifestAfterRestore = orig }()
	if _, err := Restore(bytes.NewReader(valid), t.TempDir()); err == nil || !strings.Contains(err.Error(), "manifest after restore") {
		t.Fatalf("manifest failure = %v, want wrapped error", err)
	}
}

// fakeEntry is a synthetic os.DirEntry for exercising the walk callback.
type fakeEntry struct {
	name string
	dir  bool
	mod  os.FileMode
	info os.FileInfo
	err  error
}

func (f fakeEntry) Name() string               { return f.name }
func (f fakeEntry) IsDir() bool                { return f.dir }
func (f fakeEntry) Type() os.FileMode          { return f.mod }
func (f fakeEntry) Info() (os.FileInfo, error) { return f.info, f.err }

// fakeInfo is a regular-file FileInfo for synthetic entries.
type fakeInfo struct{}

func (fakeInfo) Name() string       { return "f" }
func (fakeInfo) Size() int64        { return 1 }
func (fakeInfo) Mode() os.FileMode  { return 0o644 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (fakeInfo) Sys() any           { return nil }

// TestCollectEntriesSyntheticEntryShapes drives the walk callback with entry
// shapes a real filesystem cannot produce deterministically: a symlinked
// directory (skipped as a subtree), a regular file whose metadata cannot be
// read, and a path that escapes the canonical root.
func TestCollectEntriesSyntheticEntryShapes(t *testing.T) {
	root := t.TempDir()
	canon, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	orig := walkDir
	defer func() { walkDir = orig }()

	run := func(steps ...struct {
		path string
		d    os.DirEntry
		err  error
	}) error {
		walkDir = func(r string, fn fs.WalkDirFunc) error {
			for _, s := range steps {
				if err := fn(s.path, s.d, s.err); err != nil {
					if errors.Is(err, fs.SkipDir) {
						continue
					}
					return err
				}
			}
			return nil
		}
		return collectEntriesErr(canon)
	}

	// Symlinked directory: SkipDir is returned and the walk completes.
	err = run(
		struct {
			path string
			d    os.DirEntry
			err  error
		}{canon, fakeEntry{name: ".", dir: true, mod: os.ModeDir}, nil},
		struct {
			path string
			d    os.DirEntry
			err  error
		}{filepath.Join(canon, "loop"), fakeEntry{name: "loop", dir: true, mod: os.ModeSymlink}, nil},
	)
	if err != nil {
		t.Fatalf("symlinked directory must be skipped: %v", err)
	}

	// Unreadable metadata on a regular entry.
	err = run(struct {
		path string
		d    os.DirEntry
		err  error
	}{filepath.Join(canon, "broken"), fakeEntry{name: "broken", err: errors.New("stat refused")}, nil})
	if err == nil || !strings.Contains(err.Error(), "stat refused") {
		t.Fatalf("unreadable metadata = %v, want stat error", err)
	}

	// Escaping path.
	err = run(struct {
		path string
		d    os.DirEntry
		err  error
	}{filepath.Join(canon, "..", "escape"), fakeEntry{name: "escape", mod: 0, info: fakeInfo{}}, nil})
	if err == nil || !strings.Contains(err.Error(), "escapes workspace") {
		t.Fatalf("escaping path = %v, want escape error", err)
	}
}

// collectEntriesErr opens the workspace and collects entries, so the
// synthetic walk seam exercises the real callback.
func collectEntriesErr(workspace string) error {
	root, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return err
	}
	defer root.Close()
	_, err = manifestForRoot(root)
	return err
}

// makeArchive builds a deterministic tar.gz from name->content pairs.
func makeArchive(t *testing.T, files map[string]string) ([]byte, Manifest) {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		body := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	m, err := Parse(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), m
}
