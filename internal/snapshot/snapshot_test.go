package snapshot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// symlinkArchive builds a tar.gz with a single symlink entry.
func symlinkArchive() []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// writeTree plants a regular-file tree plus one symlink and reports whether
// the symlink could be created. On Windows symlink creation needs
// privileges; when it fails there, callers that specifically need the link
// skip while the tree-only tests still run.
func writeTree(t *testing.T, root string) (symlinkCreated bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "b.txt"), []byte("world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Symlinks and special files are never captured.
	if err := os.Symlink("a.txt", filepath.Join(root, "link")); err != nil {
		if runtime.GOOS == "windows" {
			return false
		}
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".hidden"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return true
}

func TestCreateRestoreRoundtrip(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src)

	var buf bytes.Buffer
	m1, err := Create(src, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if m1.Version != ManifestVersion {
		t.Fatalf("version = %d", m1.Version)
	}
	if m1.RootSHA256 == "" {
		t.Fatal("empty root digest")
	}
	if len(m1.Entries) != 3 {
		t.Fatalf("entries = %d, want 3 (symlink excluded): %+v", len(m1.Entries), m1.Entries)
	}

	// Deterministic: creating twice produces identical bytes and manifests.
	var buf2 bytes.Buffer
	m2, err := Create(src, &buf2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
		t.Fatal("snapshot archives are not deterministic")
	}
	if m1.RootSHA256 != m2.RootSHA256 {
		t.Fatal("manifests differ across identical captures")
	}

	// The archive-side manifest (Parse) agrees with the capture manifest.
	mParsed, err := Parse(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if mParsed.RootSHA256 != m1.RootSHA256 {
		t.Fatalf("parse root %s != capture root %s", mParsed.RootSHA256, m1.RootSHA256)
	}
	if len(mParsed.Entries) != len(m1.Entries) {
		t.Fatalf("parse entries = %d, want %d", len(mParsed.Entries), len(m1.Entries))
	}

	// Restore into a fresh directory and verify the manifest matches.
	dst := t.TempDir()
	m3, err := Restore(bytes.NewReader(buf.Bytes()), dst)
	if err != nil {
		t.Fatal(err)
	}
	if m3.RootSHA256 != m1.RootSHA256 {
		t.Fatalf("restore root %s != capture root %s", m3.RootSHA256, m1.RootSHA256)
	}
	got, err := os.ReadFile(filepath.Join(dst, "sub", "b.txt"))
	if err != nil || string(got) != "world\n" {
		t.Fatalf("restored content wrong: %q %v", got, err)
	}
	// The symlink is not restored.
	if _, err := os.Lstat(filepath.Join(dst, "link")); err == nil {
		t.Fatal("symlink restored; it must be excluded")
	}
}

func TestManifestForSkippedSymlinks(t *testing.T) {
	root := t.TempDir()
	if !writeTree(t, root) {
		t.Skip("symlink creation needs privileges on windows")
	}
	m, err := ManifestFor(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Entries {
		if e.Path == "link" {
			t.Fatal("symlink captured in manifest")
		}
		if e.Mode != 0o644 {
			t.Fatalf("entry %q mode = %#o, want normalized 0644", e.Path, e.Mode)
		}
	}
}

func TestRestoreRejectsUnsafeArchive(t *testing.T) {
	// A tar.gz containing a symlink entry must be rejected by safefs.
	dir := t.TempDir()
	if _, err := Restore(bytes.NewReader(symlinkArchive()), dir); err == nil {
		t.Fatal("symlink archive restored without error")
	}
}

func TestCreateEmptyWorkspace(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	m, err := Create(dir, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 0 {
		t.Fatalf("empty workspace has %d entries", len(m.Entries))
	}
}

func TestParseRejectsOversizedEntry(t *testing.T) {
	// A tar entry declaring > 1 GiB must be rejected from the header alone,
	// before its body is read.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "bomb", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2 << 30}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte("tiny body"))
	_ = tw.Close()
	_ = gz.Close()
	if _, err := Parse(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("oversized entry must be rejected")
	}
	if _, err := ParseWithLimits(bytes.NewReader(buf.Bytes()), safefs.ExtractLimits{}); err == nil {
		t.Fatal("oversized entry must be rejected with default limits")
	}
}

func TestParseEnforcesEntryCap(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := 0; i < 5; i++ {
		if err := tw.WriteHeader(&tar.Header{Name: "f" + string(rune('a'+i)), Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	limits := safefs.ExtractLimits{MaxEntries: 3}
	_, err := ParseWithLimits(bytes.NewReader(buf.Bytes()), limits)
	if err == nil || !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("expected entry-cap rejection, got %v", err)
	}
}

func TestParseEnforcesPathBounds(t *testing.T) {
	mk := func(name string) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte("x"))
		_ = tw.Close()
		_ = gz.Close()
		return buf.Bytes()
	}
	long := strings.Repeat("a", 2049)
	if _, err := Parse(bytes.NewReader(mk(long))); err == nil {
		t.Fatal("over-long path must be rejected")
	}
	deep := strings.Repeat("d/", 64) + "f"
	if _, err := Parse(bytes.NewReader(mk(deep))); err == nil {
		t.Fatal("over-deep path must be rejected")
	}
}
