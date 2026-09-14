package snapshot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
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

func writeTree(t *testing.T, root string) {
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
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".hidden"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
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
	writeTree(t, root)
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
