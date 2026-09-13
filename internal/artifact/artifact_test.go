package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveExtractRoundTrip(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "dist", "app"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, err := s.Save("run1", "job1", "app", ws, []string{"dist"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	m, err := ReadManifest(path + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "app" || m.RunID != "run1" || m.JobID != "job1" {
		t.Fatalf("unexpected manifest: %+v", m)
	}
	if len(m.Entries) != 1 || m.Entries[0].Path != "dist/app" {
		t.Fatalf("unexpected entries: %+v", m.Entries)
	}
	dest := t.TempDir()
	if err := Extract(path, dest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "dist", "app"))
	if err != nil || string(b) != "binary" {
		t.Fatalf("extracted content mismatch: %q %v", b, err)
	}
}

func TestExtractRejectsEvilArchive(t *testing.T) {
	dest := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "../evil", Typeflag: tar.TypeReg, Size: 4, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	f := filepath.Join(t.TempDir(), "evil.tar.gz")
	if err := os.WriteFile(f, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Extract(f, dest); err == nil {
		t.Fatal("evil archive must be rejected")
	}
}

func TestSaveSkipsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	s := &Store{Root: t.TempDir()}
	ws := t.TempDir()
	secret := t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "key"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(secret, "key"), filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "real"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := s.Save("r", "j", "a", ws, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ReadManifest(path + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Entries {
		if e.Path == "link" {
			t.Fatal("symlink must not be archived")
		}
	}
	dest := t.TempDir()
	if err := Extract(path, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); !os.IsNotExist(err) {
		t.Fatal("symlink extracted")
	}
}
