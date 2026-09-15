package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func base64RawURL(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

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

func TestSaveRejectsSymlinkedDirectoryInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	s := &Store{Root: t.TempDir()}
	ws := t.TempDir()
	secret := t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "key"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "real"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlinked directory resolving outside the workspace must be rejected
	// before any enumeration happens: no artifact and no tmp file remain.
	if _, err := s.Save("r", "j", "a", ws, []string{"link"}); err == nil {
		t.Fatal("symlinked directory input must be rejected")
	}
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("artifact store must stay empty, found %q", e.Name())
	}
}

func TestSaveWeirdNamesRoundTripViaManifest(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "data"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	runID, jobID, name := "run/1..", "job 2", "artifact name/../weird"
	path, err := s.Save(runID, jobID, name, ws, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	// The archive lands inside the store root: encoded components never
	// escape it.
	rel, err := filepath.Rel(s.Root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("artifact path escapes store root: %q", path)
	}
	m, err := ReadManifest(path + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != name || m.RunID != runID || m.JobID != jobID {
		t.Fatalf("manifest must preserve originals: got %+v", m)
	}
}

func TestEncodeArtifactName(t *testing.T) {
	cases := map[string]string{
		"app":                 "app",
		"app-1.2.3_linux.tar": "app-1.2.3_linux.tar",
		"a.b":                 "a.b",
		"":                    "",
		"we ird":              base64RawURL("we ird"),
		"a/b":                 base64RawURL("a/b"),
		"../escape":           base64RawURL("../escape"),
		"détente":             base64RawURL("détente"),
	}
	for in, want := range cases {
		if got := encodeArtifactName(in); got != want {
			t.Errorf("encodeArtifactName(%q) = %q, want %q", in, got, want)
		}
		if again := encodeArtifactName(in); again != encodeArtifactName(in) {
			t.Errorf("encodeArtifactName(%q) not deterministic", in)
		}
	}
	for _, out := range cases {
		if strings.ContainsAny(out, "/\\") {
			t.Errorf("encoded name %q contains a path separator", out)
		}
	}
}

func TestSaveCapExceededLeavesNoPartialArchive(t *testing.T) {
	s := &Store{Root: t.TempDir(), MaxArtifactBytes: 64}
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "big"), bytes.Repeat([]byte("x"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.Save("r", "j", "a", ws, []string{"."})
	if err == nil {
		t.Fatal("expected cap error")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("error %q does not mention cap", err)
	}
	entries, err := os.ReadDir(filepath.Join(s.Root, "r", "j"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("no archive may remain after cap failure, found %q", e.Name())
	}
}
