package safefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func tarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: e.typeflag, Size: int64(len(e.data)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type tarEntry struct {
	name     string
	data     []byte
	typeflag byte
}

func extract(t *testing.T, data []byte, dest string) error {
	t.Helper()
	_, err := Extract(bytes.NewReader(data), dest, DefaultLimits())
	return err
}

func TestExtractRoundTrip(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{
		{name: "dir/", typeflag: tar.TypeDir},
		{name: "dir/file.txt", data: []byte("hello"), typeflag: tar.TypeReg},
		{name: "root.txt", data: []byte("world"), typeflag: tar.TypeReg},
	})
	if err := extract(t, data, dest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "dir", "file.txt"))
	if err != nil || string(b) != "hello" {
		t.Fatalf("expected file content, got %q err %v", b, err)
	}
}

func TestExtractRejectsParentTraversal(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{{name: "../evil", data: []byte("x"), typeflag: tar.TypeReg}})
	if err := extract(t, data, dest); err == nil {
		t.Fatal("expected traversal rejection")
	}
	if _, err := os.Stat(filepath.Join(dest, "..", "evil")); !os.IsNotExist(err) {
		t.Fatal("file escaped destination")
	}
}

func TestExtractRejectsAbsolutePath(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{{name: "/abs/evil", data: []byte("x"), typeflag: tar.TypeReg}})
	if err := extract(t, data, dest); err == nil {
		t.Fatal("expected absolute path rejection")
	}
}

func TestExtractRejectsSymlinkEntry(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{{name: "link", data: []byte("/etc/passwd"), typeflag: tar.TypeSymlink}})
	if err := extract(t, data, dest); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestExtractRejectsHardlinkEntry(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{
		{name: "a", data: []byte("x"), typeflag: tar.TypeReg},
		{name: "b", data: []byte("a"), typeflag: tar.TypeLink},
	})
	if err := extract(t, data, dest); err == nil {
		t.Fatal("expected hardlink rejection")
	}
}

func TestExtractRejectsDeviceEntry(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{{name: "dev", typeflag: tar.TypeChar}})
	if err := extract(t, data, dest); err == nil {
		t.Fatal("expected device rejection")
	}
}

func TestExtractRejectsSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	dest := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dest, "cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dest, "cache")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dest, "cache")); err != nil {
		t.Fatal(err)
	}
	data := tarGz(t, []tarEntry{{name: "cache/evil", data: []byte("pwned"), typeflag: tar.TypeReg}})
	if err := extract(t, data, dest); err == nil {
		t.Fatal("expected symlink-parent rejection")
	}
	if _, err := os.Stat(filepath.Join(outside, "evil")); !os.IsNotExist(err) {
		t.Fatal("file written through symlink")
	}
}

func TestExtractRejectsDuplicateEntry(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{
		{name: "a", data: []byte("1"), typeflag: tar.TypeReg},
		{name: "a", data: []byte("2"), typeflag: tar.TypeReg},
	})
	if err := extract(t, data, dest); err == nil {
		t.Fatal("expected duplicate rejection")
	}
}

func TestExtractRejectsCaseFoldCollision(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("case-fold collision only on case-insensitive filesystems")
	}
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{
		{name: "File", data: []byte("1"), typeflag: tar.TypeReg},
		{name: "file", data: []byte("2"), typeflag: tar.TypeReg},
	})
	if err := extract(t, data, dest); err == nil {
		t.Fatal("expected case-fold collision rejection")
	}
}

func TestExtractRejectsCompressionBomb(t *testing.T) {
	dest := t.TempDir()
	big := bytes.Repeat([]byte("A"), 64<<20)
	data := tarGz(t, []tarEntry{{name: "bomb", data: big, typeflag: tar.TypeReg}})
	limits := DefaultLimits()
	limits.MaxCompressionRatio = 10 // 64MiB zeros compress far beyond 10x
	_, err := Extract(bytes.NewReader(data), dest, limits)
	if err == nil {
		t.Fatal("expected compression ratio rejection")
	}
}

func TestExtractEnforcesFileLimit(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{{name: "big", data: bytes.Repeat([]byte("B"), 1024), typeflag: tar.TypeReg}})
	limits := DefaultLimits()
	limits.MaxFileBytes = 512
	if _, err := Extract(bytes.NewReader(data), dest, limits); err == nil {
		t.Fatal("expected file size limit rejection")
	}
}

func TestExtractEnforcesDepthLimit(t *testing.T) {
	dest := t.TempDir()
	deep := strings.Repeat("d/", 70) + "f"
	data := tarGz(t, []tarEntry{{name: deep, data: []byte("x"), typeflag: tar.TypeReg}})
	if err := extract(t, data, dest); err == nil {
		t.Fatal("expected depth limit rejection")
	}
}

func TestExtractEnforcesEntryLimit(t *testing.T) {
	dest := t.TempDir()
	var entries []tarEntry
	for i := 0; i < 10; i++ {
		entries = append(entries, tarEntry{name: "f" + strings.Repeat("x", i%3) + string(rune('a'+i)), data: []byte("x"), typeflag: tar.TypeReg})
	}
	data := tarGz(t, entries)
	limits := DefaultLimits()
	limits.MaxEntries = 5
	if _, err := Extract(bytes.NewReader(data), dest, limits); err == nil {
		t.Fatal("expected entry count rejection")
	}
}

func TestExtractAllowedFilter(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{
		{name: "keep/a", data: []byte("1"), typeflag: tar.TypeReg},
		{name: "skip/b", data: []byte("2"), typeflag: tar.TypeReg},
	})
	limits := DefaultLimits()
	limits.Allowed = []string{"keep"}
	if _, err := Extract(bytes.NewReader(data), dest, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "keep", "a")); err != nil {
		t.Fatal("allowed entry missing")
	}
	if _, err := os.Stat(filepath.Join(dest, "skip", "b")); !os.IsNotExist(err) {
		t.Fatal("disallowed entry written")
	}
}

func TestWriteTarGzDeterministicAndSafe(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "sub", "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink("/etc/passwd", filepath.Join(ws, "link")); err != nil {
			t.Fatal(err)
		}
	}
	var b1, b2 bytes.Buffer
	if err := WriteTarGz(&b1, ws, []string{"."}, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteTarGz(&b2, ws, []string{"."}, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1.Bytes(), b2.Bytes()) {
		t.Fatal("archives not deterministic")
	}
	dest := t.TempDir()
	if _, err := Extract(bytes.NewReader(b1.Bytes()), dest, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "sub", "a.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); !os.IsNotExist(err) {
		t.Fatal("symlink must not be archived")
	}
}
