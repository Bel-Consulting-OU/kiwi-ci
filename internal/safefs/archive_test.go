package safefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
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
	limits := DefaultLimits()
	limits.AllowAll = true
	return extractWith(t, data, dest, limits)
}

func extractWith(t *testing.T, data []byte, dest string, limits ExtractLimits) error {
	t.Helper()
	root, err := OpenRootNoFollow(dest)
	if err != nil {
		return err
	}
	defer root.Close()
	_, err = Extract(root, bytes.NewReader(data), limits)
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
	limits.AllowAll = true
	limits.MaxCompressionRatio = 10 // 64MiB zeros compress far beyond 10x
	if err := extractWith(t, data, dest, limits); err == nil {
		t.Fatal("expected compression ratio rejection")
	}
}

func TestExtractEnforcesFileLimit(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{{name: "big", data: bytes.Repeat([]byte("B"), 1024), typeflag: tar.TypeReg}})
	limits := DefaultLimits()
	limits.AllowAll = true
	limits.MaxFileBytes = 512
	if err := extractWith(t, data, dest, limits); err == nil {
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
	limits.AllowAll = true
	limits.MaxEntries = 5
	if err := extractWith(t, data, dest, limits); err == nil {
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
	if err := extractWith(t, data, dest, limits); err != nil {
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
	if err := extract(t, b1.Bytes(), dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "sub", "a.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); !os.IsNotExist(err) {
		t.Fatal("symlink must not be archived")
	}
}

func TestExtractPathShimStillWorks(t *testing.T) {
	dest := t.TempDir()
	data := tarGz(t, []tarEntry{
		{name: "dir/", typeflag: tar.TypeDir},
		{name: "dir/file.txt", data: []byte("hello"), typeflag: tar.TypeReg},
	})
	limits := DefaultLimits()
	limits.AllowAll = true
	if _, err := ExtractPath(dest, bytes.NewReader(data), limits); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "dir", "file.txt")); err != nil || string(b) != "hello" {
		t.Fatalf("shim extraction wrong: %q %v", b, err)
	}
}

func TestOpenRootNoFollowRejectsSymlinkDest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRootNoFollow(link); !errors.Is(err, ErrSymlinkParent) {
		t.Fatalf("expected ErrSymlinkParent, got %v", err)
	}
}

func TestOpenRootNoFollowRequiresExistingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := OpenRootNoFollow(missing); err == nil {
		t.Fatal("expected error for missing destination")
	}
}

func TestExtractIntoPrecreatedLeafDirs(t *testing.T) {
	dest := t.TempDir()
	if err := os.Mkdir(filepath.Join(dest, "cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dest, "other", "leaf"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := tarGz(t, []tarEntry{
		{name: "cache/hit.txt", data: []byte("cached"), typeflag: tar.TypeReg},
		{name: "other/leaf/deep.txt", data: []byte("deep"), typeflag: tar.TypeReg},
		{name: "fresh/dir/new.txt", data: []byte("new"), typeflag: tar.TypeReg},
	})
	if err := extract(t, data, dest); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, want string }{
		{filepath.Join(dest, "cache", "hit.txt"), "cached"},
		{filepath.Join(dest, "other", "leaf", "deep.txt"), "deep"},
		{filepath.Join(dest, "fresh", "dir", "new.txt"), "new"},
	} {
		b, err := os.ReadFile(tc.path)
		if err != nil || string(b) != tc.want {
			t.Fatalf("file %s = %q, %v; want %q", tc.path, b, err, tc.want)
		}
	}
}

// TestExtractParentSwapNeverEscapes opens the root handle, then concurrently
// replaces the root's parent directory with a symlink to an unrelated
// directory while extraction runs. Because all writes are anchored to the
// held descriptor, every file must land in the original directory and none
// may escape through the swapped parent.
func TestExtractParentSwapNeverEscapes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink/rename swap needs unix semantics")
	}
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(parent, "dest")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRootNoFollow(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	evil := t.TempDir()
	const nFiles = 300
	var entries []tarEntry
	for i := 0; i < nFiles; i++ {
		entries = append(entries, tarEntry{
			name:     fmt.Sprintf("d%d/f%d.txt", i%30, i),
			data:     []byte(fmt.Sprintf("payload-%04d-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", i)),
			typeflag: tar.TypeReg,
		})
	}
	data := tarGz(t, entries)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		moved := parent + ".moved"
		for {
			select {
			case <-stop:
				_ = os.Remove(parent)
				_ = os.Rename(moved, parent)
				return
			default:
			}
			_ = os.Rename(parent, moved)
			_ = os.Symlink(evil, parent)
			time.Sleep(200 * time.Microsecond)
			_ = os.Remove(parent)
			_ = os.Rename(moved, parent)
			time.Sleep(200 * time.Microsecond)
		}
	}()

	limits := DefaultLimits()
	limits.AllowAll = true
	stats, err := Extract(root, bytes.NewReader(data), limits)
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Files != nFiles {
		t.Fatalf("files = %d, want %d", stats.Files, nFiles)
	}
	for i := 0; i < nFiles; i++ {
		p := filepath.Join(parent, "dest", fmt.Sprintf("d%d", i%30), fmt.Sprintf("f%d.txt", i))
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("file %d missing after swap: %v", i, err)
		}
		if !strings.HasPrefix(string(b), fmt.Sprintf("payload-%04d-", i)) {
			t.Fatalf("file %d content corrupted: %q", i, b)
		}
	}
	ents, err := os.ReadDir(evil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("extraction escaped through swapped parent: %d entries outside root", len(ents))
	}
}

func TestCappedWriterEnforcesLimit(t *testing.T) {
	var buf bytes.Buffer
	cw := NewCappedWriter(&buf, 10)
	n, err := cw.Write([]byte("1234567890"))
	if err != nil || n != 10 {
		t.Fatalf("first write = %d, %v", n, err)
	}
	if _, err := cw.Write([]byte("x")); !errors.Is(err, ErrCapExceeded) {
		t.Fatalf("expected ErrCapExceeded, got %v", err)
	} else if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("error %q does not mention cap", err)
	}
	if buf.String() != "1234567890" {
		t.Fatalf("underlying writer got %q", buf.String())
	}
}

func TestCappedWriterUnlimitedWhenZero(t *testing.T) {
	var buf bytes.Buffer
	cw := NewCappedWriter(&buf, 0)
	if _, err := cw.Write([]byte("no limit")); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "no limit" {
		t.Fatalf("got %q", buf.String())
	}
}

func TestWriteTarGzPropagatesCapError(t *testing.T) {
	ws := t.TempDir()
	payload := make([]byte, 4096)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "big.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err := WriteTarGz(NewCappedWriter(&buf, 512), ws, []string{"."}, false)
	if err == nil {
		t.Fatal("expected cap error to propagate")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("error %q does not mention cap", err)
	}
}
