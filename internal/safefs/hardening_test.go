package safefs

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestExtractEntryCapBoundary pins the entry-count cap boundary: exactly
// MaxEntries entries are accepted and MaxEntries+1 is rejected before any
// further entry is written.
func TestExtractEntryCapBoundary(t *testing.T) {
	mk := func(n int) []byte {
		entries := make([]tarEntry, 0, n)
		for i := 0; i < n; i++ {
			entries = append(entries, tarEntry{name: fmt.Sprintf("f%05d", i), data: []byte("x"), typeflag: tar.TypeReg})
		}
		return tarGz(t, entries)
	}
	limits := DefaultLimits()
	limits.MaxEntries = 4096
	if err := extractWith(t, mk(4096), t.TempDir(), limits); err != nil {
		t.Fatalf("archive with exactly MaxEntries entries must extract: %v", err)
	}
	err := extractWith(t, mk(4097), t.TempDir(), limits)
	if !errors.Is(err, ErrLimits) {
		t.Fatalf("MaxEntries+1 entries: want ErrLimits, got %v", err)
	}
}

// TestExtractCompressionRatioBoundary pins the ratio check at the limit:
// with the compressed stream fully buffered, an expanded size equal to
// MaxCompressionRatio (integer-truncated) times the consumed compressed
// bytes is accepted, and a ratio whose truncated budget is smaller is not.
func TestExtractCompressionRatioBoundary(t *testing.T) {
	payload := make([]byte, 2000)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	data := tarGz(t, []tarEntry{{name: "blob.bin", data: payload, typeflag: tar.TypeReg}})
	if len(data) >= 4096 {
		t.Fatalf("test archive %d bytes; expected the whole compressed stream to be buffered", len(data))
	}
	at := DefaultLimits()
	at.MaxCompressionRatio = 1 // 2000 expanded <= 1 x total compressed bytes
	if err := extractWith(t, data, t.TempDir(), at); err != nil {
		t.Fatalf("expanded size at the ratio limit must extract: %v", err)
	}
	below := DefaultLimits()
	below.MaxCompressionRatio = 0.5 // int64 truncation: any expansion exceeds the budget
	if err := extractWith(t, data, t.TempDir(), below); !errors.Is(err, ErrCompression) {
		t.Fatalf("ratio below the limit: want ErrCompression, got %v", err)
	}
}

// TestExtractRejectsControlAndBidiNames verifies that entry names carrying
// C0/DEL controls or Unicode bidirectional formatting controls are rejected:
// such names can spoof or inject into logs and terminals even though they
// cannot escape the root.
func TestExtractRejectsControlAndBidiNames(t *testing.T) {
	names := []string{
		"a\x01b", "a\x1bb", "a\x7fb", "a\tb", "a\nb",
		"a\u202Eb", "a\u202Ab", "a\u2066b", "a\u200Fb",
	}
	for _, name := range names {
		dest := t.TempDir()
		data := tarGz(t, []tarEntry{{name: name, data: []byte("x"), typeflag: tar.TypeReg}})
		if err := extractWith(t, data, dest, DefaultLimits()); !errors.Is(err, ErrUnsafeEntry) {
			t.Errorf("name %q: want ErrUnsafeEntry, got %v", name, err)
		}
	}
}

// TestExtractRejectsWindowsDangerousNames verifies that component shapes
// which are not portable across the supported platforms are rejected
// everywhere: reserved device names, trailing dots/spaces and NTFS
// alternate-data-stream colons.
func TestExtractRejectsWindowsDangerousNames(t *testing.T) {
	bad := []string{
		"CON", "con.txt", "NUL", "aux", "AUX.log", "COM1.log", "LPT9", "prn.txt",
		"CONIN$", "conout$.txt", "a.", "b ", "dir/a.", "c:d", "nested/COM2", "nul.txt.bak",
	}
	for _, name := range bad {
		dest := t.TempDir()
		data := tarGz(t, []tarEntry{{name: name, data: []byte("x"), typeflag: tar.TypeReg}})
		if err := extractWith(t, data, dest, DefaultLimits()); !errors.Is(err, ErrUnsafeEntry) {
			t.Errorf("name %q: want ErrUnsafeEntry, got %v", name, err)
		}
	}
	good := []string{
		"console.txt", "complex", "a.b", "COM10", "LPT0", "auxiliary",
		"a b", "dir/file", "a-B_c.d",
	}
	for _, name := range good {
		dest := t.TempDir()
		data := tarGz(t, []tarEntry{{name: name, data: []byte("x"), typeflag: tar.TypeReg}})
		if err := extractWith(t, data, dest, DefaultLimits()); err != nil {
			t.Errorf("name %q must extract, got %v", name, err)
		}
	}
}

// TestExtractRejectsNormalizationCollisions verifies that on
// normalization-insensitive filesystems an NFC/NFD pair of names is rejected
// as a duplicate instead of silently overwriting one file with the other.
func TestExtractRejectsNormalizationCollisions(t *testing.T) {
	if !caseInsensitiveFS {
		t.Skip("normalization-insensitive duplicate detection applies to darwin/windows")
	}
	nfc := "caf\u00e9.txt"
	nfd := "cafe\u0301.txt"
	if foldPath(nfc) != foldPath(nfd) {
		t.Fatalf("fold does not merge NFC/NFD: %q vs %q", foldPath(nfc), foldPath(nfd))
	}
	data := tarGz(t, []tarEntry{
		{name: nfc, data: []byte("1"), typeflag: tar.TypeReg},
		{name: nfd, data: []byte("2"), typeflag: tar.TypeReg},
	})
	if err := extractWith(t, data, t.TempDir(), DefaultLimits()); !errors.Is(err, ErrDuplicateEntry) {
		t.Fatalf("NFC/NFD collision: want ErrDuplicateEntry, got %v", err)
	}
}

// TestCappedWriterLimitBoundary pins the cap boundary: writing exactly the
// limit is allowed and writes all bytes; the next byte aborts with
// ErrCapExceeded after at most the remaining budget is written.
func TestCappedWriterLimitBoundary(t *testing.T) {
	var exact bytes.Buffer
	cw := NewCappedWriter(&exact, 5)
	n, err := cw.Write([]byte("12345"))
	if err != nil || n != 5 || exact.String() != "12345" {
		t.Fatalf("write exactly at limit: n=%d err=%v buf=%q", n, err, exact.String())
	}
	n, err = cw.Write([]byte("6"))
	if !errors.Is(err, ErrCapExceeded) || n != 0 {
		t.Fatalf("write past limit: n=%d err=%v", n, err)
	}

	var over bytes.Buffer
	cw2 := NewCappedWriter(&over, 5)
	n, err = cw2.Write([]byte("123456"))
	if !errors.Is(err, ErrCapExceeded) || n != 5 {
		t.Fatalf("single oversized write: n=%d err=%v", n, err)
	}
	if over.String() != "12345" {
		t.Fatalf("underlying writer received %q, want the first 5 bytes", over.String())
	}
}

// deleteOnFirstWrite is an io.Writer that deletes a file in the workspace the
// first time any byte is written, deterministically opening the window
// between collection and the file's OpenRel.
type deleteOnFirstWrite struct {
	target string
	done   bool
}

func (d *deleteOnFirstWrite) Write(p []byte) (int, error) {
	if !d.done {
		d.done = true
		_ = os.Remove(d.target)
	}
	return len(p), nil
}

// TestWriteTarGzFromRootDeletedBeforeOpenFailsCleanly verifies that a file
// deleted after the walk but before its descriptor is opened fails the
// archive instead of producing a torn archive.
func TestWriteTarGzFromRootDeletedBeforeOpenFailsCleanly(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "a.txt"), []byte("aa"), 0o644); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(ws, "b.txt")
	if err := os.WriteFile(victim, []byte("bb"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	w := &deleteOnFirstWrite{target: victim}
	if err := WriteTarGzFromRoot(w, root, []string{"."}); err == nil {
		t.Fatal("archive must fail when a file disappears before its descriptor is opened")
	}
}

// TestOpenRelDeletedAfterOpenStillReadable verifies the descriptor contract
// behind capture: once OpenRel has returned, deleting the path does not
// affect the opened descriptor, so a capture reads the opened file or fails
// cleanly.
func TestOpenRelDeletedAfterOpenStillReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot delete a file with an open handle")
	}
	ws := t.TempDir()
	path := filepath.Join(ws, "victim.txt")
	if err := os.WriteFile(path, []byte("original bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := root.OpenRel("victim.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "original bytes" {
		t.Fatalf("deleted-after-open descriptor read %q", b)
	}
}

// TestWriteTarGzFromRootManyFilesDoesNotExhaustDescriptors captures a
// workspace with far more files than a typical file-descriptor limit, which
// is only possible because the writer holds one descriptor at a time.
func TestWriteTarGzFromRootManyFilesDoesNotExhaustDescriptors(t *testing.T) {
	ws := t.TempDir()
	const n = 600
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(ws, fmt.Sprintf("f%04d", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var buf bytes.Buffer
	if err := WriteTarGzFromRoot(&buf, root, []string{"."}); err != nil {
		t.Fatalf("capture of %d files failed (descriptor leak?): %v", n, err)
	}
}

func TestCleanEntryNameBoundaries(t *testing.T) {
	rejected := []string{"", ".", "./", "..", "../x", "a/..", "a/../.."}
	for _, name := range rejected {
		if _, err := cleanEntryName(name); err == nil {
			t.Errorf("name %q was accepted", name)
		}
	}
	accepted := map[string]string{
		".hidden":  ".hidden",
		"a//":      "a",
		"a/./b":    "a/b",
		"a/../b":   "b",
		"dir/x.md": "dir/x.md",
	}
	for in, want := range accepted {
		got, err := cleanEntryName(in)
		if err != nil || got != want {
			t.Errorf("cleanEntryName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// TestFoldPathStableForPlainNames documents that the fold is idempotent
// everywhere and byte-exact on case-sensitive hosts.
func TestFoldPathStableForPlainNames(t *testing.T) {
	for _, n := range []string{"a/b.txt", "MiXeD", "caf\u00e9"} {
		if got := FoldPath(FoldPath(n)); got != FoldPath(n) {
			t.Fatalf("fold not idempotent for %q: %q", n, got)
		}
	}
	if !caseInsensitiveFS {
		if FoldPath("MiXeD") != "MiXeD" {
			t.Fatal("case-sensitive hosts must not fold case")
		}
	}
}

func TestValidateEntryNameRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../x", "a/../../x", "/abs", `a\b`} {
		if _, err := ValidateEntryName(name); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if got, err := ValidateEntryName("dir/file.txt"); err != nil || got != "dir/file.txt" {
		t.Fatalf("valid name: got %q err %v", got, err)
	}
}
