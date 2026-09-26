package safefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// archiveBudgetSource counts the bytes it hands to the decompressor, so a
// test can prove the compressed budget stopped the stream early.
type archiveBudgetSource struct {
	b        []byte
	off      int
	returned int64
}

func (s *archiveBudgetSource) Read(p []byte) (int, error) {
	if s.off >= len(s.b) {
		return 0, io.EOF
	}
	n := copy(p, s.b[s.off:])
	s.off += n
	s.returned += int64(n)
	return n, nil
}

// singleMemberArchive builds a tar.gz whose only member is incompressible
// and of the requested size: there is no second tar header to trigger a
// boundary check while the member body streams.
func singleMemberArchive(t *testing.T, size int) []byte {
	t.Helper()
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "big.bin", Mode: 0o644, Size: int64(size), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// budgetLimits allows the whole archive and leaves every other bound wide
// enough that the compressed-byte budget is the only applicable one.
func budgetLimits(bound int64) ExtractLimits {
	return ExtractLimits{
		MaxArchiveBytes:     bound,
		MaxExpandedBytes:    16 << 20,
		MaxFileBytes:        8 << 20,
		MaxEntries:          100,
		MaxPathLength:       2048,
		MaxDepth:            64,
		MaxCompressionRatio: 1000,
		AllowAll:            true,
	}
}

// TestExtractArchiveBudgetContinuous pins Y3-A: a single enormous member (no
// second header) must fail within the compressed-byte bound even though the
// only tar-entry boundary is EOF, the source must never hand more than
// budget+1 bytes to the decompressor, an exact-bound archive must succeed,
// and budget-1 must fail with ErrLimits.
func TestExtractArchiveBudgetContinuous(t *testing.T) {
	const memberSize = 2 << 20
	data := singleMemberArchive(t, memberSize)

	// A budget far below the archive size: the old boundary check let the
	// whole member stream through and then returned at EOF.
	bound := int64(1 << 20)
	if int64(len(data)) <= bound {
		t.Fatalf("test archive %d bytes does not exceed the %d-byte budget", len(data), bound)
	}
	src := &archiveBudgetSource{b: data}
	stats, err := extractFromSource(t, src, budgetLimits(bound))
	if !errors.Is(err, ErrLimits) {
		t.Fatalf("single-member archive %d bytes exceeded bound %d: err = %v, want ErrLimits", len(data), bound, err)
	}
	if src.returned > bound+1 {
		t.Fatalf("source handed %d bytes to the decompressor, want at most %d (bound + one probe)", src.returned, bound+1)
	}
	if stats != nil && stats.Files != 0 {
		t.Fatalf("oversized archive reported %d extracted files, want 0", stats.Files)
	}

	// The exact archive size is a valid budget: the probe sees EOF.
	exact := int64(len(data))
	src = &archiveBudgetSource{b: data}
	stats, err = extractFromSource(t, src, budgetLimits(exact))
	if err != nil {
		t.Fatalf("archive exactly at the %d-byte budget must extract: %v", exact, err)
	}
	if stats.Files != 1 || stats.Bytes != memberSize {
		t.Fatalf("exact-bound stats = %+v, want 1 file / %d bytes", stats, memberSize)
	}
	if src.returned != exact {
		t.Fatalf("exact-bound source handed %d bytes, want %d", src.returned, exact)
	}

	// A budget just below the archive size fails ErrLimits: the member body
	// still needs compressed bytes that the budget withholds. (A budget that
	// only truncates the trailing gzip trailer is not observable here because
	// tar stops at its end-of-archive blocks without forcing gzip to read the
	// trailer; the reader's own exact bound+1 contract is pinned separately.)
	src = &archiveBudgetSource{b: data}
	if _, err := extractFromSource(t, src, budgetLimits(exact-4096)); !errors.Is(err, ErrLimits) {
		t.Fatalf("near-bound err = %v, want ErrLimits", err)
	}
	if src.returned > exact-4096+1 {
		t.Fatalf("near-bound source handed %d bytes, want at most %d", src.returned, exact-4096+1)
	}
}

func extractFromSource(t *testing.T, src io.Reader, limits ExtractLimits) (*ExtractStats, error) {
	t.Helper()
	root, err := OpenRootNoFollow(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	return Extract(root, src, limits)
}

// TestBoundedArchiveReaderExactBound pins the reader's own contract: at the
// bound it probes exactly once, never delivers the probed byte, latches the
// violation, and treats an EOF probe as a clean end.
func TestBoundedArchiveReaderExactBound(t *testing.T) {
	src := &archiveBudgetSource{b: []byte("abcdef")}
	b := newBoundedArchiveReader(src, 4)
	out, err := io.ReadAll(b)
	if !errors.Is(err, ErrLimits) {
		t.Fatalf("over-bound read = %v, want ErrLimits", err)
	}
	if string(out) != "abcd" {
		t.Fatalf("delivered %q, want the budgeted prefix only", out)
	}
	if src.returned != 5 {
		t.Fatalf("probe consumed %d source bytes, want exactly one past the bound", src.returned)
	}
	before := src.returned
	if _, err := b.Read(make([]byte, 8)); !errors.Is(err, ErrLimits) {
		t.Fatalf("latched read = %v, want ErrLimits", err)
	}
	if src.returned != before {
		t.Fatalf("latched read touched the source again (%d -> %d)", before, src.returned)
	}

	exact := &archiveBudgetSource{b: []byte("abcd")}
	b = newBoundedArchiveReader(exact, 4)
	out, err = io.ReadAll(b)
	if err != nil || string(out) != "abcd" {
		t.Fatalf("exact-bound read = %q, %v; want clean EOF", out, err)
	}
	if exact.returned != 4 {
		t.Fatalf("exact-bound source handed %d bytes, want 4", exact.returned)
	}
}

// TestExtractAllowAllIsExplicit pins the Y3-C API contract: zero limits write
// nothing, AllowAll writes everything, and Allowed restricts to its roots.
func TestExtractAllowAllIsExplicit(t *testing.T) {
	data := tarGz(t, []tarEntry{
		{name: "keep/a", data: []byte("1"), typeflag: tar.TypeReg},
		{name: "skip/b", data: []byte("2"), typeflag: tar.TypeReg},
	})

	// Zero limits: everything is validated, nothing is written.
	dest := t.TempDir()
	stats, err := extractTo(t, data, dest, ExtractLimits{})
	if err != nil {
		t.Fatalf("empty limits extraction = %v, want nil (nothing written)", err)
	}
	if stats.Files != 0 || stats.Bytes != 0 {
		t.Fatalf("empty limits stats = %+v, want nothing written", stats)
	}
	if _, err := os.Stat(filepath.Join(dest, "keep", "a")); !os.IsNotExist(err) {
		t.Fatal("empty limits wrote an entry")
	}

	// AllowAll: the whole archive.
	dest = t.TempDir()
	stats, err = extractTo(t, data, dest, ExtractLimits{AllowAll: true})
	if err != nil {
		t.Fatalf("AllowAll extraction = %v", err)
	}
	if stats.Files != 2 {
		t.Fatalf("AllowAll stats = %+v, want 2 files", stats)
	}
	for _, p := range []string{"keep/a", "skip/b"} {
		if _, err := os.Stat(filepath.Join(dest, filepath.FromSlash(p))); err != nil {
			t.Fatalf("AllowAll entry %s missing: %v", p, err)
		}
	}

	// Allowed without AllowAll: only the listed root.
	dest = t.TempDir()
	stats, err = extractTo(t, data, dest, ExtractLimits{Allowed: []string{"keep"}})
	if err != nil {
		t.Fatalf("Allowed extraction = %v", err)
	}
	if stats.Files != 1 {
		t.Fatalf("Allowed stats = %+v, want 1 file", stats)
	}
	if _, err := os.Stat(filepath.Join(dest, "keep", "a")); err != nil {
		t.Fatalf("allowed entry missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "skip", "b")); !os.IsNotExist(err) {
		t.Fatal("disallowed entry written")
	}
}

// TestUnderAllowedRequiresAllowAllForEmpty proves no Allowed list shape
// silently means the whole archive.
func TestUnderAllowedRequiresAllowAllForEmpty(t *testing.T) {
	for _, limits := range []ExtractLimits{
		{},
		{Allowed: []string{}},
		{Allowed: nil},
	} {
		if underAllowed("any/path", limits) {
			t.Fatalf("limits %+v allowed an entry without AllowAll", limits)
		}
	}
	if !underAllowed("any/path", ExtractLimits{AllowAll: true, Allowed: nil}) {
		t.Fatal("AllowAll did not allow an entry")
	}
}

// capPartialErrWriter writes n bytes of each chunk, then returns err.
type capPartialErrWriter struct {
	n   int
	err error
	got bytes.Buffer
}

func (w *capPartialErrWriter) Write(p []byte) (int, error) {
	k := w.n
	if k > len(p) {
		k = len(p)
	}
	w.got.Write(p[:k])
	return k, w.err
}

// capShortWriter always claims one byte fewer than it was given, with a nil
// error.
type capShortWriter struct{ got bytes.Buffer }

func (w *capShortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.got.Write(p[:len(p)-1])
	return len(p) - 1, nil
}

// TestCappedWriterErrorPrecedence pins Y3-B: at the cap boundary the final
// partial chunk's writer error wins unchanged, a short write with a nil error
// becomes io.ErrShortWrite, an exact partial boundary is a clean full write,
// and an exhausted budget refuses further writes without touching the sink.
func TestCappedWriterErrorPrecedence(t *testing.T) {
	sinkErr := errors.New("sink refused")

	// Partial write + error: the writer error is propagated unchanged and the
	// cap signal must not mask it.
	w := &capPartialErrWriter{n: 2, err: sinkErr}
	cw := NewCappedWriter(w, 4)
	n, err := cw.Write([]byte("abcdef"))
	if n != 2 || !errors.Is(err, sinkErr) || errors.Is(err, ErrCapExceeded) {
		t.Fatalf("partial+error write = (%d, %v), want (2, %v)", n, err, sinkErr)
	}
	if w.got.String() != "ab" {
		t.Fatalf("sink got %q, want %q", w.got.String(), "ab")
	}

	// Short write + nil error: io.ErrShortWrite, not a silent success.
	sw := &capShortWriter{}
	cw = NewCappedWriter(sw, 4)
	n, err = cw.Write([]byte("abcdef"))
	if n != 3 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write = (%d, %v), want (3, io.ErrShortWrite)", n, err)
	}
	if sw.got.String() != "abc" {
		t.Fatalf("short sink got %q, want %q", sw.got.String(), "abc")
	}

	// Exact partial boundary: len(p) == remaining is a full write, no error.
	var exact bytes.Buffer
	cw = NewCappedWriter(&exact, 4)
	n, err = cw.Write([]byte("abcd"))
	if n != 4 || err != nil || exact.String() != "abcd" {
		t.Fatalf("exact boundary = (%d, %v, %q), want (4, nil, abcd)", n, err, exact.String())
	}

	// Zero remaining: refused without touching the underlying writer.
	n, err = cw.Write([]byte("x"))
	if n != 0 || !errors.Is(err, ErrCapExceeded) {
		t.Fatalf("zero remaining = (%d, %v), want (0, ErrCapExceeded)", n, err)
	}
	if exact.String() != "abcd" {
		t.Fatalf("zero-remaining write reached the sink: %q", exact.String())
	}
}
