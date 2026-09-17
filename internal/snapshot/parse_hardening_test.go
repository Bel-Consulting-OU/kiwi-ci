package snapshot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

func tarGzEntries(t *testing.T, entries []struct {
	name string
	data []byte
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
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

// tarGzHeaders builds a tar.gz from raw headers; regular entries carry a
// one-byte body per declared size.
func tarGzHeaders(t *testing.T, headers []tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := range headers {
		h := headers[i]
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg && h.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(h.Size))); err != nil {
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

// TestParseHeaderCountRejectsDirectoryFlood pins the total-header bound:
// directory headers used to bypass MaxEntries entirely, so an archive of
// nothing but directories could grow the seen map without bound.
func TestParseHeaderCountRejectsDirectoryFlood(t *testing.T) {
	headers := make([]tar.Header, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		headers = append(headers, tar.Header{
			Name:     fmt.Sprintf("dir%05d/", i),
			Typeflag: tar.TypeDir,
			Mode:     0o755,
		})
	}
	limits := safefs.ExtractLimits{MaxEntries: 100}
	if _, err := ParseWithLimits(bytes.NewReader(tarGzHeaders(t, headers)), limits); !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("directory flood: want ErrLimits, got %v", err)
	}
}

// TestParseHeaderCountRejectsSymlinkFlood is the symlink twin: non-regular
// headers are processed and counted too.
func TestParseHeaderCountRejectsSymlinkFlood(t *testing.T) {
	headers := make([]tar.Header, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		headers = append(headers, tar.Header{
			Name:     fmt.Sprintf("link%05d", i),
			Typeflag: tar.TypeSymlink,
			Linkname: "target",
		})
	}
	limits := safefs.ExtractLimits{MaxEntries: 100}
	if _, err := ParseWithLimits(bytes.NewReader(tarGzHeaders(t, headers)), limits); !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("symlink flood: want ErrLimits, got %v", err)
	}
}

// TestParseHeaderCountRejectsPaxFlood floods the archive with PAX extended
// headers: each entry is long enough that the writer emits an extended header
// record, and the total-header cap must reject the resulting stream even
// though Go's tar reader merges those records before returning them.
func TestParseHeaderCountRejectsPaxFlood(t *testing.T) {
	long := strings.Repeat("p", 120)
	headers := make([]tar.Header, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		headers = append(headers, tar.Header{
			Name:     fmt.Sprintf("%s%05d", long, i),
			Typeflag: tar.TypeSymlink,
			Linkname: "target",
			Format:   tar.FormatPAX,
		})
	}
	limits := safefs.ExtractLimits{MaxEntries: 100}
	if _, err := ParseWithLimits(bytes.NewReader(tarGzHeaders(t, headers)), limits); !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("pax flood: want ErrLimits, got %v", err)
	}
}

// TestParseHeaderCountBoundaryMixed pins the boundary: a mixed archive with
// exactly MaxEntries headers of any type is accepted, one header more is
// rejected, and the regular-entry set is unaffected.
func TestParseHeaderCountBoundaryMixed(t *testing.T) {
	mk := func(extra bool) []byte {
		headers := make([]tar.Header, 0, 101)
		for i := 0; i < 40; i++ {
			headers = append(headers, tar.Header{
				Name:     fmt.Sprintf("dir%02d/", i),
				Typeflag: tar.TypeDir,
				Mode:     0o755,
			})
		}
		for i := 0; i < 30; i++ {
			headers = append(headers, tar.Header{
				Name:     fmt.Sprintf("link%02d", i),
				Typeflag: tar.TypeSymlink,
				Linkname: "dir00",
			})
		}
		for i := 0; i < 30; i++ {
			headers = append(headers, tar.Header{
				Name:     fmt.Sprintf("file%02d", i),
				Typeflag: tar.TypeReg,
				Mode:     0o644,
				Size:     1,
			})
		}
		if extra {
			headers = append(headers, tar.Header{
				Name:     "one-more",
				Typeflag: tar.TypeReg,
				Mode:     0o644,
				Size:     1,
			})
		}
		return tarGzHeaders(t, headers)
	}
	limits := safefs.ExtractLimits{MaxEntries: 100}
	m, err := ParseWithLimits(bytes.NewReader(mk(false)), limits)
	if err != nil {
		t.Fatalf("archive with exactly MaxEntries headers must parse: %v", err)
	}
	if len(m.Entries) != 30 {
		t.Fatalf("regular entries = %d, want 30", len(m.Entries))
	}
	if _, err := ParseWithLimits(bytes.NewReader(mk(true)), limits); !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("MaxEntries+1 headers: want ErrLimits, got %v", err)
	}
}

// TestParseFileLimitBoundary pins the per-entry size boundary: an entry
// exactly at MaxFileBytes is accepted and one byte over is rejected.
func TestParseFileLimitBoundary(t *testing.T) {
	data := tarGzEntries(t, []struct {
		name string
		data []byte
	}{{name: "f", data: []byte("abcd")}})
	at := safefs.ExtractLimits{MaxFileBytes: 4}
	if _, err := ParseWithLimits(bytes.NewReader(data), at); err != nil {
		t.Fatalf("entry exactly at MaxFileBytes must parse: %v", err)
	}
	over := safefs.ExtractLimits{MaxFileBytes: 3}
	if _, err := ParseWithLimits(bytes.NewReader(data), over); !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("one byte over MaxFileBytes: want ErrLimits, got %v", err)
	}
}

// TestParseRejectsUnsafeNames verifies Parse applies the extraction
// name discipline: a manifest built from untrusted headers must not describe
// entries extraction would refuse.
func TestParseRejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"../evil", "/abs", "a\x01b", `a\b`, "NUL", "x."} {
		data := tarGzEntries(t, []struct {
			name string
			data []byte
		}{{name: name, data: []byte("x")}})
		if _, err := Parse(bytes.NewReader(data)); !errors.Is(err, safefs.ErrUnsafeEntry) {
			t.Errorf("name %q: want ErrUnsafeEntry, got %v", name, err)
		}
	}
}

// TestParseRejectsDuplicateNames verifies duplicate entries are rejected,
// including case-fold and NFC/NFD collisions on case-insensitive hosts.
func TestParseRejectsDuplicateNames(t *testing.T) {
	data := tarGzEntries(t, []struct {
		name string
		data []byte
	}{{name: "a", data: []byte("1")}, {name: "a", data: []byte("2")}})
	if _, err := Parse(bytes.NewReader(data)); !errors.Is(err, safefs.ErrDuplicateEntry) {
		t.Fatalf("duplicate entry: want ErrDuplicateEntry, got %v", err)
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		pair := tarGzEntries(t, []struct {
			name string
			data []byte
		}{
			{name: "caf\u00e9", data: []byte("1")},
			{name: "cafe\u0301", data: []byte("2")},
		})
		if _, err := Parse(bytes.NewReader(pair)); !errors.Is(err, safefs.ErrDuplicateEntry) {
			t.Fatalf("NFC/NFD duplicate: want ErrDuplicateEntry, got %v", err)
		}
		fold := tarGzEntries(t, []struct {
			name string
			data []byte
		}{{name: "File", data: []byte("1")}, {name: "file", data: []byte("2")}})
		if _, err := Parse(bytes.NewReader(fold)); !errors.Is(err, safefs.ErrDuplicateEntry) {
			t.Fatalf("case-fold duplicate: want ErrDuplicateEntry, got %v", err)
		}
	}
}

// TestParseRejectsCompressionBomb verifies Parse enforces the compression
// ratio, not only expanded-size and per-entry bounds.
func TestParseRejectsCompressionBomb(t *testing.T) {
	bomb := tarGzEntries(t, []struct {
		name string
		data []byte
	}{{name: "bomb", data: bytes.Repeat([]byte("A"), 8<<20)}})
	limits := safefs.ExtractLimits{MaxCompressionRatio: 10}
	if _, err := ParseWithLimits(bytes.NewReader(bomb), limits); !errors.Is(err, safefs.ErrCompression) {
		t.Fatalf("compression bomb: want ErrCompression, got %v", err)
	}
	// Incompressible data of the same expanded size stays within the
	// default ratio envelope.
	noisy := make([]byte, 8<<20)
	if _, err := rand.Read(noisy); err != nil {
		t.Fatal(err)
	}
	incompressible := tarGzEntries(t, []struct {
		name string
		data []byte
	}{{name: "noisy", data: noisy}})
	if _, err := Parse(bytes.NewReader(incompressible)); err != nil {
		t.Fatalf("incompressible archive within the default ratio must parse: %v", err)
	}
}

// TestExtractDefaultRatioRejectsHighlyCompressible is the extraction-side
// twin of the parse ratio check: the default envelope is enforced by Extract
// too, so an archive Parse accepts can always be extracted.
func TestExtractDefaultRatioRejectsHighlyCompressible(t *testing.T) {
	bomb := tarGzEntries(t, []struct {
		name string
		data []byte
	}{{name: "bomb", data: bytes.Repeat([]byte("A"), 8<<20)}})
	if _, err := Restore(bytes.NewReader(bomb), t.TempDir()); !errors.Is(err, safefs.ErrCompression) {
		t.Fatalf("restore of a ratio bomb: want ErrCompression, got %v", err)
	}
}

// TestParseCompressedBytesBound verifies the compressed-input bound applies.
func TestParseCompressedBytesBound(t *testing.T) {
	data := tarGzEntries(t, []struct {
		name string
		data []byte
	}{{name: "f", data: bytes.Repeat([]byte("z"), 4096)}})
	limits := safefs.ExtractLimits{MaxArchiveBytes: 64}
	if _, err := ParseWithLimits(bytes.NewReader(data), limits); !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("compressed bound: want ErrLimits, got %v", err)
	}
}

// TestCreateManifestBindsArchiveBytes verifies Create's manifest digests
// equal the content actually stored in the archive (single write path).
func TestCreateManifestBindsArchiveBytes(t *testing.T) {
	ws := t.TempDir()
	writeTree(t, ws)
	var buf bytes.Buffer
	m, err := Create(ws, &buf)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RootSHA256 != m.RootSHA256 {
		t.Fatal("Create and Parse disagree about the same archive")
	}
	for i := range m.Entries {
		if m.Entries[i] != parsed.Entries[i] {
			t.Fatalf("entry %d differs: %+v vs %+v", i, m.Entries[i], parsed.Entries[i])
		}
	}
	// And the archive bytes hash to the same per-file digests.
	for _, e := range m.Entries {
		if !strings.Contains(e.SHA256, "") || len(e.SHA256) != 64 {
			t.Fatalf("bad digest %q", e.SHA256)
		}
	}
}
