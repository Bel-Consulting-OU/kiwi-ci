package snapshot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// emptyFileArchive builds a tar.gz of n zero-byte regular files with short
// names: the pathological shape that previously let the manifest entry
// slice/map grow without bound because zero-byte bodies contribute nothing to
// the expansion budget.
func emptyFileArchive(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := 0; i < n; i++ {
		if err := tw.WriteHeader(&tar.Header{
			Name:     fmt.Sprintf("f%06d", i),
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     0,
		}); err != nil {
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

// TestParseRejectsEmptyFileFlood is the G2-C regression: a 200k-empty-files
// archive is rejected with a typed limit error (default MaxEntries scale)
// before the full entry slice/map is built.
func TestParseRejectsEmptyFileFlood(t *testing.T) {
	data := emptyFileArchive(t, 200_000)
	if _, err := Parse(bytes.NewReader(data)); !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("200k empty files: want ErrLimits, got %v", err)
	}
}

// TestParseManifestMetadataCap pins the aggregate metadata bound directly:
// even with the old permissive MaxEntries the 300k-empty-files archive is
// rejected by the sum of path bytes plus per-entry overhead, with a typed
// ErrLimits that names the metadata budget.
func TestParseManifestMetadataCap(t *testing.T) {
	data := emptyFileArchive(t, 300_000)
	_, err := ParseWithLimits(bytes.NewReader(data), safefs.ExtractLimits{MaxEntries: 1_000_000})
	if !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("metadata cap: want ErrLimits, got %v", err)
	}
	if !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("metadata cap error must name the metadata budget: %v", err)
	}
	// A manifest whose aggregate metadata is within the budget still parses.
	small := emptyFileArchive(t, 100)
	if _, err := Parse(bytes.NewReader(small)); err != nil {
		t.Fatalf("small manifest rejected: %v", err)
	}
}

// TestParseCountsHeadersTowardExpansion pins the header charge: every tar
// header (including zero-byte regular files) consumes manifestHeaderBytes of
// the expansion budget.
func TestParseCountsHeadersTowardExpansion(t *testing.T) {
	data := emptyFileArchive(t, 3)
	exact := safefs.ExtractLimits{MaxExpandedBytes: 3 * manifestHeaderBytes}
	if _, err := ParseWithLimits(bytes.NewReader(data), exact); err != nil {
		t.Fatalf("exactly at header expansion budget: %v", err)
	}
	under := safefs.ExtractLimits{MaxExpandedBytes: 3*manifestHeaderBytes - 1}
	if _, err := ParseWithLimits(bytes.NewReader(data), under); !errors.Is(err, safefs.ErrLimits) {
		t.Fatalf("one byte under header budget: want ErrLimits, got %v", err)
	}
}
