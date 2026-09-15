package safefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// fuzzExtractLimits bounds every resource the extractor can consume so
// adversarial archives cannot wedge the fuzz worker: archive bytes, expanded
// bytes, per-file bytes, entry count, path length, depth and compression
// ratio are all capped far below the defaults.
func fuzzExtractLimits() ExtractLimits {
	return ExtractLimits{
		MaxArchiveBytes:     1 << 20,
		MaxExpandedBytes:    1 << 20,
		MaxFileBytes:        1 << 18,
		MaxEntries:          1024,
		MaxPathLength:       256,
		MaxDepth:            16,
		MaxCompressionRatio: 64,
	}
}

func fuzzTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		body := entries[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
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

// extractTo runs the hardened extractor beneath a held destination handle.
func extractTo(t *testing.T, data []byte, dest string, limits ExtractLimits) (*ExtractStats, error) {
	t.Helper()
	root, err := OpenRootNoFollow(dest)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return Extract(root, bytes.NewReader(data), limits)
}

// TestFuzzTarGzRoundTrip drives the deterministic archive builder through
// the hardened extractor: every regular entry is materialized under the
// destination with its content intact.
func TestFuzzTarGzRoundTrip(t *testing.T) {
	data := fuzzTarGz(t, map[string]string{"a.txt": "hi\n", "dir/b.txt": "ok\n"})
	dest := t.TempDir()
	stats, err := extractTo(t, data, dest, fuzzExtractLimits())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if stats.Files != 2 || stats.Bytes != 6 {
		t.Fatalf("stats = %+v, want 2 files and 6 bytes", stats)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "a.txt")); err != nil || string(b) != "hi\n" {
		t.Fatalf("a.txt = %q, %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "dir", "b.txt")); err != nil || string(b) != "ok\n" {
		t.Fatalf("dir/b.txt = %q, %v", b, err)
	}
}

// TestFuzzTarGzTraversalRejected verifies the extractor's confinement
// boundary: an entry that escapes the workspace is an error, never a write
// outside the destination.
func TestFuzzTarGzTraversalRejected(t *testing.T) {
	data := fuzzTarGz(t, map[string]string{"../evil.txt": "x"})
	dest := t.TempDir()
	if _, err := extractTo(t, data, dest, fuzzExtractLimits()); err == nil {
		t.Fatal("expected parent-traversal entry to be rejected")
	}
}

// FuzzArtifactExtract drives the hardened extractor with an arbitrary
// artifact archive. Extraction is a security boundary: untrusted input must
// never panic, and successful extractions must be confined to the workspace
// destination.
func FuzzArtifactExtract(f *testing.F) {
	f.Add(fuzzTarGzSeed())
	f.Add([]byte("not a gzip stream"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		dest := t.TempDir()
		root, err := OpenRootNoFollow(dest)
		if err != nil {
			return
		}
		defer root.Close()
		_, _ = Extract(root, bytes.NewReader(data), fuzzExtractLimits())
	})
}

// FuzzCacheExtract drives the same hardened extractor on the cache-restore
// path. Cache archives come from a remote control plane and are equally
// untrusted; the same confinement contract applies.
func FuzzCacheExtract(f *testing.F) {
	f.Add(fuzzTarGzSeed())
	f.Add([]byte("garbage-garbage-garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dest := t.TempDir()
		root, err := OpenRootNoFollow(dest)
		if err != nil {
			return
		}
		defer root.Close()
		_, _ = Extract(root, bytes.NewReader(data), fuzzExtractLimits())
	})
}

func fuzzTarGzSeed() []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi\n"))
	_ = tw.WriteHeader(&tar.Header{Name: "dir/b.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("ok\n"))
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}
