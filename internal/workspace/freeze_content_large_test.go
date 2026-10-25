package workspace

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestFreezeManifestContentHashBeyond1MiB: a same-size same-mtime rewrite
// of a file larger than 1 MiB must change the freeze stability digest
// (the previous 1 MiB cap left large files on size+mtime only).
func TestFreezeManifestContentHashBeyond1MiB(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "big.bin")
	// 2 MiB payload: above the old 1 MiB cap, below the 64 MiB full-hash cap.
	payload := bytes.Repeat([]byte("A"), 2<<20)
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	m1, err := freezeManifest(src, "")
	if err != nil {
		t.Fatal(err)
	}
	// Same size, same mtime, different content.
	payload2 := bytes.Repeat([]byte("B"), 2<<20)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload2, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	m2, err := freezeManifest(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if m1 == m2 {
		t.Fatal("same-size rewrite of a >1MiB file must change the freeze manifest")
	}
}
