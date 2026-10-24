package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

// Same size + restored mtime must still be detected as a content change
// during freeze (metadata-only manifest was a known hole).
func TestFreezeDetectsSameSizeMtimeContentChange(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "cfg.txt")
	if err := os.WriteFile(path, []byte("AAAA"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Freeze snapshot of source: we only compare freezeManifest directly
	// by mutating between two manifest calls (same as freeze A/B).
	before, err := freezeManifest(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("BBBB"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Restore size/mtime so metadata-only would match.
	if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := freezeManifest(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("freezeManifest ignored same-size same-mtime content change")
	}
}
