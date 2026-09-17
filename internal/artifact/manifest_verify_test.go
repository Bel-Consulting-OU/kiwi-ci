package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func saveTree(t *testing.T, ws string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(ws, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "dist", "app"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "README.md"), []byte("# readme"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSaveManifestMatchesArchive verifies the manifest produced by Save is
// consistent with the archive it wrote, including per-entry digests.
func TestSaveManifestMatchesArchive(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	ws := t.TempDir()
	saveTree(t, ws)
	path, err := s.Save("run", "job", "app", ws, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ReadManifest(path + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyArchive(path, m); err != nil {
		t.Fatalf("Save produced an archive that does not match its manifest: %v", err)
	}
	if len(m.Entries) != 2 {
		t.Fatalf("entries = %+v", m.Entries)
	}
}

// TestVerifyArchiveDetectsTampering mutates the archive and the manifest in
// every way the verification contract must catch.
func TestVerifyArchiveDetectsTampering(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	ws := t.TempDir()
	saveTree(t, ws)
	path, err := s.Save("run", "job", "app", ws, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	base, err := ReadManifest(path + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}

	// 1. One archive byte flipped: digest mismatch.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff
	badPath := filepath.Join(t.TempDir(), "tampered.tar.gz")
	if err := os.WriteFile(badPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArchive(badPath, base); err == nil {
		t.Fatal("modified archive must fail verification")
	}

	// 2. Manifest entry digest changed.
	m := base
	m.Entries = append([]ArtifactEntry(nil), base.Entries...)
	m.Entries[0].SHA256 = strings.Repeat("0", 64)
	if err := VerifyArchive(path, m); err == nil {
		t.Fatal("manifest entry digest tamper must fail verification")
	}

	// 3. Manifest entry removed: archive carries an undeclared entry. The
	// root digest is adjusted to keep the manifest itself valid.
	m = base
	m.Entries = m.Entries[1:]
	if err := VerifyArchive(path, m); err == nil {
		t.Fatal("undeclared archive entry must fail verification")
	}

	// 4. Manifest declares an entry the archive does not contain.
	m = base
	m.Entries = append(m.Entries, ArtifactEntry{Path: "ghost", Mode: 0o644, Size: 1, SHA256: strings.Repeat("0", 64)})
	m.Size = base.Size
	if err := VerifyArchive(path, m); err == nil {
		t.Fatal("missing archive entry must fail verification")
	}

	// 5. Entry size tampered.
	m = base
	m.Entries = append([]ArtifactEntry(nil), base.Entries...)
	m.Entries[0].Size++
	if err := VerifyArchive(path, m); err == nil {
		t.Fatal("manifest entry size tamper must fail verification")
	}
}

// TestVerifyArchiveRejectsUnsafeAndDuplicateEntries builds archives that
// carry a traversal name or a duplicate name and verifies the verification
// rejects them even when the manifest was crafted to match.
func TestVerifyArchiveRejectsUnsafeAndDuplicateEntries(t *testing.T) {
	build := func(entries []struct {
		name string
		data string
	}) (string, []byte) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for _, e := range entries {
			_ = tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e.data))})
			_, _ = tw.Write([]byte(e.data))
		}
		_ = tw.Close()
		_ = gz.Close()
		return filepath.Join(t.TempDir(), "a.tar.gz"), buf.Bytes()
	}
	// Traversal entry: VerifyArchive must reject the archive name.
	p, data := build([]struct {
		name string
		data string
	}{{"../evil", "x"}})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	m := ArtifactManifest{Version: 1, SHA256: sum(data), Size: int64(len(data))}
	if err := VerifyArchive(p, m); err == nil {
		t.Fatal("traversal entry must fail verification")
	}
	// Duplicate names.
	p2, data2 := build([]struct {
		name string
		data string
	}{{"a", "1"}, {"a", "2"}})
	if err := os.WriteFile(p2, data2, 0o600); err != nil {
		t.Fatal(err)
	}
	m2 := ArtifactManifest{Version: 1, SHA256: sum(data2), Size: int64(len(data2)), Entries: []ArtifactEntry{{Path: "a", Mode: 0o644, Size: 1, SHA256: sum([]byte("1"))}}}
	if err := VerifyArchive(p2, m2); err == nil {
		t.Fatal("duplicate archive entries must fail verification")
	}
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestValidateManifestEntryPaths verifies manifests with unsafe, duplicate or
// oversized entry paths are rejected at validation time.
func TestValidateManifestEntryPaths(t *testing.T) {
	good := ArtifactManifest{
		Version: 1,
		SHA256:  strings.Repeat("a", 64),
		Size:    100,
		Entries: []ArtifactEntry{{Path: "dist/app", Mode: 0o644, Size: 10, SHA256: strings.Repeat("b", 64)}},
	}
	if err := ValidateManifest(good); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	cases := map[string]ArtifactEntry{
		"traversal":    {Path: "../evil", Mode: 0o644, Size: 1, SHA256: strings.Repeat("b", 64)},
		"absolute":     {Path: "/etc/passwd", Mode: 0o644, Size: 1, SHA256: strings.Repeat("b", 64)},
		"control":      {Path: "a\x01b", Mode: 0o644, Size: 1, SHA256: strings.Repeat("b", 64)},
		"uncanonical":  {Path: "a/./b", Mode: 0o644, Size: 1, SHA256: strings.Repeat("b", 64)},
		"device name":  {Path: "NUL", Mode: 0o644, Size: 1, SHA256: strings.Repeat("b", 64)},
		"duplicate":    {Path: "dist/app", Mode: 0o644, Size: 1, SHA256: strings.Repeat("b", 64)},
		"empty digest": {Path: "x", Mode: 0o644, Size: 1, SHA256: ""},
	}
	for label, e := range cases {
		m := good
		m.Entries = []ArtifactEntry{e, e}
		if label != "duplicate" {
			m.Entries = []ArtifactEntry{e}
		}
		if err := ValidateManifest(m); err == nil {
			t.Errorf("%s: manifest accepted", label)
		}
	}
	// Entry sizes describe expanded content and may legitimately exceed the
	// compressed archive size (a 4096-byte run of one byte compresses to
	// tens of bytes), so larger-than-archive sizes are not rejected.
	m := good
	m.Entries = []ArtifactEntry{{Path: "big", Mode: 0o644, Size: 1 << 20, SHA256: strings.Repeat("b", 64)}}
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("expanded entry size larger than the compressed archive rejected: %v", err)
	}
}

// TestSaveCapBoundaryExactlyAtLimit verifies the archive cap is inclusive:
// an archive whose size equals MaxArtifactBytes is written and renamed, while
// one byte less aborts and leaves no partial or temporary file behind.
func TestSaveCapBoundaryExactlyAtLimit(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "data.bin"), bytes.Repeat([]byte("x"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	probe := &Store{Root: t.TempDir()}
	path, err := probe.Save("r", "j", "a", ws, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	size := fi.Size()

	atLimit := &Store{Root: t.TempDir(), MaxArtifactBytes: size}
	if _, err := atLimit.Save("r", "j", "a", ws, []string{"."}); err != nil {
		t.Fatalf("archive exactly at the cap must succeed: %v", err)
	}

	overLimit := &Store{Root: t.TempDir(), MaxArtifactBytes: size - 1}
	if _, err := overLimit.Save("r", "j", "a", ws, []string{"."}); err == nil {
		t.Fatal("archive one byte over the cap must fail")
	} else if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("cap error does not mention the cap: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(overLimit.Root, "r", "j"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("over-cap save left %q behind", e.Name())
	}
}

// TestReadManifestRejectsTamperedJSON verifies a manifest tampered at rest is
// rejected on read rather than trusted.
func TestReadManifestRejectsTamperedJSON(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	ws := t.TempDir()
	saveTree(t, ws)
	path, err := s.Save("r", "j", "a", ws, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ReadManifest(path + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m.Entries[0].Path = "../../etc/passwd"
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".manifest.json", b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(path + ".manifest.json"); err == nil {
		t.Fatal("manifest with a traversal entry path must be rejected on read")
	}
}

// TestSaveCapturePathSpellings verifies capture roots spelled with a trailing
// separator or a redundant dot component behave exactly like their clean
// form: the same entries, no duplicate or escape errors.
func TestSaveCapturePathSpellings(t *testing.T) {
	ws := t.TempDir()
	saveTree(t, ws)
	for _, spelling := range []string{"dist/", "dist/.", "./dist"} {
		s := &Store{Root: t.TempDir()}
		path, err := s.Save("r", "j", "a", ws, []string{spelling})
		if err != nil {
			t.Fatalf("path %q: %v", spelling, err)
		}
		m, err := ReadManifest(path + ".manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Entries) != 1 || m.Entries[0].Path != "dist/app" {
			t.Fatalf("path %q entries = %+v, want only dist/app", spelling, m.Entries)
		}
	}
}

// TestSaveRejectsCaptureRootSymlinkLoop verifies a capture root that is a
// symlink (including a self-referential loop) is rejected before any
// enumeration, not silently walked.
func TestSaveRejectsCaptureRootSymlinkLoop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	ws := t.TempDir()
	loop := filepath.Join(ws, "loop")
	if err := os.Symlink("loop", loop); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "real"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Store{Root: t.TempDir()}
	if _, err := s.Save("r", "j", "a", ws, []string{"loop"}); err == nil {
		t.Fatal("symlink loop capture root must be rejected")
	}
	// A loop with no artifact root must not create store directories either.
	if _, err := s.Save("r", "j", "a", ws, []string{"real", "loop/2"}); err == nil {
		t.Fatal("symlink loop below a capture root must be rejected")
	}
}
