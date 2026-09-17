package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireNonRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection does not apply to root")
	}
}

// TestDefaultStoreRoot proves Default anchors the store under the user's home.
func TestDefaultStoreRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	s := Default()
	want := filepath.Join(home, ".kiwi", "artifacts")
	if s.Root != want {
		t.Fatalf("Default().Root = %q, want %q", s.Root, want)
	}
}

// TestSaveOpenWorkspaceRootErrors proves Save rejects a workspace root that
// cannot be opened as an existing no-follow directory.
func TestSaveOpenWorkspaceRootErrors(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := s.Save("r", "j", "a", missing, []string{"."}); err == nil {
		t.Fatal("missing workspace must fail")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save("r", "j", "a", file, []string{"."}); err == nil {
		t.Fatal("file workspace must fail")
	}
	// A symlinked workspace root is rejected by the no-follow open.
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save("r", "j", "a", link, []string{"."}); err == nil {
		t.Fatal("symlinked workspace root must fail")
	}
}

// TestSaveStoreSetupErrors proves Save surfaces store-root failures:
// uncreatable directories, insufficient free space for the requested cap,
// an uncreatable temp file, and a rename blocked by an existing directory.
func TestSaveStoreSetupErrors(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// MkdirAll fails: the store root path is a regular file.
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Store{Root: blocked}).Save("r", "j", "a", ws, []string{"."}); err == nil {
		t.Fatal("store root under a regular file must fail")
	}

	// FitsAvailable fails: the cap cannot possibly fit.
	if _, err := (&Store{Root: t.TempDir(), MaxArtifactBytes: math.MaxInt64}).Save("r", "j", "a", ws, []string{"."}); err == nil {
		t.Fatal("impossible cap must fail the free-space check")
	}

	// os.Create of the temp archive fails: pre-create the same path as a
	// directory so creation is refused regardless of privileges.
	root := t.TempDir()
	jobDir := filepath.Join(root, "r", "j")
	if err := os.MkdirAll(filepath.Join(jobDir, "a.tar.gz.tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Store{Root: root}).Save("r", "j", "a", ws, []string{"."}); err == nil {
		t.Fatal("temp archive path occupied by a directory must fail")
	}

	// os.Rename fails: the destination archive path is already a directory.
	root2 := t.TempDir()
	jobDir2 := filepath.Join(root2, "r", "j")
	if err := os.MkdirAll(filepath.Join(jobDir2, "a.tar.gz"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Store{Root: root2}).Save("r", "j", "a", ws, []string{"."}); err == nil {
		t.Fatal("archive destination occupied by a directory must fail the rename")
	}
}

// TestSaveOpenArchiveAndManifestErrors proves Save surfaces failures after
// the rename: an unreadable archive for hashing, and a manifest path that
// cannot be written.
func TestSaveOpenArchiveAndManifestErrors(t *testing.T) {
	requireNonRoot(t)
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// os.WriteFile of the manifest fails: the manifest path is a directory.
	root2 := t.TempDir()
	jobDir := filepath.Join(root2, "r", "j")
	if err := os.MkdirAll(filepath.Join(jobDir, "a.tar.gz.manifest.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Store{Root: root2}).Save("r", "j", "a", ws, []string{"."}); err == nil {
		t.Fatal("manifest path occupied by a directory must fail")
	}
}

// TestSaveCloseAndCopyErrors proves the two checked post-write I/O failures
// surface instead of leaving a partial artifact.
func TestSaveCloseAndCopyErrors(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	origClose := closeArtifactFile
	closeArtifactFile = func(*os.File) error { return errors.New("close refused") }
	root := t.TempDir()
	if _, err := (&Store{Root: root}).Save("r", "j", "a", ws, []string{"."}); err == nil {
		t.Fatal("close failure must surface")
	}
	closeArtifactFile = origClose
	// The failed close must not leave the temp archive behind.
	entries, err := os.ReadDir(filepath.Join(root, "r", "j"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("close failure left %q behind", e.Name())
	}

	origCopy := copyDigest
	copyDigest = func(io.Writer, io.Reader) (int64, error) {
		return 0, errors.New("copy refused")
	}
	defer func() { copyDigest = origCopy }()
	if _, err := (&Store{Root: t.TempDir()}).Save("r", "j", "a", ws, []string{"."}); err == nil {
		t.Fatal("digest copy failure must surface")
	}
}

// TestVerifyCaptureRootsMissingPath proves a capture root that does not
// exist is skipped rather than rejected.
func TestVerifyCaptureRootsMissingPath(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "real"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	canon, err := filepath.EvalSymlinks(ws)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCaptureRoots(canon, []string{"missing", "real"}); err != nil {
		t.Fatalf("missing capture root must be skipped: %v", err)
	}
}

// TestWithinWorkspaceMixedPaths proves the relative-mismatch guard reports
// false instead of guessing.
func TestWithinWorkspaceMixedPaths(t *testing.T) {
	abs := t.TempDir()
	if withinWorkspace("relative-root", filepath.Join(abs, "child")) {
		t.Fatal("mixed relative/absolute paths must not be reported as contained")
	}
	if !withinWorkspace(abs, abs) {
		t.Fatal("root must contain itself")
	}
	if !withinWorkspace(abs, filepath.Join(abs, "child")) {
		t.Fatal("child must be contained")
	}
	if withinWorkspace(abs, filepath.Dir(abs)) {
		t.Fatal("parent must not be contained")
	}
}

// TestValidateManifestErrorMatrix exercises every rejection branch of
// ValidateManifest plus the accepted boundary shapes.
func TestValidateManifestErrorMatrix(t *testing.T) {
	digest := strings.Repeat("a", 64)
	entry := ArtifactEntry{Path: "x", Mode: 0o644, Size: 1, SHA256: digest}
	base := func() ArtifactManifest {
		return ArtifactManifest{Version: 1, SHA256: digest, Size: 1, Entries: []ArtifactEntry{entry}}
	}

	cases := map[string]func(m *ArtifactManifest){
		"version":           func(m *ArtifactManifest) { m.Version = 2 },
		"archive digest":    func(m *ArtifactManifest) { m.SHA256 = "nothex" },
		"negative size":     func(m *ArtifactManifest) { m.Size = -1 },
		"empty entry path":  func(m *ArtifactManifest) { m.Entries[0].Path = "" },
		"entry digest":      func(m *ArtifactManifest) { m.Entries[0].SHA256 = "zz" },
		"negative entry":    func(m *ArtifactManifest) { m.Entries[0].Size = -1 },
		"unsafe entry":      func(m *ArtifactManifest) { m.Entries[0].Path = "../esc" },
		"sbom absolute":     func(m *ArtifactManifest) { m.SBOMPath = "/etc/passwd" },
		"sbom dotdot":       func(m *ArtifactManifest) { m.SBOMPath = "a/../b" },
		"sbom backslash":    func(m *ArtifactManifest) { m.SBOMPath = `a\..\b` },
		"empty envelope":    func(m *ArtifactManifest) { m.Sigstore = &SigstoreAttestation{Envelope: nil} },
		"bad sig digest":    func(m *ArtifactManifest) { m.Sigstore = &SigstoreAttestation{Envelope: []byte{1}, Digest: "short"} },
		"fine sbom":         func(m *ArtifactManifest) { m.SBOMPath = "sbom/out.spdx.json" },
		"fine sig store":    func(m *ArtifactManifest) { m.Sigstore = &SigstoreAttestation{Envelope: []byte{1}} },
		"fine sig digest":   func(m *ArtifactManifest) { m.Sigstore = &SigstoreAttestation{Envelope: []byte{1}, Digest: digest} },
		"fine zero mode":    func(m *ArtifactManifest) { m.Entries[0].Mode = 0 },
		"fine nil entries":  func(m *ArtifactManifest) { m.Entries = nil },
		"fine exact digest": func(m *ArtifactManifest) {},
	}
	reject := map[string]bool{
		"version": true, "archive digest": true, "negative size": true,
		"empty entry path": true, "entry digest": true, "negative entry": true,
		"unsafe entry": true, "sbom absolute": true, "sbom dotdot": true,
		"sbom backslash": true, "empty envelope": true, "bad sig digest": true,
	}
	for label, mutate := range cases {
		m := base()
		mutate(&m)
		err := ValidateManifest(m)
		if reject[label] && err == nil {
			t.Errorf("%s: manifest accepted, want rejection", label)
		}
		if !reject[label] && err != nil {
			t.Errorf("%s: manifest rejected: %v", label, err)
		}
	}
}

// TestSaveManifestErrors proves SaveManifest rejects invalid manifests,
// propagates JSON encoding failures (an unrepresentable timestamp), and
// surfaces write failures.
func TestSaveManifestErrors(t *testing.T) {
	valid := ArtifactManifest{Version: 1, SHA256: strings.Repeat("a", 64), Size: 1}

	if _, err := (&Store{}).SaveManifest(filepath.Join(t.TempDir(), "a"), ArtifactManifest{}); err == nil {
		t.Fatal("invalid manifest must be rejected before writing")
	}

	// An unserializable CreatedAt drives the json.MarshalIndent error path.
	bad := valid
	bad.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := (&Store{}).SaveManifest(filepath.Join(t.TempDir(), "a"), bad); err == nil {
		t.Fatal("unrepresentable timestamp must fail encoding")
	}

	// A write failure: the manifest path is a directory.
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.gz")
	if err := os.Mkdir(archive+".manifest.json", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Store{}).SaveManifest(archive, valid); err == nil {
		t.Fatal("manifest write into a directory must fail")
	}

	// Happy path: bytes parse back and validate.
	archive2 := filepath.Join(t.TempDir(), "b.tar.gz")
	p, err := (&Store{}).SaveManifest(archive2, valid)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ArtifactManifest
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(decoded); err != nil {
		t.Fatal(err)
	}
}

// TestReadManifestErrors proves read failures and decode failures surface.
func TestReadManifestErrors(t *testing.T) {
	if _, err := ReadManifest(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing manifest must fail")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(bad); err == nil {
		t.Fatal("invalid JSON must fail")
	}
}

func writeBytes(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func manifestFor(b []byte) ArtifactManifest {
	return ArtifactManifest{Version: 1, SHA256: sum(b), Size: int64(len(b))}
}

// TestVerifyArchiveIOErrors proves VerifyArchive surfaces a manifest
// rejection, an unopenable archive, a read failure from a non-regular file,
// a size mismatch, a digest mismatch, a seek refusal (FIFO), and non-gzip
// content.
func TestVerifyArchiveIOErrors(t *testing.T) {
	dir := t.TempDir()

	// Manifest rejection short-circuits before any file access.
	if err := VerifyArchive("", ArtifactManifest{}); err == nil {
		t.Fatal("invalid manifest must fail")
	}

	// Unopenable archive.
	if err := VerifyArchive(filepath.Join(dir, "missing"), ArtifactManifest{Version: 1, SHA256: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("missing archive must fail")
	}

	// Reading a directory yields an I/O error from io.Copy.
	if err := VerifyArchive(dir, ArtifactManifest{Version: 1, SHA256: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("directory archive must fail the digest read")
	}

	// Size mismatch: the digest is right but the recorded size is not.
	data := []byte("some archive bytes")
	p := writeBytes(t, "a.bin", data)
	m := manifestFor(data)
	m.Size++
	if err := VerifyArchive(p, m); err == nil {
		t.Fatal("size mismatch must fail")
	}

	// Digest mismatch with a matching size.
	m = manifestFor(data)
	m.SHA256 = strings.Repeat("b", 64)
	if err := VerifyArchive(p, m); err == nil {
		t.Fatal("digest mismatch must fail")
	}

	// Non-gzip content with a matching manifest.
	if err := VerifyArchive(p, manifestFor(data)); err == nil {
		t.Fatal("non-gzip content must fail")
	}
}

// TestVerifyArchiveEntryErrorMatrix proves the per-entry checks reject mode
// mismatches, corrupt tar streams, truncated entries, and unsafe names even
// when the manifest matches the archive bytes exactly.
func TestVerifyArchiveEntryErrorMatrix(t *testing.T) {
	buildGz := func(raw []byte) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write(raw)
		_ = gz.Close()
		return buf.Bytes()
	}
	rawTar := func(name string, mode int64, data []byte) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(data))})
		_, _ = tw.Write(data)
		_ = tw.Close()
		return buf.Bytes()
	}

	// Mode mismatch.
	data := []byte("payload")
	gzBytes := buildGz(rawTar("x", 0o644, data))
	p := writeBytes(t, "mode.tar.gz", gzBytes)
	m := manifestFor(gzBytes)
	m.Entries = []ArtifactEntry{{Path: "x", Mode: 0o755, Size: int64(len(data)), SHA256: sum(data)}}
	if err := VerifyArchive(p, m); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("mode mismatch = %v, want mode error", err)
	}

	// Corrupt tar stream inside a valid gzip container: tar.Next fails.
	garbage := buildGz([]byte("this is not a tar stream at all, but it is long enough to look like one to a first read"))
	p2 := writeBytes(t, "garbage.tar.gz", garbage)
	if err := VerifyArchive(p2, manifestFor(garbage)); err == nil {
		t.Fatal("garbage tar stream must fail")
	}

	// Truncated entry: the header declares more bytes than the stream holds.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 100})
	_, _ = tw.Write([]byte("short"))
	// Close gzip without closing the tar writer: the entry never completes.
	_ = gz.Close()
	truncated := buf.Bytes()
	p3 := writeBytes(t, "truncated.tar.gz", truncated)
	m3 := manifestFor(truncated)
	m3.Entries = []ArtifactEntry{{Path: "x", Mode: 0, Size: 100, SHA256: sum([]byte("short"))}}
	if err := VerifyArchive(p3, m3); err == nil {
		t.Fatal("truncated entry must fail")
	}
}

// TestExtractErrorBranches proves Extract surfaces destination creation
// failures, unopenable archives, and a symlinked destination root.
func TestExtractErrorBranches(t *testing.T) {
	// A valid archive to keep the failure at the intended stage.
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	archive, err := (&Store{Root: t.TempDir()}).Save("r", "j", "a", ws, []string{"."})
	if err != nil {
		t.Fatal(err)
	}

	// MkdirAll failure: a parent component is a regular file.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Extract(archive, filepath.Join(blocker, "dest")); err == nil {
		t.Fatal("dest under a regular file must fail")
	}

	// Archive open failure.
	if err := Extract(filepath.Join(t.TempDir(), "missing.tar.gz"), t.TempDir()); err == nil {
		t.Fatal("missing archive must fail")
	}

	// Symlinked destination: MkdirAll follows the link, the no-follow root
	// open rejects it.
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := Extract(archive, link); err == nil {
		t.Fatal("symlinked destination must fail")
	}

	// Happy path still works after all of the above.
	if err := Extract(archive, t.TempDir()); err != nil {
		t.Fatalf("valid extraction: %v", err)
	}
}

// TestVerifyArchiveUndeclaredAndMissing proves the archive-side entry-set
// checks: undeclared entries, duplicate entries, and manifest entries absent
// from the archive.
func TestVerifyArchiveUndeclaredAndMissing(t *testing.T) {
	build := func(entries ...struct {
		name string
		data string
	}) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for _, e := range entries {
			_ = tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e.data))})
			_, _ = tw.Write([]byte(e.data))
		}
		_ = tw.Close()
		_ = gz.Close()
		return buf.Bytes()
	}
	type ent = struct {
		name string
		data string
	}

	// Undeclared entry.
	b := build(ent{"a", "1"}, ent{"b", "2"})
	p := writeBytes(t, "u.tar.gz", b)
	m := manifestFor(b)
	m.Entries = []ArtifactEntry{{Path: "a", Mode: 0o644, Size: 1, SHA256: sum([]byte("1"))}}
	if err := VerifyArchive(p, m); err == nil {
		t.Fatal("undeclared entry must fail")
	}

	// Manifest entry missing from the archive.
	b2 := build(ent{"a", "1"})
	p2 := writeBytes(t, "m.tar.gz", b2)
	m2 := manifestFor(b2)
	m2.Entries = []ArtifactEntry{
		{Path: "a", Mode: 0o644, Size: 1, SHA256: sum([]byte("1"))},
		{Path: "gone", Mode: 0o644, Size: 1, SHA256: sum([]byte("x"))},
	}
	if err := VerifyArchive(p2, m2); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing manifest entry = %v, want missing error", err)
	}

	// Directory entries are skipped by the entry-set check.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "dir/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "dir/f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("1"))
	_ = tw.Close()
	_ = gz.Close()
	b3 := buf.Bytes()
	p3 := writeBytes(t, "d.tar.gz", b3)
	m3 := manifestFor(b3)
	m3.Entries = []ArtifactEntry{{Path: "dir/f", Mode: 0o644, Size: 1, SHA256: sum([]byte("1"))}}
	if err := VerifyArchive(p3, m3); err != nil {
		t.Fatalf("directory entries must be skipped: %v", err)
	}

	// Zero-mode manifest entries skip the mode comparison.
	b4 := build(ent{"x", "1"})
	p4 := writeBytes(t, "z.tar.gz", b4)
	m4 := manifestFor(b4)
	m4.Entries = []ArtifactEntry{{Path: "x", Mode: 0, Size: 1, SHA256: sum([]byte("1"))}}
	if err := VerifyArchive(p4, m4); err != nil {
		t.Fatalf("zero mode entry: %v", err)
	}

	// Entry digest mismatch with correct size.
	b5 := build(ent{"x", "1"})
	p5 := writeBytes(t, "h.tar.gz", b5)
	m5 := manifestFor(b5)
	m5.Entries = []ArtifactEntry{{Path: "x", Mode: 0o644, Size: 1, SHA256: sum([]byte("2"))}}
	if err := VerifyArchive(p5, m5); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("entry digest mismatch = %v, want digest error", err)
	}
}

// TestVerifyArchiveShortEntryRead proves the yielded-bytes guard: a tar
// entry whose copy ends without error but short of the declared size is
// rejected.
func TestVerifyArchiveShortEntryRead(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4})
	_, _ = tw.Write([]byte("data"))
	_ = tw.Close()
	_ = gz.Close()
	b := buf.Bytes()
	p := writeBytes(t, "short.tar.gz", b)
	m := manifestFor(b)
	m.Entries = []ArtifactEntry{{Path: "x", Mode: 0o644, Size: 4, SHA256: sum([]byte("data"))}}

	orig := copyDigest
	copyDigest = func(io.Writer, io.Reader) (int64, error) { return 0, nil }
	defer func() { copyDigest = orig }()
	if err := VerifyArchive(p, m); err == nil || !strings.Contains(err.Error(), "yielded") {
		t.Fatalf("short entry read = %v, want yielded error", err)
	}
}

// TestArtifactEntryDigestEncoding pins that entry digests are hex-encoded
// SHA-256 over the archived bytes.
func TestArtifactEntryDigestEncoding(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := (&Store{Root: t.TempDir()}).Save("r", "j", "a", ws, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ReadManifest(path + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("abc"))
	want := hex.EncodeToString(h[:])
	for _, e := range m.Entries {
		if e.Path == "f" && e.SHA256 != want {
			t.Fatalf("entry digest = %s, want %s", e.SHA256, want)
		}
	}
}
