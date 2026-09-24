package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// savedCache builds a store with one saved archive and returns the store, the
// key and the workspace the archive was captured from.
func savedCache(t *testing.T) (*Store, string, string) {
	t.Helper()
	root := t.TempDir()
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Store{Root: root}
	key := "deadbeef"
	if err := s.Save(key, ws, []string{"f"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return s, key, ws
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// TestSaveDirSyncFailureLeavesNoArchiveOrSidecar proves a failed directory
// fsync after the rename fails the save and removes the published-but-
// uncertain archive; no digest sidecar and no temp file remain.
func TestSaveDirSyncFailureLeavesNoArchiveOrSidecar(t *testing.T) {
	restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(string) error {
		return errors.New("dir sync refused")
	}})
	defer restore()

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := (&Store{Root: root}).Save("deadbeef", ws, []string{"f"}); err == nil {
		t.Fatal("archive dir-sync failure must surface")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("dir-sync failure left %q behind", e.Name())
	}
}

// TestSaveSyncFailureLeavesNoTemp proves a failed file fsync surfaces and
// removes the unique temp file.
func TestSaveSyncFailureLeavesNoTemp(t *testing.T) {
	orig := syncCacheFile
	syncCacheFile = func(*os.File) error { return errors.New("sync refused") }
	defer func() { syncCacheFile = orig }()

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := (&Store{Root: root}).Save("deadbeef", ws, []string{"f"}); err == nil {
		t.Fatal("file sync failure must surface")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("sync failure left %q behind", e.Name())
	}
}

// TestSaveWritesMatchingDigestSidecar proves Save records the digest of the
// exact archive bytes it published.
func TestSaveWritesMatchingDigestSidecar(t *testing.T) {
	s, key, _ := savedCache(t)
	archive := readFile(t, s.archivePath(key))
	sum := sha256.Sum256(archive)
	want := hex.EncodeToString(sum[:])
	got := strings.TrimSpace(string(readFile(t, s.stripChecksumPath(key))))
	if got != want {
		t.Fatalf("stored digest = %s, want %s", got, want)
	}
}

// TestRestoreRejectsStoredDigestMismatch proves a tampered local archive
// (sidecar mismatch) fails closed instead of extracting.
func TestRestoreRejectsStoredDigestMismatch(t *testing.T) {
	s, key, _ := savedCache(t)
	if err := os.WriteFile(s.archivePath(key), []byte("tampered bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	hit, err := s.Restore(key, dest, nil)
	if err == nil || hit {
		t.Fatalf("tampered archive = (%v, %v), want error", hit, err)
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Fatalf("error = %v, want digest mismatch", err)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "f")); !os.IsNotExist(statErr) {
		t.Fatal("tampered archive was extracted")
	}
}

// TestRestoreFailsClosedOnMissingSidecar proves a local archive with no
// stored digest is never extracted and surfaces fail-closed when no remote is
// configured.
func TestRestoreFailsClosedOnMissingSidecar(t *testing.T) {
	s, key, _ := savedCache(t)
	if err := os.Remove(s.stripChecksumPath(key)); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	hit, err := s.Restore(key, dest, nil)
	if err == nil || hit {
		t.Fatalf("unverifiable archive = (%v, %v), want fail-closed error", hit, err)
	}
	if !errors.Is(err, errLocalUnverified) {
		t.Fatalf("error = %v, want errLocalUnverified", err)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "f")); !os.IsNotExist(statErr) {
		t.Fatal("unverifiable archive was extracted")
	}
}

// TestRestoreFallsBackToRemoteWhenLocalUnverified proves an unverifiable
// local archive is not extracted but a configured remote can replace it and
// satisfy the restore.
func TestRestoreFallsBackToRemoteWhenLocalUnverified(t *testing.T) {
	s, key, _ := savedCache(t)
	if err := os.Remove(s.stripChecksumPath(key)); err != nil {
		t.Fatal(err)
	}
	archive := readFile(t, s.archivePath(key))
	sum := sha256.Sum256(archive)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderCacheSHA256, hex.EncodeToString(sum[:]))
		_, _ = w.Write(archive)
	}))
	t.Cleanup(srv.Close)
	s.RemoteURL = srv.URL

	dest := t.TempDir()
	hit, err := s.Restore(key, dest, []string{"f"})
	if err != nil || !hit {
		t.Fatalf("remote fallback = (%v, %v), want hit", hit, err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "f")); err != nil || string(b) != "payload" {
		t.Fatalf("restored content = %q, %v", b, err)
	}
	if _, err := os.Stat(s.stripChecksumPath(key)); err != nil {
		t.Fatalf("remote fetch did not record a verifiable sidecar: %v", err)
	}
}

// TestFetchRemoteRejectsOversizedBody proves the download is bounded and a
// body past the bound is rejected without publishing anything.
func TestFetchRemoteRejectsOversizedBody(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	root := t.TempDir()
	s := &Store{Root: root, RemoteURL: srv.URL, MaxCacheBytes: 8}
	if err := s.fetchRemote("deadbeef"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized body = %v, want exceeds error", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("oversized download left %q behind", e.Name())
	}
}

// TestFetchRemoteRejectsDigestMismatch proves a body that does not hash to
// the endpoint-advertised digest is rejected before publication.
func TestFetchRemoteRejectsDigestMismatch(t *testing.T) {
	body := []byte("some archive bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderCacheSHA256, strings.Repeat("0", 64))
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	root := t.TempDir()
	s := &Store{Root: root, RemoteURL: srv.URL}
	if err := s.fetchRemote("deadbeef"); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("mismatched body = %v, want digest mismatch", err)
	}
	if _, err := os.Stat(s.archivePath("deadbeef")); !os.IsNotExist(err) {
		t.Fatal("mismatched body was published")
	}
}

// TestFetchRemoteVerifiesAndRecordsDigest proves a verified download is
// published with a matching sidecar and is then locally restorable.
func TestFetchRemoteVerifiesAndRecordsDigest(t *testing.T) {
	archive := testArchive(t)
	sum := sha256.Sum256(archive)
	digest := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderCacheSHA256, digest)
		_, _ = w.Write(archive)
	}))
	t.Cleanup(srv.Close)
	s := &Store{Root: t.TempDir(), RemoteURL: srv.URL}
	key := "deadbeef"
	if err := s.fetchRemote(key); err != nil {
		t.Fatalf("fetchRemote: %v", err)
	}
	if got := strings.TrimSpace(string(readFile(t, s.stripChecksumPath(key)))); got != digest {
		t.Fatalf("stored digest = %s, want %s", got, digest)
	}
	if _, err := os.Stat(s.archivePath(key)); err != nil {
		t.Fatalf("archive not published: %v", err)
	}
	if err := os.Chmod(s.archivePath(key), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	hit, err := s.Restore(key, dest, []string{"f"})
	if err != nil || !hit {
		t.Fatalf("local restore after fetch = (%v, %v)", hit, err)
	}
}

// TestRestoreRejectsSymlinkedParent proves extraction never follows a
// symlinked parent component of the destination: a workspace of
// `base/link/ws` (link -> a real directory) is refused and nothing is
// created through the link.
func TestRestoreRejectsSymlinkedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	s, key, _ := savedCache(t)
	base := t.TempDir()
	real := t.TempDir()
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(base, "link", "ws")
	hit, err := s.Restore(key, dest, nil)
	if err == nil || hit {
		t.Fatalf("symlinked parent = (%v, %v), want error", hit, err)
	}
	if _, statErr := os.Stat(filepath.Join(real, "ws")); !os.IsNotExist(statErr) {
		t.Fatal("destination created through a symlinked parent")
	}
}

// TestRestoreCreatesNestedDestinationSafely proves normal nested destinations
// are still created and extracted into.
func TestRestoreCreatesNestedDestinationSafely(t *testing.T) {
	s, key, _ := savedCache(t)
	dest := filepath.Join(t.TempDir(), "a", "b", "c")
	hit, err := s.Restore(key, dest, []string{"f"})
	if err != nil || !hit {
		t.Fatalf("nested restore = (%v, %v)", hit, err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "f")); err != nil || string(b) != "payload" {
		t.Fatalf("content = %q, %v", b, err)
	}
}

// TestFetchRemoteConnectionErrorLeavesNothing proves transport failures are
// surfaced without leaving a temp file.
func TestFetchRemoteConnectionErrorLeavesNothing(t *testing.T) {
	boom := errors.New("connection refused")
	root := t.TempDir()
	s := &Store{Root: root, RemoteURL: "http://cache.test", Client: &http.Client{Transport: cacheTripper{err: boom}}}
	if err := s.fetchRemote("deadbeef"); !errors.Is(err, boom) {
		t.Fatalf("transport error = %v, want %v", err, boom)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("transport failure left %q behind", e.Name())
	}
}

// TestSaveManifestSidecarFailureRemovesArchive proves a failure to record the
// stored digest does not leave an unverifiable archive behind.
func TestSaveManifestSidecarFailureRemovesArchive(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	// Occupy the sidecar path with a directory so AtomicWriteFile's rename
	// fails after the archive is published.
	if err := os.MkdirAll(filepath.Join(root, "deadbeef.tar.gz.sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (&Store{Root: root}).Save("deadbeef", ws, []string{"f"}); err == nil {
		t.Fatal("sidecar write failure must surface")
	}
	if _, err := os.Stat(filepath.Join(root, "deadbeef.tar.gz")); !os.IsNotExist(err) {
		t.Fatal("archive left behind without a verifiable sidecar")
	}
}
