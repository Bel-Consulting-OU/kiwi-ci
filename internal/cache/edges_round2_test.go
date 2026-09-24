package cache

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// TestReadStoredDigestErrorArms covers the non-ENOENT read error and the
// malformed-digest rejection.
func TestReadStoredDigestErrorArms(t *testing.T) {
	root := t.TempDir()
	s := &Store{Root: root}
	key := "aabbccdd"
	sidecar := s.stripChecksumPath(key)

	if err := os.MkdirAll(sidecar, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readStoredDigest(key); err == nil || errors.Is(err, errLocalUnverified) {
		t.Fatalf("directory sidecar = %v, want a read error", err)
	}
	if err := os.Remove(sidecar); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecar, []byte("not-a-digest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readStoredDigest(key); err == nil {
		t.Fatal("malformed stored digest was accepted")
	}
}

// TestRestoreLocalArchiveShapeAndBound covers the symlink, non-regular and
// over-bound archive refusals.
func TestRestoreLocalArchiveShapeAndBound(t *testing.T) {
	s, key, ws := savedCache(t)
	archive := s.archivePath(key)

	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(s.Root, "elsewhere"), archive); err != nil {
		t.Fatal(err)
	}
	if _, err := s.restoreLocal(key, ws, []string{"f"}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink archive = %v", err)
	}

	os.Remove(archive)
	if err := os.Mkdir(archive, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.restoreLocal(key, ws, []string{"f"}); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory archive = %v", err)
	}

	// Over the configured bound.
	os.RemoveAll(archive)
	s2, key2, ws2 := savedCache(t)
	s2.MaxCacheBytes = 1
	if _, err := s2.restoreLocal(key2, ws2, []string{"f"}); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("over-bound archive = %v", err)
	}
}

// TestOpenExtractRootArms covers the workspace-shape rejections and success.
func TestOpenExtractRootArms(t *testing.T) {
	if _, err := openExtractRoot(""); err == nil {
		t.Fatal("empty workspace accepted")
	}
	if _, err := openExtractRoot("."); err == nil {
		t.Fatal("dot workspace accepted")
	}

	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := openExtractRoot(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink final component = %v", err)
	}

	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openExtractRoot(file); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("file final component = %v", err)
	}
	if _, err := openExtractRoot(filepath.Join(file, "child")); err == nil {
		t.Fatal("path below a file accepted")
	}

	root, err := openExtractRoot(filepath.Join(dir, "nested", "ws"))
	if err != nil {
		t.Fatalf("nested destination = %v", err)
	}
	root.Close()
}

// TestFetchRemoteRemainingArms covers the file-sync, directory-fsync and
// sidecar-write failure arms not reached by the existing matrix.
func TestFetchRemoteRemainingArms(t *testing.T) {
	freshTripper := func() cacheTripper {
		return cacheTripper{resp: okResp(http.StatusOK, io.NopCloser(strings.NewReader("archive")))}
	}

	origSync := syncCacheFile
	syncCacheFile = func(*os.File) error { return errors.New("sync refused") }
	s := &Store{Root: t.TempDir(), RemoteURL: "http://cache.test", Client: &http.Client{Transport: freshTripper()}}
	if err := s.fetchRemote(gapCacheKey); err == nil || !strings.Contains(err.Error(), "sync refused") {
		t.Fatalf("sync failure = %v", err)
	}
	syncCacheFile = origSync

	restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(string) error { return errors.New("dir sync refused") }})
	s = &Store{Root: t.TempDir(), RemoteURL: "http://cache.test", Client: &http.Client{Transport: freshTripper()}}
	err := s.fetchRemote(gapCacheKey)
	restore()
	if err == nil {
		t.Fatal("directory fsync failure was ignored")
	}
	if _, statErr := os.Stat(s.archivePath(gapCacheKey)); !os.IsNotExist(statErr) {
		t.Fatal("archive survived a directory-fsync failure")
	}

	// Sidecar write failure: the sidecar path is a directory.
	root := t.TempDir()
	s = &Store{Root: root, RemoteURL: "http://cache.test", Client: &http.Client{Transport: freshTripper()}}
	if err := os.MkdirAll(s.stripChecksumPath(gapCacheKey), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.fetchRemote(gapCacheKey); err == nil {
		t.Fatal("sidecar write failure was ignored")
	}
	if _, statErr := os.Stat(s.archivePath(gapCacheKey)); !os.IsNotExist(statErr) {
		t.Fatal("archive survived a sidecar-write failure")
	}
}

// TestSignManifestRejectsShortKey covers the malformed-key guard.
func TestSignManifestRejectsShortKey(t *testing.T) {
	if _, err := SignManifest(CacheManifest{}, "id", []byte("short")); err == nil {
		t.Fatal("short signing key was accepted")
	}
}
