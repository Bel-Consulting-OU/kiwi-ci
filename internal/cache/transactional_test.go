package cache

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// cacheTarEntry is one entry for the inline tar.gz cache fixtures.
type cacheTarEntry struct {
	name     string
	data     []byte
	typeflag byte
}

// cacheTarGz builds a complete tar.gz archive from entries.
func cacheTarGz(t *testing.T, entries []cacheTarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: e.typeflag, Size: int64(len(e.data)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
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

// truncatedMemberArchive builds a tar.gz whose first member is complete and
// whose second member declares 64 bytes but carries only a few, with the gzip
// stream closed so the digest sidecar can still match the exact bytes.
func truncatedMemberArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "first.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "second.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 64}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	// Close only the gzip stream: the tar stream never completes the second
	// member.
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// writeCacheArchive publishes raw archive bytes with a matching digest
// sidecar, so restore verification passes and any failure must come from
// extraction or publication.
func writeCacheArchive(t *testing.T, s *Store, key string, archive []byte) {
	t.Helper()
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.archivePath(key), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(archive)
	if err := os.WriteFile(s.stripChecksumPath(key), []byte(hex.EncodeToString(sum[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// snapshotTree records the full workspace tree: directories as "dir" and
// regular files as their exact bytes.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			out[rel] = "dir"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = "file:" + string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// stagingDirs returns the restore staging directories left in root.
func stagingDirs(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), cacheStagePrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestRestoreTruncatedArchiveLeavesWorkspaceUnchanged proves a restore whose
// extraction fails on a later member publishes nothing: the workspace tree
// and the bytes of its pre-existing files are identical to a pre-restore
// snapshot (no first member left behind) and the staging tree is gone.
func TestRestoreTruncatedArchiveLeavesWorkspaceUnchanged(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "sub", "inner.txt"), []byte("inner"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, ws)

	s := &Store{Root: t.TempDir()}
	writeCacheArchive(t, s, "deadbeef", truncatedMemberArchive(t))

	hit, err := s.RestoreContext(context.Background(), "deadbeef", ws, []string{"."})
	if err == nil || hit {
		t.Fatalf("truncated restore = hit=%t err=%v, want error", hit, err)
	}
	if _, statErr := os.Lstat(filepath.Join(ws, "first.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("completed first member was published despite the extraction failure: %v", statErr)
	}
	if got := snapshotTree(t, ws); !reflect.DeepEqual(before, got) {
		t.Fatalf("workspace changed:\nbefore=%v\nafter=%v", before, got)
	}
	if dirs := stagingDirs(t, ws); len(dirs) != 0 {
		t.Fatalf("staging directories left behind: %v", dirs)
	}
}

// TestRestorePublishCollisionLeavesWorkspaceUnchanged proves a collision with
// a pre-existing destination path is detected before anything is published:
// the staged A is absent, the pre-existing B keeps its original bytes, the
// snapshot is unchanged and the staging tree is gone.
func TestRestorePublishCollisionLeavesWorkspaceUnchanged(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "B"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, ws)

	s := &Store{Root: t.TempDir()}
	writeCacheArchive(t, s, "deadbeef", cacheTarGz(t, []cacheTarEntry{
		{name: "A", data: []byte("new-a"), typeflag: tar.TypeReg},
		{name: "B", data: []byte("new-b"), typeflag: tar.TypeReg},
	}))

	hit, err := s.RestoreContext(context.Background(), "deadbeef", ws, []string{"."})
	if err == nil || hit {
		t.Fatalf("collision restore = hit=%t err=%v, want error", hit, err)
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("collision error = %v, want an already-exists error", err)
	}
	if _, statErr := os.Lstat(filepath.Join(ws, "A")); !os.IsNotExist(statErr) {
		t.Fatalf("staged A was published despite the collision: %v", statErr)
	}
	if b, readErr := os.ReadFile(filepath.Join(ws, "B")); readErr != nil || string(b) != "original" {
		t.Fatalf("pre-existing B = %q, %v; want %q", b, readErr, "original")
	}
	if got := snapshotTree(t, ws); !reflect.DeepEqual(before, got) {
		t.Fatalf("workspace changed:\nbefore=%v\nafter=%v", before, got)
	}
	if dirs := stagingDirs(t, ws); len(dirs) != 0 {
		t.Fatalf("staging directories left behind: %v", dirs)
	}
}

// TestRestorePublishesAllStagedMembers proves the success path still restores
// every member (nested directories and files) and removes the staging tree.
func TestRestorePublishesAllStagedMembers(t *testing.T) {
	ws := t.TempDir()
	s := &Store{Root: t.TempDir()}
	writeCacheArchive(t, s, "deadbeef", cacheTarGz(t, []cacheTarEntry{
		{name: "dir/", typeflag: tar.TypeDir},
		{name: "dir/nested.txt", data: []byte("nested"), typeflag: tar.TypeReg},
		{name: "top.txt", data: []byte("top"), typeflag: tar.TypeReg},
	}))

	hit, err := s.RestoreContext(context.Background(), "deadbeef", ws, []string{"."})
	if err != nil || !hit {
		t.Fatalf("restore = hit=%t err=%v, want hit", hit, err)
	}
	for path, want := range map[string]string{
		"top.txt":        "top",
		"dir/nested.txt": "nested",
	} {
		b, readErr := os.ReadFile(filepath.Join(ws, filepath.FromSlash(path)))
		if readErr != nil || string(b) != want {
			t.Fatalf("restored %s = %q, %v; want %q", path, b, readErr, want)
		}
	}
	if dirs := stagingDirs(t, ws); len(dirs) != 0 {
		t.Fatalf("staging directories left behind: %v", dirs)
	}
}

// TestKeyContextRejectsMalformedHashGlob proves a malformed hash_files glob is
// an immediate KeyContext error instead of being silently discarded, while a
// valid glob still hashes matching files.
func TestKeyContextRejectsMalformedHashGlob(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "go.sum"), []byte("checksum"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Store{Root: t.TempDir()}
	if _, err := s.KeyContext(context.Background(), "base", ws, []string{"[bad"}); err == nil {
		t.Fatal("malformed hash_files glob was accepted")
	} else if !strings.Contains(err.Error(), "cache hash_files") || !strings.Contains(err.Error(), "[bad") {
		t.Fatalf("malformed glob error = %v", err)
	}
	if _, err := s.KeyContext(context.Background(), "base", ws, []string{"*.sum"}); err != nil {
		t.Fatalf("valid glob = %v", err)
	}
}

// TestRestoreMergesIntoExistingWorkspaceDirectories pins the normal cache
// overlay: caches are restored over the repository checkout, so a staged
// directory that already exists as a real directory is a merge point, not a
// collision. Pre-existing files survive untouched and the staged file lands.
func TestRestoreMergesIntoExistingWorkspaceDirectories(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "d", "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Store{Root: t.TempDir()}
	writeCacheArchive(t, s, "mergekey", cacheTarGz(t, []cacheTarEntry{
		{name: "d", typeflag: tar.TypeDir},
		{name: "d/a.txt", data: []byte("a"), typeflag: tar.TypeReg},
	}))
	hit, err := s.RestoreContext(context.Background(), "mergekey", ws, []string{"."})
	if err != nil || !hit {
		t.Fatalf("merge restore = hit=%t err=%v, want a hit", hit, err)
	}
	if got, err := os.ReadFile(filepath.Join(ws, "d", "a.txt")); err != nil || string(got) != "a" {
		t.Fatalf("staged member not published: %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(ws, "d", "keep.txt")); err != nil || string(got) != "keep" {
		t.Fatalf("pre-existing file changed: %q, %v", got, err)
	}
	if dirs := stagingDirs(t, ws); len(dirs) != 0 {
		t.Fatalf("staging directories left behind: %v", dirs)
	}
}

// TestRestoreRejectsOverwritingFileInsideMergedDirectory is the merge-safe
// collision half: even though the parent directory merges, a staged file can
// never overwrite a pre-existing workspace file, and the failed restore
// leaves the workspace byte-for-byte unchanged (including members staged
// before the collision).
func TestRestoreRejectsOverwritingFileInsideMergedDirectory(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "d", "a.txt"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, ws)
	s := &Store{Root: t.TempDir()}
	writeCacheArchive(t, s, "collidekey", cacheTarGz(t, []cacheTarEntry{
		{name: "new.txt", typeflag: tar.TypeReg, data: []byte("new")},
		{name: "d", typeflag: tar.TypeDir},
		{name: "d/a.txt", data: []byte("replaced"), typeflag: tar.TypeReg},
	}))
	hit, err := s.RestoreContext(context.Background(), "collidekey", ws, []string{"."})
	if err == nil || hit {
		t.Fatalf("collision restore = hit=%t err=%v, want an error", hit, err)
	}
	if _, statErr := os.Lstat(filepath.Join(ws, "new.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("member staged before the collision was published: %v", statErr)
	}
	if got, err := os.ReadFile(filepath.Join(ws, "d", "a.txt")); err != nil || string(got) != "original" {
		t.Fatalf("pre-existing file overwritten: %q, %v", got, err)
	}
	if got := snapshotTree(t, ws); !reflect.DeepEqual(before, got) {
		t.Fatalf("workspace changed:\nbefore=%v\nafter=%v", before, got)
	}
	if dirs := stagingDirs(t, ws); len(dirs) != 0 {
		t.Fatalf("staging directories left behind: %v", dirs)
	}
}
