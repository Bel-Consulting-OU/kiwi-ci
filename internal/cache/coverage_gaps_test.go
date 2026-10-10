//go:build unix

package cache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type foreignFileInfo struct{}

func (foreignFileInfo) Name() string       { return "foreign" }
func (foreignFileInfo) Size() int64        { return 0 }
func (foreignFileInfo) Mode() os.FileMode  { return 0 }
func (foreignFileInfo) ModTime() time.Time { return time.Time{} }
func (foreignFileInfo) IsDir() bool        { return false }
func (foreignFileInfo) Sys() any           { return nil }

// TestAcquireNamespaceLockRejectsWritableLockFile covers the trust gate on the
// namespace ownership lock.
func TestAcquireNamespaceLockRejectsWritableLockFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, NamespaceLockFileName)
	if err := os.WriteFile(path, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireNamespaceLock(dir); err == nil || !strings.Contains(err.Error(), "trustworthy") {
		t.Fatalf("writable lock = %v, want the trust refusal", err)
	}
}

// TestStageOwnedByCurrentUserForeignInfo covers the non-Stat_t descriptor.
func TestStageOwnedByCurrentUserForeignInfo(t *testing.T) {
	if stageOwnedByCurrentUser(foreignFileInfo{}) {
		t.Fatal("foreign FileInfo accepted as owned")
	}
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !stageOwnedByCurrentUser(info) {
		t.Fatal("own directory not recognized")
	}
}

// TestPruneLocalDirFailureArms covers the unreadable root and the
// missing-directory scan.
func TestPruneLocalDirFailureArms(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pruneLocalDir(context.Background(), file, RetentionPolicy{}); err == nil {
		t.Fatal("prune over a regular file succeeded")
	}
	entries, err := listLocalEntriesAt(filepath.Join(t.TempDir(), "missing"))
	if err != nil || entries != nil {
		t.Fatalf("missing dir scan = %v/%v", entries, err)
	}
}

// TestListLocalEntriesAtSkipsInvalidNames covers the key-shape filter.
func TestListLocalEntriesAtSkipsInvalidNames(t *testing.T) {
	dir := t.TempDir()
	good := strings.Repeat("a", 64)
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(good + ".tar.gz")
	write("BAD NAME.tar.gz")
	write(".hidden.tar.gz")
	entries, err := listLocalEntriesAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].key != good {
		t.Fatalf("entries = %+v, want only the valid key", entries)
	}
}

// TestEvictLocalEntryStatFailure covers a non-NotExist stat failure: the
// entry is counted failed, never silently skipped.
func TestEvictLocalEntryStatFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var res PruneResult
	if evictLocalEntry(file, localCacheEntry{key: strings.Repeat("b", 64)}, &res) {
		t.Fatal("evict over a regular-file root reported success")
	}
	if res.Failed != 1 {
		t.Fatalf("failed = %d, want 1", res.Failed)
	}
}

// TestReclaimLegacyLayoutFailureArms covers the readdir failure and the
// invalid-key skip.
func TestReclaimLegacyLayoutFailureArms(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReclaimLegacyLayout(file); err == nil {
		t.Fatal("reclaim over a regular file succeeded")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "not a key.tar.gz"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, bytes, err := ReclaimLegacyLayout(dir)
	if err != nil || files != 0 || bytes != 0 {
		t.Fatalf("invalid-name reclaim = %d/%d/%v", files, bytes, err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "not a key.tar.gz")); serr != nil {
		t.Fatalf("foreign file removed: %v", serr)
	}
}

// TestCollectStagedEntriesRejectsNonRegularProofEntries covers the walk
// failures: a missing staging root, a symlink and a FIFO.
func TestCollectStagedEntriesRejectsNonRegularProofEntries(t *testing.T) {
	if _, err := collectStagedEntries(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing staging root accepted")
	}

	dir := t.TempDir()
	if err := os.Symlink("target", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := collectStagedEntries(dir); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink entry = %v, want the invariant failure", err)
	}

	dir2 := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir2, "pipe"), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if _, err := collectStagedEntries(dir2); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("fifo entry = %v, want the invariant failure", err)
	}
}

// TestReleaseNamespaceLockRetrySeam covers the release hook seam contract: a
// failing hook retries and a nil-safe release is idempotent.
func TestReleaseNamespaceLockRetrySeam(t *testing.T) {
	SetNamespaceReleaseHookForTest(func() error { return errors.New("release refused") })
	t.Cleanup(func() { SetNamespaceReleaseHookForTest(nil) })
	if err := releaseNamespaceLock(&namespaceLock{}); err == nil {
		t.Fatal("failing release hook ignored")
	}
	var nilLock *namespaceLock
	if err := nilLock.release(); err != nil {
		t.Fatalf("nil release = %v", err)
	}
	lock := &namespaceLock{}
	if err := lock.release(); err != nil {
		t.Fatalf("empty release = %v", err)
	}
}

// TestOpenExtractRootRefusals covers a symlinked destination and a regular
// file in the destination path chain.
func TestOpenExtractRootRefusals(t *testing.T) {
	if _, err := openExtractRoot(""); err == nil {
		t.Fatal("empty destination accepted")
	}

	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openExtractRoot(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink destination = %v", err)
	}

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openExtractRoot(filepath.Join(file, "child")); err == nil {
		t.Fatal("regular-file component accepted")
	}
}
