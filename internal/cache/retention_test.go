package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// archiveStats returns the archive count and total bytes in a store root.
func archiveStats(t *testing.T, root string) (int, int64) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return 0, 0
	}
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var total int64
	for _, de := range entries {
		if de.IsDir() || filepath.Ext(de.Name()) != ".gz" {
			continue
		}
		fi, ierr := de.Info()
		if ierr != nil {
			continue
		}
		n++
		total += fi.Size()
	}
	return n, total
}

func archiveExists(root, key string) bool {
	_, err := os.Stat(filepath.Join(root, key+".tar.gz"))
	return err == nil
}

// saveKey saves one small archive under key with an explicit mtime so
// eviction order is deterministic.
func saveKey(t *testing.T, store *Store, key string, when time.Time) {
	t.Helper()
	ws := t.TempDir()
	writeIncompressible(t, filepath.Join(ws, "f.bin"), 800)
	if err := store.SaveContext(context.Background(), key, ws, []string{"f.bin"}); err != nil {
		t.Fatal(err)
	}
	path := store.archivePath(key)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

// TestPruneEnforcesByteAndEntryBounds is the P1 regression: rotating logical
// keys cannot grow the local cache tree past the configured caps. Saves prune
// inline, so the invariant holds immediately after the last save.
func TestPruneEnforcesByteAndEntryBounds(t *testing.T) {
	root := t.TempDir()
	store := &Store{Root: root, Retention: RetentionPolicy{MaxBytes: 2500, MaxEntries: 3}}
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 6; i++ {
		saveKey(t, store, fmt.Sprintf("key%02d", i), base.Add(time.Duration(i)*time.Minute))
	}
	entries, total := archiveStats(t, root)
	if entries > 3 {
		t.Fatalf("cache entries = %d, want <= 3", entries)
	}
	if total > 2500 {
		t.Fatalf("cache bytes = %d, want <= 2500", total)
	}
	if !archiveExists(root, "key05") {
		t.Fatal("newest entry was evicted")
	}
	if archiveExists(root, "key00") {
		t.Fatal("oldest entry survived the caps")
	}
	// A direct pass is idempotent once the policy holds.
	res, err := store.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 0 || res.Failed != 0 {
		t.Fatalf("idempotent prune = %+v", res)
	}
}

// TestPruneEvictsAgedEntries pins the age dimension independent of the caps.
func TestPruneEvictsAgedEntries(t *testing.T) {
	root := t.TempDir()
	store := &Store{Root: root, Retention: RetentionPolicy{MaxAge: time.Minute}}
	saveKey(t, store, "fresh", time.Now())
	saveKey(t, store, "stale", time.Now().Add(-2*time.Hour))
	res, err := store.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 1 {
		t.Fatalf("prune = %+v, want one aged entry evicted", res)
	}
	if archiveExists(root, "stale") || !archiveExists(root, "fresh") {
		t.Fatalf("aged eviction wrong: stale=%t fresh=%t", archiveExists(root, "stale"), archiveExists(root, "fresh"))
	}
	if _, err := os.Stat(store.stripChecksumPath("stale")); !os.IsNotExist(err) {
		t.Fatalf("digest sidecar survived eviction (err=%v)", err)
	}
}

// TestPruneRemovalFailureKeepsAccountingAndRetries pins the fail-closed
// eviction rule: an archive that cannot be removed stays in the tree and is
// counted as failed (and is retried on the next pass), never silently
// dropped from the accounting while it still occupies disk.
func TestPruneRemovalFailureKeepsAccountingAndRetries(t *testing.T) {
	root := t.TempDir()
	// Save both entries WITHOUT a policy so the populating saves cannot
	// prune, then install the policy for the pass under test.
	store := &Store{Root: root}
	base := time.Now().Add(-time.Hour)
	saveKey(t, store, "old", base)
	saveKey(t, store, "new", base.Add(time.Minute))
	store.Retention = RetentionPolicy{MaxEntries: 1}

	orig := removeCacheFile
	removeCacheFile = func(path string) error {
		if filepath.Base(path) == "old.tar.gz" {
			return errors.New("test: remove refused")
		}
		return os.Remove(path)
	}
	t.Cleanup(func() { removeCacheFile = orig })

	res, err := store.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != 1 || res.Entries != 0 {
		t.Fatalf("prune = %+v, want one failed removal", res)
	}
	if !archiveExists(root, "old") {
		t.Fatal("failed removal reported the entry as evicted")
	}

	removeCacheFile = orig
	res, err = store.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 1 || res.Failed != 0 {
		t.Fatalf("retry prune = %+v, want the entry reclaimed", res)
	}
	if archiveExists(root, "old") || !archiveExists(root, "new") {
		t.Fatal("retry evicted the wrong entry")
	}
}

// TestPruneDisabledPolicyIsNoop pins the local-CLI compatibility: without a
// policy nothing is evicted.
func TestPruneDisabledPolicyIsNoop(t *testing.T) {
	root := t.TempDir()
	store := &Store{Root: root}
	saveKey(t, store, "a", time.Now())
	saveKey(t, store, "b", time.Now())
	res, err := store.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 0 {
		t.Fatalf("prune with no policy evicted %d entries", res.Entries)
	}
	if !archiveExists(root, "a") || !archiveExists(root, "b") {
		t.Fatal("no-policy prune removed entries")
	}
}
