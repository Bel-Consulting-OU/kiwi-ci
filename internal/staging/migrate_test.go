package staging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestMigrateLegacyStagingLayoutRefusesWhileRootLocked proves the migration's
// verification step: it takes the ROOT's ownership lock, so a live process
// that owns the root as its staging directory (here the raw lock, as a
// pre-rolling-upgrade owner would hold) makes it refuse with
// ErrStagingDirOwned and remove nothing. Only after the lock is released does
// the migration reclaim the legacy file.
func TestMigrateLegacyStagingLayoutRefusesWhileRootLocked(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, FilePrefix+"held-root")
	if err := os.WriteFile(legacy, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	held, err := acquireDirLock(root)
	if err != nil {
		t.Fatalf("acquire root lock: %v", err)
	}
	if _, err := MigrateLegacyStagingLayout(context.Background(), root); !errors.Is(err, ErrStagingDirOwned) {
		t.Fatalf("migration while the root is locked = %v, want ErrStagingDirOwned", err)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("migration removed a file while the root was locked: %v", err)
	}
	if err := held.release(); err != nil {
		t.Fatalf("release root lock: %v", err)
	}
	res, err := MigrateLegacyStagingLayout(context.Background(), root)
	if err != nil {
		t.Fatalf("migration after unlock: %v", err)
	}
	if len(res.Reclaimed) != 1 {
		t.Fatalf("migration after unlock reclaimed %v, want one file", res.Reclaimed)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy file survived the unlocked migration: %v", err)
	}
}

// TestMigrateLegacyStagingLayoutKeepsInstanceIDAndForeignFiles: the migration
// reclaims only top-level FilePrefix entries. The persisted staging.instance
// id (which must never be deleted, or a restart would generate a second
// generation) and unrelated files survive, and replica subdirectories are
// reported as skipped, never entered.
func TestMigrateLegacyStagingLayoutKeepsInstanceIDAndForeignFiles(t *testing.T) {
	root := t.TempDir()
	// Persist a generated id and create its directory (a live/new replica).
	dir, id, err := ReplicaDir(root, "")
	if err != nil {
		t.Fatalf("ReplicaDir: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "unrelated.dat")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyA := filepath.Join(root, FilePrefix+"a")
	legacyB := filepath.Join(root, FilePrefix+"b")
	for _, p := range []string{legacyA, legacyB} {
		if err := os.WriteFile(p, []byte("legacy"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := MigrateLegacyStagingLayout(context.Background(), root)
	if err != nil {
		t.Fatalf("migration: %v", err)
	}
	if len(res.Reclaimed) != 2 || res.ReclaimedBytes != 12 {
		t.Fatalf("migration result = %+v, want 2 files / 12 bytes", res)
	}
	if res.ReplicaDirs != 1 {
		t.Fatalf("ReplicaDirs = %d, want 1", res.ReplicaDirs)
	}
	// staging.instance and unrelated.dat are "foreign" (non-spool) entries,
	// both kept.
	if res.ForeignFiles != 1 {
		t.Fatalf("ForeignFiles = %d, want 1 (unrelated.dat; staging.instance excluded)", res.ForeignFiles)
	}
	if _, err := os.Stat(filepath.Join(root, InstanceIDFileName)); err != nil {
		t.Fatalf("staging.instance was removed by the migration: %v", err)
	}
	if data, rerr := os.ReadFile(filepath.Join(root, InstanceIDFileName)); rerr != nil || len(data) == 0 {
		t.Fatalf("staging.instance content = %q, %v", data, rerr)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign file was removed: %v", err)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("replica directory %s was touched: %v", id, err)
	}
	// Idempotent: a second run reclaims nothing.
	if again, err := MigrateLegacyStagingLayout(context.Background(), root); err != nil || len(again.Reclaimed) != 0 {
		t.Fatalf("second migration = (%+v, %v), want no reclaimed files", again, err)
	}
}

// TestMigrateLegacyStagingLayoutMissingRootAndCancel: a missing root is
// created (nothing to reclaim), and a cancelled context stops the pass.
func TestMigrateLegacyStagingLayoutMissingRootAndCancel(t *testing.T) {
	if _, err := MigrateLegacyStagingLayout(context.Background(), ""); !errors.Is(err, ErrNoBound) {
		t.Fatalf("empty root = %v, want ErrNoBound", err)
	}
	missing := filepath.Join(t.TempDir(), "deep", "staging")
	res, err := MigrateLegacyStagingLayout(context.Background(), missing)
	if err != nil || len(res.Reclaimed) != 0 {
		t.Fatalf("missing root migration = (%+v, %v), want (none, nil)", res, err)
	}
	if fi, err := os.Stat(missing); err != nil || !fi.IsDir() {
		t.Fatalf("missing root was not created: %v", err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, FilePrefix+"x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := MigrateLegacyStagingLayout(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled migration = %v, want context.Canceled", err)
	}
}
