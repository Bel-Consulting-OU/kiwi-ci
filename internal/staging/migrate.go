package staging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LegacyLayoutMigrationResult reports what one explicit
// migrate-staging-layout run reclaimed. Reclaimed holds the base names of the
// top-level legacy spool files that were removed (empty when the root was
// already migrated); ReclaimedBytes is their pre-removal size when the entry
// could be stat'd.
type LegacyLayoutMigrationResult struct {
	// Root is the normalized configured staging root that was migrated.
	Root string
	// LockPath is the root ownership lock held for the migration.
	LockPath string
	// Reclaimed lists the removed top-level FilePrefix entries.
	Reclaimed []string
	// ReclaimedBytes is the sum of the removed entries' sizes (best effort).
	ReclaimedBytes int64
	// ReplicaDirs is how many replica subdirectories were skipped.
	ReplicaDirs int
	// ForeignFiles is how many non-spool, non-directory entries were left
	// untouched (excluding this package's lock and instance-id files).
	ForeignFiles int
}

// MigrateLegacyStagingLayout is the EXPLICIT, operator-driven migration out of
// the pre-per-replica staging layout. A pre-contract process (< commit
// 72d887d) staged its active spool files directly in the configured staging
// root with no ownership lock, so those top-level kiwi-stage-* files cannot be
// reclaimed automatically without risking a live old replica's in-flight
// upload during a rolling upgrade. NewReplicaBudget therefore leaves them
// alone; this function is the only path that removes them.
//
// Safety contract:
//
//   - It takes the ROOT's exclusive ownership lock (<root>/kiwi-stage.lock)
//     before touching anything and holds it for the whole pass. A live
//     new-contract process that owns the root as its staging directory (or a
//     concurrent migration) makes it fail with ErrStagingDirOwned instead of
//     racing. The lock does NOT prove that a pre-contract process is dead —
//     that layout took no lock — which is exactly why the caller must also
//     confirm the old replicas have drained (the CLI's `--force`/interactive
//     prompt).
//   - It removes ONLY top-level entries carrying FilePrefix. Subdirectories
//     (each a replica's private staging directory, possibly live) and foreign
//     files are never entered or removed, and the persisted staging.instance
//     id file is never touched.
//
// It is idempotent: a root with no legacy files reports zero reclaimed. A
// cancelled context stops before removing the remaining entries and reports
// the error with the entries removed so far.
func MigrateLegacyStagingLayout(ctx context.Context, root string) (LegacyLayoutMigrationResult, error) {
	var res LegacyLayoutMigrationResult
	root = strings.TrimSpace(root)
	if root == "" {
		return res, fmt.Errorf("%w: staging directory is not configured", ErrNoBound)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return res, fmt.Errorf("staging: create staging root %s: %w", root, err)
	}
	res.Root = root
	res.LockPath = filepath.Join(root, LockFileName)

	lock, err := acquireDirLock(root)
	if err != nil {
		return res, fmt.Errorf("staging: migrate layout: %w; stop/drain every old-layout replica before migrating %s", err, root)
	}
	defer func() { _ = lock.release() }()

	entries, err := os.ReadDir(root)
	if err != nil {
		return res, fmt.Errorf("staging: migrate layout: read %s: %w", root, err)
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if e.IsDir() {
			res.ReplicaDirs++
			continue
		}
		name := e.Name()
		if name == LockFileName || name == InstanceIDFileName {
			continue
		}
		if !strings.HasPrefix(name, FilePrefix) {
			res.ForeignFiles++
			continue
		}
		path := filepath.Join(root, name)
		if info, ierr := e.Info(); ierr == nil {
			res.ReclaimedBytes += info.Size()
		}
		if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return res, fmt.Errorf("staging: migrate layout: reclaim legacy spool file %s: %w", path, rerr)
		}
		res.Reclaimed = append(res.Reclaimed, name)
	}
	return res, nil
}
