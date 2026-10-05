package executor

import (
	"errors"
	"path/filepath"
	"testing"
)

// XFS ambiguous-side-effect matrix: an xfs_quota command failure is NOT proof
// the side effect did not happen. When removal subsequently fails too, the
// coordinates must stay durably owned (typed error), never the soft "no
// quota" status that lets the caller drop its ledger entry.

func xfsAmbiguitySetup(t *testing.T, failPattern string) (mountInfoEntry, string) {
	t.Helper()
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "100000")
	t.Setenv(xfsProjectIDCountEnv, "4")
	t.Setenv("KIWI_XFS_LOCK_DIR", t.TempDir())
	logPath := filepath.Join(t.TempDir(), "xfs.log")
	t.Setenv("FAKE_XFS_LOG", logPath)
	script := writeFakeXFSQuota(t, failPattern)
	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:70", fsType: "xfs"}
	return entry, script
}

func TestXFSAssignFailureCleanupSuccessReleasesID(t *testing.T) {
	entry, script := xfsAmbiguitySetup(t, "project -s")
	pool := projectIDPoolFor(entry.fsKey())
	before := pool.liveCount()
	status, cleanup, err := setupXFSProjectQuotaOnMountHook("/mnt/xfs/ws", entry, 1<<20, script, nil)
	if err != nil {
		t.Fatalf("cleanup succeeded; setup error = %v (want the soft status)", err)
	}
	if cleanup != nil || status.Hard {
		t.Fatalf("soft failure returned cleanup/hard: %+v cleanup=%v", status, cleanup != nil)
	}
	if pool.liveCount() != before {
		t.Fatalf("project id leaked after successful cleanup: %d -> %d", before, pool.liveCount())
	}
}

func TestXFSAssignFailureCleanupFailureReturnsCleanupPending(t *testing.T) {
	entry, script := xfsAmbiguitySetup(t, "project -")
	pool := projectIDPoolFor(entry.fsKey())
	before := pool.liveCount()
	status, cleanup, err := setupXFSProjectQuotaOnMountHook("/mnt/xfs/ws", entry, 1<<20, script, nil)
	var pending *QuotaCleanupPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("assign+cleanup failure = %v, want QuotaCleanupPendingError", err)
	}
	if cleanup != nil {
		t.Fatal("cleanup returned for an unproven assignment")
	}
	if pending.Assignment.ProjectID == 0 || status.Detail == "" {
		t.Fatalf("pending carries no coordinates: %+v", pending)
	}
	// The ID stays quarantined (durable ownership), not released.
	if pool.liveCount() <= before {
		t.Fatalf("ambiguous id was released: %d -> %d", before, pool.liveCount())
	}
}

func TestXFSLimitFailureCleanupSuccessReleasesID(t *testing.T) {
	entry, script := xfsAmbiguitySetup(t, "bhard=1048576")
	pool := projectIDPoolFor(entry.fsKey())
	before := pool.liveCount()
	_, cleanup, err := setupXFSProjectQuotaOnMountHook("/mnt/xfs/ws", entry, 1<<20, script, nil)
	if err != nil {
		t.Fatalf("cleanup succeeded; setup error = %v", err)
	}
	if cleanup != nil {
		t.Fatal("soft limit failure returned cleanup")
	}
	if pool.liveCount() != before {
		t.Fatalf("project id leaked: %d -> %d", before, pool.liveCount())
	}
}

func TestXFSLimitFailureCleanupFailureReturnsCleanupPending(t *testing.T) {
	entry, script := xfsAmbiguitySetup(t, "limit -p")
	status, cleanup, err := setupXFSProjectQuotaOnMountHook("/mnt/xfs/ws", entry, 1<<20, script, nil)
	var pending *QuotaCleanupPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("limit+cleanup failure = %v, want QuotaCleanupPendingError", err)
	}
	if cleanup != nil || status.Detail == "" {
		t.Fatalf("bad pending result: %+v cleanup=%v", status, cleanup != nil)
	}
}

func TestXFSOwnershipHookFailureReleasesUnpublishedProjectID(t *testing.T) {
	entry, script := xfsAmbiguitySetup(t, "")
	pool := projectIDPoolFor(entry.fsKey())
	before := pool.liveCount()
	_, cleanup, err := setupXFSProjectQuotaOnMountHook("/mnt/xfs/ws", entry, 1<<20, script,
		func(WorkspaceQuotaAssignment) error { return errors.New("ledger unavailable") })
	if err == nil || cleanup != nil {
		t.Fatalf("hook failure = (%v, cleanup=%v), want an error", err, cleanup != nil)
	}
	if pool.liveCount() != before {
		t.Fatalf("unpublished project id leaked: %d -> %d", before, pool.liveCount())
	}
}
