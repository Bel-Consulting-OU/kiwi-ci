package executor

// Branch coverage for the portable disk-quota core: the exported setup
// routing, the mountinfo parser's malformed records, the mount-coverage
// predicate, the project-ID pool configuration guards and the XFS flow's
// allocate/assign/limit failure paths (including the "cleanup also failed, the
// ID stays allocated" branch).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWorkspaceDiskQuotaSetupRoutesThroughProbe proves the exported entry
// point uses the SAME substitutable probe as the backend, so the runner's
// pre-checkout install and the backend's step-boundary checks can never
// disagree about the outcome.
func TestWorkspaceDiskQuotaSetupRoutesThroughProbe(t *testing.T) {
	orig := workspaceDiskQuotaSetup
	calls := 0
	workspaceDiskQuotaSetup = func(workspace string, limit int64) (DiskQuotaStatus, func() error) {
		calls++
		if workspace != "/tmp/ws" || limit != 42 {
			t.Errorf("probe called with (%q, %d)", workspace, limit)
		}
		return DiskQuotaStatus{Hard: true, Limit: limit, Detail: "stub"}, func() error { return nil }
	}
	t.Cleanup(func() { workspaceDiskQuotaSetup = orig })

	status, cleanup := WorkspaceDiskQuotaSetup("/tmp/ws", 42)
	if calls != 1 || !status.Hard || status.Limit != 42 || cleanup == nil {
		t.Fatalf("routed status = (%+v, cleanup=%v, calls=%d)", status, cleanup != nil, calls)
	}
}

// TestParseMountInfoLineRejectsMalformedRecords: a record without the "-"
// separator and a record truncated before fstype/source/super-options are
// not mount records and must be skipped instead of producing a bogus entry.
func TestParseMountInfoLineRejectsMalformedRecords(t *testing.T) {
	cases := map[string]string{
		"too few fields":   "36 35 98:0 / /mnt",
		"no separator":     "36 35 98:0 / /mnt/data rw,relatime xfs /dev/sdb1 rw",
		"truncated after":  "36 35 98:0 / /mnt/data rw,relatime - xfs",
		"separator at end": "36 35 98:0 / /mnt/data rw,relatime -",
	}
	for name, line := range cases {
		if entry, ok := parseMountInfoLine(line); ok {
			t.Errorf("%s: %q parsed to %+v", name, line, entry)
		}
	}
	// The well-formed minimum parses, including the escaped mount point.
	entry, ok := parseMountInfoLine(`36 35 98:0 / /mnt/my\040data rw,relatime - xfs /dev/sdb1 rw,prjquota`)
	if !ok || entry.fsType != "xfs" || entry.superOptions != "rw,prjquota" {
		t.Fatalf("well-formed line = (%+v, %v)", entry, ok)
	}
	if entry.mountPoint != "/mnt/my data" {
		t.Fatalf("escaped mount point decoded to %q", entry.mountPoint)
	}
}

// TestPathCoveredByMount pins the mount-namespace coverage rule: exact match
// or a "/" boundary, the root mount covering every absolute path, and an
// empty mount point covering nothing.
func TestPathCoveredByMount(t *testing.T) {
	cases := []struct {
		path, mount string
		want        bool
	}{
		{"", "", false},
		{"/mnt/ws", "", false},
		{"/", "/", true},
		{"/mnt/ws", "/", true},
		{"/mnt/ws", "/mnt", true},
		{"/mnt", "/mnt", true},
		{"/mnt", "/mnt/", true},
		{"/mntx", "/mnt", false},
		{"/mnt", "/mnt/ws", false},
	}
	for _, tc := range cases {
		if got := pathCoveredByMount(tc.path, tc.mount); got != tc.want {
			t.Errorf("pathCoveredByMount(%q, %q) = %v, want %v", tc.path, tc.mount, got, tc.want)
		}
	}
}

// TestNewProjectIDPoolConfigurationGuards pins the pool construction guards:
// an out-of-range base falls back to the default and an unset/zero/overflowing
// size is clamped to what the base leaves available.
func TestNewProjectIDPoolConfigurationGuards(t *testing.T) {
	def := newProjectIDPool(0, 0)
	if def.base != defaultXFSProjectIDBase || def.size != defaultXFSProjectIDCount {
		t.Fatalf("zero pool = (base %d, size %d), want the defaults", def.base, def.size)
	}
	over := newProjectIDPool(xfsProjectIDMax+1, 16)
	if over.base != defaultXFSProjectIDBase || over.size != 16 {
		t.Fatalf("over-range base pool = (base %d, size %d)", over.base, over.size)
	}
	// A valid base with an in-range size is honored.
	valid := newProjectIDPool(1234, 7)
	if valid.base != 1234 || valid.size != 7 {
		t.Fatalf("valid pool = (base %d, size %d)", valid.base, valid.size)
	}
	// A base one below the ceiling leaves exactly two IDs.
	capped := newProjectIDPool(xfsProjectIDMax-1, defaultXFSProjectIDCount)
	if capped.size != 2 {
		t.Fatalf("capped pool size = %d, want 2", capped.size)
	}
}

// TestReleaseXFSProjectIDZeroIsNoOp: releasing ID 0 (the "no quota" sentinel)
// must not create or touch a pool, so a cleanup path that never allocated
// cannot perturb another workspace's allocator.
func TestReleaseXFSProjectIDZeroIsNoOp(t *testing.T) {
	resetProjectIDPools(t)
	releaseXFSProjectID("8:9", 0)
	xfsProjectIDPools.mu.Lock()
	_, created := xfsProjectIDPools.m["8:9"]
	xfsProjectIDPools.mu.Unlock()
	if created {
		t.Fatal("releasing ID 0 created a pool")
	}
	// Releasing an unknown non-zero ID is equally harmless.
	releaseXFSProjectID("8:9", 4242)
	if got := projectIDPoolFor("8:9").liveCount(); got != 0 {
		t.Fatalf("live IDs after releasing an unallocated ID = %d", got)
	}
}

// TestSetupXFSProjectQuotaAllocateExhaustion: an exhausted per-filesystem
// pool is reported as a non-hard status naming the allocation step, with no
// cleanup and no partial state.
func TestSetupXFSProjectQuotaAllocateExhaustion(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "900000")
	t.Setenv(xfsProjectIDCountEnv, "1")
	t.Setenv("FAKE_XFS_LOG", filepath.Join(t.TempDir(), "xfs.log"))
	script := writeFakeXFSQuota(t, "")

	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:20", fsType: "xfs"}
	first, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws-a", entry, 1<<20, script)
	if !first.Hard || cleanup == nil {
		t.Fatalf("first apply = %+v cleanup=%v", first, cleanup != nil)
	}
	second, cleanup2 := setupXFSProjectQuotaOnMount("/mnt/xfs/ws-b", entry, 1<<20, script)
	if second.Hard || cleanup2 != nil {
		t.Fatalf("exhausted apply = %+v cleanup=%v", second, cleanup2 != nil)
	}
	if !strings.Contains(second.Detail, "allocate XFS project id") || !strings.Contains(second.Detail, "exhausted") {
		t.Fatalf("detail = %q, want an explicit allocation exhaustion reason", second.Detail)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestSetupXFSProjectQuotaAssignFailureReleasesID: when the project
// assignment command fails, the outcome is ambiguous (the kernel call may
// have succeeded before the error), so Kiwi first tries to remove the
// assignment with the ID-named cleanup and only then releases the ID. Here
// the cleanup succeeds (the fake fails only "project -s"), so the ID is
// reusable; TestSetupXFSProjectQuotaAssignCleanupFailureQuarantinesID covers
// the case where cleanup cannot prove removal.
func TestSetupXFSProjectQuotaAssignFailureReleasesID(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "910000")
	t.Setenv(xfsProjectIDCountEnv, "1")
	t.Setenv("FAKE_XFS_LOG", filepath.Join(t.TempDir(), "xfs.log"))
	script := writeFakeXFSQuota(t, "project -s")

	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:21", fsType: "xfs"}
	status, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws", entry, 1<<20, script)
	if status.Hard || cleanup != nil {
		t.Fatalf("assign failure = %+v cleanup=%v", status, cleanup != nil)
	}
	if !strings.Contains(status.Detail, "assign XFS project quota") {
		t.Fatalf("detail = %q", status.Detail)
	}
	// The assignment never existed, so the ID must be free again: a second
	// setup on the same (one-ID) filesystem succeeds with the same ID.
	if n := projectIDPoolFor("8:21").liveCount(); n != 0 {
		t.Fatalf("live IDs after failed assign = %d, want 0", n)
	}
	reused, err := allocateXFSProjectID("8:21")
	if err != nil || reused != 910000 {
		t.Fatalf("reuse after failed assign = (%d, %v), want 910000", reused, err)
	}
}

// TestSetupXFSProjectQuotaLimitAndCleanupFailureKeepsID: when the hard-limit
// command fails AND the compensating cleanup also fails, the reported reason
// says the project ID stays allocated — and it really does, so no other
// workspace can inherit an assignment that may still exist.
func TestSetupXFSProjectQuotaLimitAndCleanupFailureKeepsID(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "920000")
	t.Setenv(xfsProjectIDCountEnv, "1")
	t.Setenv("FAKE_XFS_LOG", filepath.Join(t.TempDir(), "xfs.log"))
	// "bhard" matches both the applied limit and the limit=0 cleanup, so
	// the assignment succeeds but every limit command fails.
	script := writeFakeXFSQuota(t, "bhard")

	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:22", fsType: "xfs"}
	status, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws", entry, 1<<20, script)
	if status.Hard || cleanup != nil {
		t.Fatalf("limit failure = %+v cleanup=%v", status, cleanup != nil)
	}
	if !strings.Contains(status.Detail, "apply XFS project hard limit") {
		t.Fatalf("detail = %q", status.Detail)
	}
	if !strings.Contains(status.Detail, "cleanup also failed") {
		t.Fatalf("detail %q must report the failed cleanup", status.Detail)
	}
	// The assignment may still exist, so the ID must NOT be handed out.
	if n := projectIDPoolFor("8:22").liveCount(); n != 1 {
		t.Fatalf("live IDs after failed cleanup = %d, want 1 (never reused)", n)
	}
	if _, err := allocateXFSProjectID("8:22"); err == nil {
		t.Fatal("the possibly-assigned project ID was handed out again")
	}
}

// TestXFSProjectIDPoolReusePersistsAcrossLookups is a small regression pin:
// the pool returned for a filesystem key is stable, so two lookups cannot
// hand out the same ID from two fresh pools.
func TestXFSProjectIDPoolReusePersistsAcrossLookups(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "930000")
	t.Setenv(xfsProjectIDCountEnv, "2")
	first := projectIDPoolFor("8:23")
	id, ok := first.allocate()
	if !ok {
		t.Fatal("first allocation failed")
	}
	if again := projectIDPoolFor("8:23"); again != first {
		t.Fatal("projectIDPoolFor returned a fresh pool for the same filesystem")
	}
	if second, _ := projectIDPoolFor("8:23").allocate(); second == id {
		t.Fatalf("ID %d handed out twice", id)
	}
}

// TestSetupXFSProjectQuotaAssignCleanupFailureQuarantinesID pins the
// ambiguous-side-effect rule: when the assignment command fails AND the
// ID-named cleanup also fails, the ID must NOT return to the pool, because
// the workspace may still carry it. A later workspace can never be handed the
// same project ID.
func TestSetupXFSProjectQuotaAssignCleanupFailureQuarantinesID(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "910000")
	t.Setenv(xfsProjectIDCountEnv, "1")
	t.Setenv("FAKE_XFS_LOG", filepath.Join(t.TempDir(), "xfs.log"))
	// Fails both the assignment ("project -s ...") and its cleanup
	// ("project -C ..."): removal cannot be proven.
	script := writeFakeXFSQuota(t, "project")

	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:30", fsType: "xfs"}
	status, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws", entry, 1<<20, script)
	if status.Hard || cleanup != nil {
		t.Fatalf("ambiguous assign failure = %+v cleanup=%v", status, cleanup != nil)
	}
	if !strings.Contains(status.Detail, "stays allocated") {
		t.Fatalf("detail = %q, want the explicit quarantine reason", status.Detail)
	}
	if n := projectIDPoolFor("8:30").liveCount(); n != 1 {
		t.Fatalf("live IDs after ambiguous assign failure = %d, want 1 (quarantined)", n)
	}
	// The one-ID pool is exhausted: a second workspace gets an allocation
	// failure, never a shared project ID.
	second, _ := setupXFSProjectQuotaOnMount("/mnt/xfs/ws2", entry, 1<<20, script)
	if second.Hard || !strings.Contains(second.Detail, "allocate XFS project id") {
		t.Fatalf("second workspace = %+v, want allocation exhaustion (no ID reuse)", second)
	}
}

// writeXFSDiscoveryScript installs a fake xfs_quota whose `report -p -n`
// output comes from FAKE_XFS_REPORT (printf %b so \n works) and whose exit
// code comes from FAKE_XFS_REPORT_EXIT; every other invocation succeeds
// silently.
func writeXFSDiscoveryScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "xfs_quota")
	body := `#!/bin/sh
case "$*" in
  *"report -p -n"*) printf '%b' "${FAKE_XFS_REPORT:-}"; exit "${FAKE_XFS_REPORT_EXIT:-0}";;
esac
exit 0
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

// TestXFSDiscoveryReservesExistingProjectIDs pins restart safety: project IDs
// the filesystem already knows are never handed out by a fresh process.
func TestXFSDiscoveryReservesExistingProjectIDs(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "100000")
	t.Setenv(xfsProjectIDCountEnv, "4")
	t.Setenv("FAKE_XFS_REPORT", "#100000\n#100002\n")
	script := writeXFSDiscoveryScript(t)

	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:40", fsType: "xfs"}
	status, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws", entry, 1<<20, script)
	if !status.Hard || cleanup == nil {
		t.Fatalf("setup with discovery = %+v cleanup=%v", status, cleanup != nil)
	}
	if !strings.Contains(status.Detail, "XFS project quota 100001") {
		t.Fatalf("allocated ID detail = %q, want 100001 (known IDs skipped)", status.Detail)
	}
	// The next allocation must skip BOTH discovered IDs (and the live one).
	next, err := allocateXFSProjectID("8:40")
	if err != nil || next != 100003 {
		t.Fatalf("next allocation = (%d, %v), want 100003 (100000/100002 discovered)", next, err)
	}
	releaseXFSProjectID("8:40", next)
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestXFSDiscoveryFailureFailsClosed pins that an unknown project-ID space is
// not treated as empty.
func TestXFSDiscoveryFailureFailsClosed(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "100000")
	t.Setenv(xfsProjectIDCountEnv, "1")
	t.Setenv("FAKE_XFS_REPORT_EXIT", "1")
	script := writeXFSDiscoveryScript(t)

	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:41", fsType: "xfs"}
	status, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws", entry, 1<<20, script)
	if status.Hard || cleanup != nil {
		t.Fatalf("failed discovery must not report a hard bound: %+v", status)
	}
	if !strings.Contains(status.Detail, "enumerate existing XFS project ids") {
		t.Fatalf("detail = %q", status.Detail)
	}
}

// TestXFSRestartCannotReuseExistingAssignment is the process-boundary
// regression: process A allocates an ID and leaves the kernel assignment
// behind; after A disappears (the Go pool is reset), process B must not
// allocate the same ID.
func TestXFSRestartCannotReuseExistingAssignment(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "100000")
	t.Setenv(xfsProjectIDCountEnv, "1")
	t.Setenv("FAKE_XFS_REPORT", "")
	script := writeXFSDiscoveryScript(t)
	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:42", fsType: "xfs"}

	first, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws-a", entry, 1<<20, script)
	if !first.Hard || cleanup == nil {
		t.Fatalf("process A setup = %+v", first)
	}
	// Process A dies WITHOUT cleanup: the kernel assignment for 100000 stays.
	// Process B starts with an empty Go allocator but the same filesystem.
	xfsProjectIDPools.mu.Lock()
	xfsProjectIDPools.m = map[string]*projectIDPool{}
	xfsProjectIDPools.mu.Unlock()
	t.Setenv("FAKE_XFS_REPORT", "#100000\n")

	second, cleanupB := setupXFSProjectQuotaOnMount("/mnt/xfs/ws-b", entry, 1<<20, script)
	if second.Hard || cleanupB != nil {
		t.Fatalf("process B reused a live project ID: %+v", second)
	}
	if !strings.Contains(second.Detail, "allocate XFS project id") || !strings.Contains(second.Detail, "exhausted") {
		t.Fatalf("process B detail = %q, want allocation exhaustion (no reuse)", second.Detail)
	}
}

// TestXFSAllocationSerializedAcrossProcesses proves the acquire sequence is
// serialized by the host-global lock: while another holder owns the
// filesystem lock, a second acquisition blocks instead of racing the report
// and choosing the same ID. flock is per open file description, so a second
// acquisition in this process behaves like a second process.
func TestXFSAllocationSerializedAcrossProcesses(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "100000")
	t.Setenv(xfsProjectIDCountEnv, "1")
	t.Setenv("KIWI_XFS_LOCK_DIR", t.TempDir())
	t.Setenv("FAKE_XFS_REPORT", "")
	script := writeXFSDiscoveryScript(t)
	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:50", fsType: "xfs"}

	holder, err := lockXFSAllocation(entry.fsKey())
	if err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	done := make(chan DiskQuotaStatus, 1)
	go func() {
		status, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws-A", entry, 1<<20, script)
		if cleanup != nil {
			_ = cleanup()
		}
		done <- status
	}()
	select {
	case status := <-done:
		t.Fatalf("second allocation completed while the filesystem lock was held: %+v", status)
	case <-time.After(150 * time.Millisecond):
	}
	holder()
	select {
	case status := <-done:
		if !status.Hard {
			t.Fatalf("second allocation after release = %+v, want success", status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second allocation never completed after the lock was released")
	}
}

// TestXFSExternalAssignmentAppearingAfterInitialDiscoveryIsRespected pins the
// re-report rule: an assignment published by another process AFTER this
// process's first discovery must be seen by the next allocation (the pool's
// cached knowledge is not authoritative).
func TestXFSExternalAssignmentAppearingAfterInitialDiscoveryIsRespected(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "100000")
	t.Setenv(xfsProjectIDCountEnv, "4")
	t.Setenv("KIWI_XFS_LOCK_DIR", t.TempDir())
	t.Setenv("FAKE_XFS_REPORT", "")
	script := writeXFSDiscoveryScript(t)
	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:51", fsType: "xfs"}

	first, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws-A", entry, 1<<20, script)
	if !first.Hard || cleanup == nil {
		t.Fatalf("first setup = %+v", first)
	}
	// Another process publishes 100000 (the ID this process just allocated is
	// irrelevant); the next report includes it plus a foreign 100002.
	t.Setenv("FAKE_XFS_REPORT", "#100000\n#100002\n")
	second, cleanup2 := setupXFSProjectQuotaOnMount("/mnt/xfs/ws-B", entry, 1<<20, script)
	if !second.Hard || cleanup2 == nil {
		t.Fatalf("second setup = %+v", second)
	}
	if !strings.Contains(second.Detail, "XFS project quota 100001") {
		t.Fatalf("second allocation detail = %q, want 100001 (100000 is live, 100002 foreign)", second.Detail)
	}
	_ = cleanup()
	_ = cleanup2()
}
