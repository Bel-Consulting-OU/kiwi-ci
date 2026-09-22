package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// resetProjectIDPools isolates the process-local per-filesystem allocator
// between tests.
func resetProjectIDPools(t *testing.T) {
	t.Helper()
	clearProjectIDPools := func() {
		xfsProjectIDPools.mu.Lock()
		xfsProjectIDPools.m = map[string]*projectIDPool{}
		xfsProjectIDPools.mu.Unlock()
	}
	clearProjectIDPools()
	t.Cleanup(clearProjectIDPools)
}

// writeFakeXFSQuota installs a fake xfs_quota script that records every
// invocation into FAKE_XFS_LOG and fails (non-zero) whenever the joined
// arguments match failPattern (an empty pattern never fails).
func writeFakeXFSQuota(t *testing.T, failPattern string) string {
	t.Helper()
	if failPattern == "" {
		failPattern = "NO-SUCH-FAILURE-MARKER"
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "xfs_quota")
	body := "#!/bin/sh\n" +
		"echo \"$@\" >> \"$FAKE_XFS_LOG\"\n" +
		"case \"$*\" in\n" +
		"  *'" + failPattern + "'*) echo simulated failure >&2; exit 1;;\n" +
		"esac\n" +
		"exit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

func readFakeXFSLog(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(os.Getenv("FAKE_XFS_LOG"))
	if err != nil {
		t.Fatalf("read fake xfs log: %v", err)
	}
	return string(b)
}

// TestProjectIDPoolNeverHandsOutTwoLiveIDs pins the allocator invariants: no
// ID is live twice, exhaustion is reported instead of reuse, and released IDs
// are reused deterministically (smallest first).
func TestProjectIDPoolNeverHandsOutTwoLiveIDs(t *testing.T) {
	p := newProjectIDPool(1000, 3)
	seen := map[uint32]bool{}
	var ids []uint32
	for i := 0; i < 3; i++ {
		id, ok := p.allocate()
		if !ok {
			t.Fatalf("allocation %d exhausted a 3-ID pool", i)
		}
		if seen[id] {
			t.Fatalf("ID %d handed out twice", id)
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if ids[0] != 1000 || ids[1] != 1001 || ids[2] != 1002 {
		t.Fatalf("IDs = %v, want 1000..1002", ids)
	}
	if _, ok := p.allocate(); ok {
		t.Fatal("exhausted pool handed out an ID")
	}
	if p.liveCount() != 3 {
		t.Fatalf("live = %d, want 3", p.liveCount())
	}
	// Releasing an unknown or already-released ID is a no-op, and a released
	// ID is reused before the cursor advances.
	p.release(9999)
	p.release(1001)
	p.release(1001)
	if p.liveCount() != 2 {
		t.Fatalf("live after release = %d, want 2", p.liveCount())
	}
	next, ok := p.allocate()
	if !ok || next != 1001 {
		t.Fatalf("reuse = (%d, %v), want the released 1001", next, ok)
	}
	if p.liveCount() != 3 {
		t.Fatalf("live after reuse = %d, want 3", p.liveCount())
	}
}

// TestXFSProjectIDAllocationIsPerFilesystem proves the documented
// mount-scoping: IDs are unique per filesystem (XFS project quotas are
// per-superblock), so the same numeric ID may be live on two filesystems, but
// never twice on one.
func TestXFSProjectIDAllocationIsPerFilesystem(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "700000")
	t.Setenv(xfsProjectIDCountEnv, "4")
	a, err := allocateXFSProjectID("8:1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := allocateXFSProjectID("8:2")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("per-filesystem pools diverged: %d vs %d", a, b)
	}
	c, err := allocateXFSProjectID("8:1")
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Fatalf("filesystem 8:1 handed out %d twice", a)
	}
	if a != 700000 || c != 700001 {
		t.Fatalf("IDs = (%d, %d), want 700000/700001", a, c)
	}
	// A one-ID filesystem exhausts explicitly, then accepts the released ID.
	t.Setenv(xfsProjectIDCountEnv, "4")
	releaseXFSProjectID("8:1", a)
	reused, err := allocateXFSProjectID("8:1")
	if err != nil || reused != a {
		t.Fatalf("reuse = (%d, %v), want %d", reused, err, a)
	}
	releaseXFSProjectID("8:2", b)
}

// TestXFSProjectIDPoolExhaustionIsExplicit proves an exhausted pool fails with
// a clear error instead of reusing a live ID.
func TestXFSProjectIDPoolExhaustionIsExplicit(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "800000")
	t.Setenv(xfsProjectIDCountEnv, "1")
	if _, err := allocateXFSProjectID("9:1"); err != nil {
		t.Fatalf("first allocation: %v", err)
	}
	_, err := allocateXFSProjectID("9:1")
	if err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("second allocation = %v, want an explicit exhaustion error", err)
	}
}

// TestXFSProjectIDConfigurationGuards pins the environment configuration
// guards: invalid, zero and over-range values fall back to the documented
// defaults instead of producing a broken pool.
func TestXFSProjectIDConfigurationGuards(t *testing.T) {
	for _, v := range []string{"", "abc", "0", "99999999999", "-1"} {
		t.Setenv(xfsProjectIDBaseEnv, v)
		if got := xfsProjectIDBase(); got != defaultXFSProjectIDBase {
			t.Fatalf("base(%q) = %d, want the default %d", v, got, defaultXFSProjectIDBase)
		}
	}
	t.Setenv(xfsProjectIDBaseEnv, "500000")
	if got := xfsProjectIDBase(); got != 500000 {
		t.Fatalf("base = %d, want 500000", got)
	}
	for _, v := range []string{"", "nope", "0", "4294967295"} {
		t.Setenv(xfsProjectIDCountEnv, v)
		if got := xfsProjectIDCount(); got != defaultXFSProjectIDCount {
			t.Fatalf("count(%q) = %d, want the default %d", v, got, defaultXFSProjectIDCount)
		}
	}
	// A base near the 31-bit ceiling clamps the pool so no ID overflows.
	p := newProjectIDPool(xfsProjectIDMax-1, 1<<20)
	if p.size != 2 {
		t.Fatalf("clamped size = %d, want 2", p.size)
	}
	// An in-range count is honoured (clamped only by the base above).
	t.Setenv(xfsProjectIDBaseEnv, "5000")
	t.Setenv(xfsProjectIDCountEnv, "100000")
	if got := xfsProjectIDCount(); got != 100000 {
		t.Fatalf("count = %d, want the configured 100000", got)
	}
	t.Setenv(xfsProjectIDCountEnv, "4294967295")
	if got := xfsProjectIDCount(); got != defaultXFSProjectIDCount {
		t.Fatalf("over-range count = %d, want the default", got)
	}
}

// TestXFSProjectCleanupCommandsNameTheID is the E3-D regression pin: BOTH
// cleanup commands carry the project ID. The previous `project -C -p <path>`
// form could remove the wrong project's state when a path was reused.
func TestXFSProjectCleanupCommandsNameTheID(t *testing.T) {
	cmds := xfsProjectCleanupCommands("/mnt/ws", 4242)
	if len(cmds) != 2 {
		t.Fatalf("cleanup commands = %v", cmds)
	}
	if cmds[0] != "project -C -p '/mnt/ws' 4242" {
		t.Fatalf("project cleanup = %q, want the ID included", cmds[0])
	}
	if cmds[1] != "limit -p bhard=0 4242" {
		t.Fatalf("limit cleanup = %q, want the ID included", cmds[1])
	}
	// Assignment and limit commands name the ID too.
	if got := xfsProjectAssignCommand("/mnt/ws", 4242); got != "project -s -p '/mnt/ws' 4242" {
		t.Fatalf("assign = %q", got)
	}
	if got := xfsProjectLimitCommand(1<<30, 4242); got != "limit -p bhard=1073741824 4242" {
		t.Fatalf("limit = %q", got)
	}
	// Quotes in the path stay one argument.
	if got := xfsProjectCleanupCommands("/mnt/it's", 7)[0]; got != `project -C -p '/mnt/it'\''s' 7` {
		t.Fatalf("quoted cleanup = %q", got)
	}
}

// TestSetupXFSProjectQuotaOnMountHappyPath proves the portable XFS core:
// allocation, assignment, the hard limit, the reported status, and a cleanup
// that removes the assignment by ID and releases the project ID only then.
func TestSetupXFSProjectQuotaOnMountHappyPath(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "500000")
	t.Setenv(xfsProjectIDCountEnv, "8")
	script := writeFakeXFSQuota(t, "")
	t.Setenv("FAKE_XFS_LOG", filepath.Join(t.TempDir(), "xfs.log"))
	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:1", fsType: "xfs"}
	status, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws", entry, 1<<30, script)
	if !status.Hard || status.Limit != 1<<30 {
		t.Fatalf("status = %+v, want a hard 1 GiB bound", status)
	}
	if cleanup == nil {
		t.Fatal("hard quota without cleanup")
	}
	if !strings.Contains(status.Detail, "500000") {
		t.Fatalf("detail does not name the project id: %q", status.Detail)
	}
	log := readFakeXFSLog(t)
	if !strings.Contains(log, "project -s -p '/mnt/xfs/ws' 500000") {
		t.Fatalf("assignment command missing or wrong:\n%s", log)
	}
	if !strings.Contains(log, "limit -p bhard=1073741824 500000") {
		t.Fatalf("limit command missing or wrong:\n%s", log)
	}
	if n := projectIDPoolFor("8:1").liveCount(); n != 1 {
		t.Fatalf("live IDs after apply = %d, want 1", n)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	log = readFakeXFSLog(t)
	if !strings.Contains(log, "project -C -p '/mnt/xfs/ws' 500000") {
		t.Fatalf("cleanup did not name the project id:\n%s", log)
	}
	if !strings.Contains(log, "limit -p bhard=0 500000") {
		t.Fatalf("limit cleanup missing the ID:\n%s", log)
	}
	if n := projectIDPoolFor("8:1").liveCount(); n != 0 {
		t.Fatalf("live IDs after cleanup = %d, want 0 (the ID must be reusable)", n)
	}
	if reused, err := allocateXFSProjectID("8:1"); err != nil || reused != 500000 {
		t.Fatalf("reuse after cleanup = (%d, %v), want 500000", reused, err)
	}
}

// TestSetupXFSProjectQuotaOnMountFailurePathCleansUp proves the failure path:
// when the limit command fails, the half-applied assignment is removed with
// the SAME ID-bearing cleanup and the ID is released, with no cleanup handed
// back to the caller.
func TestSetupXFSProjectQuotaOnMountFailurePathCleansUp(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "600000")
	script := writeFakeXFSQuota(t, "limit -p bhard=1073741824")
	t.Setenv("FAKE_XFS_LOG", filepath.Join(t.TempDir(), "xfs.log"))
	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:2", fsType: "xfs"}
	status, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws", entry, 1<<30, script)
	if status.Hard || cleanup != nil {
		t.Fatalf("failing limit reported %+v, cleanup=%v", status, cleanup != nil)
	}
	if !strings.Contains(status.Detail, "apply XFS project hard limit") {
		t.Fatalf("detail = %q", status.Detail)
	}
	log := readFakeXFSLog(t)
	if !strings.Contains(log, "project -s -p '/mnt/xfs/ws' 600000") {
		t.Fatalf("assignment wasn't attempted:\n%s", log)
	}
	if !strings.Contains(log, "project -C -p '/mnt/xfs/ws' 600000") {
		t.Fatalf("failure path cleanup did not name the project id:\n%s", log)
	}
	if !strings.Contains(log, "limit -p bhard=0 600000") {
		t.Fatalf("failure path limit cleanup missing the ID:\n%s", log)
	}
	if n := projectIDPoolFor("8:2").liveCount(); n != 0 {
		t.Fatalf("live IDs after failed apply = %d, want 0", n)
	}
}

// TestRunXFSProjectCleanupKeepsIDWhenRemovalFails proves the release ordering:
// an ID is returned to the pool only after BOTH removal commands succeeded, so
// a workspace whose assignment may still exist can never share its ID.
func TestRunXFSProjectCleanupKeepsIDWhenRemovalFails(t *testing.T) {
	resetProjectIDPools(t)
	t.Setenv(xfsProjectIDBaseEnv, "610000")
	script := writeFakeXFSQuota(t, "project -C")
	t.Setenv("FAKE_XFS_LOG", filepath.Join(t.TempDir(), "xfs.log"))
	entry := mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:3", fsType: "xfs"}
	status, cleanup := setupXFSProjectQuotaOnMount("/mnt/xfs/ws", entry, 1<<20, script)
	if !status.Hard || cleanup == nil {
		t.Fatalf("apply = %+v", status)
	}
	err := cleanup()
	if err == nil || !strings.Contains(err.Error(), "remove XFS project quota") {
		t.Fatalf("cleanup = %v, want a removal error", err)
	}
	if n := projectIDPoolFor("8:3").liveCount(); n != 1 {
		t.Fatalf("live IDs after failed cleanup = %d, want 1 (never reused)", n)
	}
}

// TestParseMountInfoLineCapturesDevice proves the allocator's filesystem key
// comes from the mountinfo device field.
func TestParseMountInfoLineCapturesDevice(t *testing.T) {
	entry, ok := parseMountInfoLine("36 35 98:0 / /mnt/data rw,relatime - xfs /dev/sdb1 rw,prjquota")
	if !ok || entry.device != "98:0" || entry.fsKey() != "98:0" {
		t.Fatalf("entry = %+v (ok=%v), want device 98:0 as the fs key", entry, ok)
	}
	if got := (mountInfoEntry{mountPoint: "/mnt", fsType: "xfs"}).fsKey(); got != "/mnt" {
		t.Fatalf("fsKey without device = %q, want the mount point fallback", got)
	}
}

// TestWorkspaceBoundBytesSharedPrecedence pins the single workspace-bound
// precedence shared by the runner and the container backend.
func TestWorkspaceBoundBytesSharedPrecedence(t *testing.T) {
	cases := []struct {
		name      string
		declared  int64
		untrusted bool
		override  int64
		want      int64
	}{
		{"trusted undeclared stays unbounded", 0, false, 0, 0},
		{"trusted declared wins", 5 << 20, false, 0, 5 << 20},
		{"untrusted undeclared gets the default", 0, true, 0, DefaultUntrustedWorkspaceMaxBytes},
		{"untrusted override wins over default", 0, true, 7 << 20, 7 << 20},
		{"untrusted declared wins over override", 3 << 20, true, 7 << 20, 3 << 20},
		{"negative override falls back to default", 0, true, -1, DefaultUntrustedWorkspaceMaxBytes},
		{"negative declared falls through", -1, true, 4 << 20, 4 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WorkspaceBoundBytes(tc.declared, tc.untrusted, tc.override); got != tc.want {
				t.Fatalf("WorkspaceBoundBytes = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestUntrustedDiskQuotaGateErrorText pins the shared fail-closed message: the
// runner's pre-checkout gate and the container backend's defense-in-depth gate
// must explain the same residual and name the escape hatch.
func TestUntrustedDiskQuotaGateErrorText(t *testing.T) {
	err := UntrustedDiskQuotaGateError("overlayfs has no project quotas")
	for _, want := range []string{"hard workspace disk quota", "overlayfs has no project quotas", AllowUnquotaedUntrustedDiskEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("gate error missing %q: %v", want, err)
		}
	}
	if kind := errorKind(err); kind != ErrorConfig {
		t.Fatalf("kind = %q, want %q", kind, ErrorConfig)
	}
}

// TestContainerBackendPreinstalledQuotaSkipsProbe proves the runner-owned
// quota lifecycle is authoritative for the backend: a caller-installed hard
// bound satisfies RequireDiskQuota without a second probe (two project
// assignments on one workspace would fight over the same tree).
func TestContainerBackendPreinstalledQuotaSkipsProbe(t *testing.T) {
	installFakeBins(t)
	probeCalls := 0
	orig := workspaceDiskQuotaSetup
	workspaceDiskQuotaSetup = func(string, int64) (DiskQuotaStatus, func() error) {
		probeCalls++
		return DiskQuotaStatus{Detail: "backend probe must not run"}, nil
	}
	t.Cleanup(func() { workspaceDiskQuotaSetup = orig })
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	b := &ContainerBackend{
		Image: "alpine:3.19", Untrusted: true, RequireDiskQuota: true,
		WorkspaceQuota: &DiskQuotaStatus{Hard: true, Limit: 1 << 20, Detail: "runner-installed XFS quota 500001"},
		RunID:          "r", JobID: "j",
	}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err != nil {
		t.Fatalf("preinstalled quota StartJob: %v", err)
	}
	if probeCalls != 0 {
		t.Fatalf("backend re-probed %d times despite the preinstalled quota", probeCalls)
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
}

// TestContainerBackendCallerProbeFailureFailsClosed proves the defense in
// depth gate: a caller that probed and could not establish a hard bound
// produces the same fail-closed error (with the caller's reason) without a
// second probe and before docker is looked up.
func TestContainerBackendCallerProbeFailureFailsClosed(t *testing.T) {
	probeCalls := 0
	orig := workspaceDiskQuotaSetup
	workspaceDiskQuotaSetup = func(string, int64) (DiskQuotaStatus, func() error) {
		probeCalls++
		return DiskQuotaStatus{Detail: "should not be consulted"}, nil
	}
	t.Cleanup(func() { workspaceDiskQuotaSetup = orig })
	t.Setenv("PATH", t.TempDir())
	ws := t.TempDir()
	b := &ContainerBackend{
		Image: "alpine:3.19", Untrusted: true, RequireDiskQuota: true,
		WorkspaceQuota: &DiskQuotaStatus{Detail: "overlayfs has no project quotas"},
	}
	err := b.StartJob(context.Background(), ws, func(string) {})
	if err == nil {
		t.Fatal("untrusted job without a hard bound accepted")
	}
	for _, want := range []string{"hard workspace disk quota", "overlayfs has no project quotas", AllowUnquotaedUntrustedDiskEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("gate error missing %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "docker not found") {
		t.Fatalf("gate ran after the docker lookup: %v", err)
	}
	if kind := runErrorKind(t, err); kind != ErrorConfig {
		t.Fatalf("kind = %q, want %q", kind, ErrorConfig)
	}
	if probeCalls != 0 {
		t.Fatalf("backend re-probed %d times despite the caller outcome", probeCalls)
	}
}

// TestContainerBackendDeclaredDiskGetsRunnerQuotaLimit proves the shared
// workspace-bound precedence reaches the backend's step-boundary checks: a
// declared disk is used as-is.
func TestContainerBackendDeclaredDiskGetsRunnerQuotaLimit(t *testing.T) {
	b := &ContainerBackend{Resources: pipeline.Resources{Disk: 3 << 20}, Untrusted: true, UntrustedDiskMaxBytes: 7 << 20}
	if got := b.workspaceMaxBytes(); got != 3<<20 {
		t.Fatalf("workspaceMaxBytes = %d, want the declared 3 MiB", got)
	}
}
