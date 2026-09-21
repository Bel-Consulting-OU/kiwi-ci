package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// stubDiskQuota replaces the capability probe for one test.
func stubDiskQuota(t *testing.T, status DiskQuotaStatus, cleanup func() error) *int {
	t.Helper()
	orig := workspaceDiskQuotaSetup
	calls := 0
	workspaceDiskQuotaSetup = func(string, int64) (DiskQuotaStatus, func() error) {
		calls++
		return status, cleanup
	}
	t.Cleanup(func() { workspaceDiskQuotaSetup = orig })
	return &calls
}

// TestUntrustedDiskBoundPrecedence pins the documented workspaceMaxBytes
// precedence: declared disk for any job, then the untrusted override, then the
// mandatory untrusted default, and zero only for trusted jobs without a
// declaration (the historical unbounded behavior).
func TestUntrustedDiskBoundPrecedence(t *testing.T) {
	if DefaultUntrustedWorkspaceMaxBytes != 10<<30 {
		t.Fatalf("DefaultUntrustedWorkspaceMaxBytes = %d, want 10 GiB", DefaultUntrustedWorkspaceMaxBytes)
	}
	cases := []struct {
		name string
		b    ContainerBackend
		want int64
	}{
		{"trusted undeclared stays unbounded", ContainerBackend{}, 0},
		{"trusted declared wins", ContainerBackend{Resources: pipeline.Resources{Disk: 5 << 20}}, 5 << 20},
		{"untrusted undeclared gets the default", ContainerBackend{Untrusted: true}, DefaultUntrustedWorkspaceMaxBytes},
		{"untrusted override wins over default", ContainerBackend{Untrusted: true, UntrustedDiskMaxBytes: 7 << 20}, 7 << 20},
		{"untrusted declared wins over override", ContainerBackend{Untrusted: true, UntrustedDiskMaxBytes: 7 << 20, Resources: pipeline.Resources{Disk: 3 << 20}}, 3 << 20},
		{"negative override falls back to default", ContainerBackend{Untrusted: true, UntrustedDiskMaxBytes: -1}, DefaultUntrustedWorkspaceMaxBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.b.workspaceMaxBytes(); got != tc.want {
				t.Fatalf("workspaceMaxBytes() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestUntrustedJobWithoutDiskGetsDefaultBound proves the mandatory default is
// actually enforced, not just reported: an untrusted job whose workspace
// exceeds the (test-sized) untrusted budget is refused before the container
// starts, while the same workspace stays accepted for a trusted job.
func TestUntrustedJobWithoutDiskGetsDefaultBound(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	writeSizedFile(t, ws, "big.bin", 8192)
	untrusted := &ContainerBackend{Image: "alpine:3.19", Untrusted: true, UntrustedDiskMaxBytes: 4096, RunID: "r", JobID: "j"}
	err := untrusted.StartJob(context.Background(), ws, func(string) {})
	if err == nil {
		t.Fatal("untrusted over-budget workspace accepted")
	}
	if !strings.Contains(err.Error(), "resources.disk") || !strings.Contains(err.Error(), "8192 bytes used") {
		t.Fatalf("error does not explain the untrusted disk budget: %v", err)
	}
	if kind := runErrorKind(t, err); kind != ErrorFailure {
		t.Fatalf("kind = %q, want %q", kind, ErrorFailure)
	}
	trusted := &ContainerBackend{Image: "alpine:3.19", RunID: "r", JobID: "j"}
	if err := trusted.StartJob(context.Background(), ws, func(string) {}); err != nil {
		t.Fatalf("trusted job lost its unbounded default: %v", err)
	}
}

// TestUntrustedDiskQuotaGateFailsClosed proves the capability gate: when the
// probe cannot establish a hard OS-level bound, an untrusted job that demands
// one fails closed with a clear, actionable error before docker is even
// looked up.
func TestUntrustedDiskQuotaGateFailsClosed(t *testing.T) {
	stubDiskQuota(t, DiskQuotaStatus{Hard: false, Detail: "overlayfs has no project quotas"}, nil)
	t.Setenv("PATH", t.TempDir())
	ws := t.TempDir()
	b := &ContainerBackend{Image: "alpine:3.19", Untrusted: true, RequireDiskQuota: true}
	err := b.StartJob(context.Background(), ws, func(string) {})
	if err == nil {
		t.Fatal("untrusted job without a hard quota accepted")
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
}

// TestUntrustedDiskQuotaGateEscapeAllowsStepBoundaryOnly proves the documented
// escape (trusted-only/self-hosted): with the requirement lifted the untrusted
// job runs with the default budget and step-boundary enforcement.
func TestUntrustedDiskQuotaGateEscapeAllowsStepBoundaryOnly(t *testing.T) {
	installFakeBins(t)
	stubDiskQuota(t, DiskQuotaStatus{Hard: false, Detail: "no hard bound"}, nil)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	b := &ContainerBackend{Image: "alpine:3.19", Untrusted: true, RequireDiskQuota: false, RunID: "r", JobID: "j"}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err != nil {
		t.Fatalf("escaped untrusted StartJob: %v", err)
	}
	if err := b.Run(context.Background(), Command{Shell: "sh", Script: "echo bounded", Dir: ws, Env: os.Environ()}, func(string) {}); err != nil {
		t.Fatalf("escaped untrusted Run: %v", err)
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
}

// TestAllowUnquotaedUntrustedDiskEnv pins the operator escape switch.
func TestAllowUnquotaedUntrustedDiskEnv(t *testing.T) {
	t.Setenv(AllowUnquotaedUntrustedDiskEnv, "")
	if AllowUnquotaedUntrustedDisk() {
		t.Fatal("empty escape enabled")
	}
	for _, v := range []string{"1", "true", "TRUE", "yes"} {
		t.Setenv(AllowUnquotaedUntrustedDiskEnv, v)
		if !AllowUnquotaedUntrustedDisk() {
			t.Fatalf("escape %q not enabled", v)
		}
	}
	t.Setenv(AllowUnquotaedUntrustedDiskEnv, "0")
	if AllowUnquotaedUntrustedDisk() {
		t.Fatal(`escape "0" enabled`)
	}
}

// TestUntrustedDiskQuotaGateSuccessRunsCleanupOnce proves the positive path:
// when the probe establishes a hard bound, the job runs and the quota cleanup
// is invoked exactly once at job close (idempotent across repeated calls).
func TestUntrustedDiskQuotaGateSuccessRunsCleanupOnce(t *testing.T) {
	installFakeBins(t)
	cleaned := 0
	stubDiskQuota(t, DiskQuotaStatus{Hard: true, Detail: "fake xfs quota"}, func() error {
		cleaned++
		return nil
	})
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	b := &ContainerBackend{Image: "alpine:3.19", Untrusted: true, RequireDiskQuota: true, RunID: "r", JobID: "j"}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err != nil {
		t.Fatalf("quota-backed StartJob: %v", err)
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("quota cleanup calls = %d, want 1", cleaned)
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("second CloseJob: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("quota cleanup re-ran: %d", cleaned)
	}
}

// TestUntrustedDiskQuotaCleanupOnDockerRunFailure proves a failure after the
// quota was applied still removes it.
func TestUntrustedDiskQuotaCleanupOnDockerRunFailure(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_RUN_FAIL", "1")
	cleaned := 0
	stubDiskQuota(t, DiskQuotaStatus{Hard: true, Detail: "fake xfs quota"}, func() error {
		cleaned++
		return nil
	})
	ws := t.TempDir()
	b := &ContainerBackend{Image: "alpine:3.19", Untrusted: true, RequireDiskQuota: true}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err == nil {
		t.Fatal("failing docker run accepted")
	}
	if cleaned != 1 {
		t.Fatalf("quota cleanup calls = %d, want 1", cleaned)
	}
}

// TestWorkspaceUsageBytesNoFollowSymlinkedDir proves the measurement stays
// no-follow for directory symlinks and for a symlinked workspace root: a
// symlinked directory out of the tree contributes nothing, while the resolved
// root's own files still count.
func TestWorkspaceUsageBytesNoFollowSymlinkedDir(t *testing.T) {
	ws := t.TempDir()
	writeSizedFile(t, ws, "a.bin", 1000)
	outside := t.TempDir()
	writeSizedFile(t, outside, "big.bin", 1<<20)
	if err := os.Symlink(outside, filepath.Join(ws, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ws, filepath.Join(ws, "self")); err != nil {
		t.Fatal(err)
	}
	got, err := workspaceUsageBytes(ws)
	if err != nil {
		t.Fatalf("workspaceUsageBytes: %v", err)
	}
	if got != 1000 {
		t.Fatalf("usage = %d, want 1000 (symlinked dirs must not be followed)", got)
	}
	linkedRoot := filepath.Join(t.TempDir(), "ws-link")
	if err := os.Symlink(ws, linkedRoot); err != nil {
		t.Fatal(err)
	}
	got, err = workspaceUsageBytes(linkedRoot)
	if err != nil {
		t.Fatalf("symlinked root: %v", err)
	}
	if got != 1000 {
		t.Fatalf("symlinked root usage = %d, want 1000", got)
	}
}

// TestFindWorkspaceMountParsesMountinfo pins the mountinfo parser: longest
// mount-point prefix wins, octal escapes decode, and malformed lines are
// ignored.
func TestFindWorkspaceMountParsesMountinfo(t *testing.T) {
	mountInfo := strings.Join([]string{
		"36 35 98:0 / /mnt/data rw,relatime - xfs /dev/sdb1 rw,prjquota",
		"37 35 0:35 / / rw,relatime - overlay overlay rw,lowerdir=/a",
		`38 35 0:36 / /mnt/My\040Data rw,relatime - ext4 /dev/sdc1 rw`,
		"malformed line",
	}, "\n")
	entry, ok := findWorkspaceMount(mountInfo, "/mnt/data/job-ws")
	if !ok || entry.fsType != "xfs" || entry.mountPoint != "/mnt/data" {
		t.Fatalf("xfs mount = %+v, ok=%v", entry, ok)
	}
	if !hasMountOption(entry.superOptions, "prjquota") {
		t.Fatalf("prjquota not detected in %q", entry.superOptions)
	}
	entry, ok = findWorkspaceMount(mountInfo, "/mnt/data")
	if !ok || entry.mountPoint != "/mnt/data" {
		t.Fatalf("exact mount point = %+v, ok=%v", entry, ok)
	}
	entry, ok = findWorkspaceMount(mountInfo, "/srv/build")
	if !ok || entry.fsType != "overlay" || entry.mountPoint != "/" {
		t.Fatalf("root mount fallback = %+v, ok=%v", entry, ok)
	}
	entry, ok = findWorkspaceMount(mountInfo, "/mnt/My Data/ws")
	if !ok || entry.fsType != "ext4" || entry.mountPoint != "/mnt/My Data" {
		t.Fatalf("escaped mount point = %+v, ok=%v", entry, ok)
	}
	if _, ok := findWorkspaceMount(mountInfo, "relative/path"); ok {
		t.Fatal("relative path matched a mount")
	}
	if _, ok := parseMountInfoLine("36 35 98:0 / /mnt rw"); ok {
		t.Fatal("short mountinfo line parsed")
	}
	if hasMountOption("rw,relatime", "prjquota") {
		t.Fatal("prjquota detected without the option")
	}
	if !hasMountOption("rw,pquota,relatime", "pquota") {
		t.Fatal("pquota option not detected")
	}
}

// TestSetupWorkspaceDiskQuotaReportsHonestReason proves the host-OS probe// never claims a hard bound it did not establish: a reported hard bound must
// come with a cleanup, and a report without one must carry a reason. On a
// non-Linux test host the probe always reports Hard=false with a reason.
func TestSetupWorkspaceDiskQuotaReportsHonestReason(t *testing.T) {
	ws := t.TempDir()
	status, cleanup := setupWorkspaceDiskQuota(ws, 1<<20)
	if status.Hard {
		if cleanup == nil {
			t.Fatalf("probe claimed a hard bound without cleanup: %+v", status)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("cleanup after probe: %v", err)
		}
		return
	}
	if cleanup != nil {
		t.Fatal("probe without a hard bound returned a cleanup")
	}
	if status.Detail == "" {
		t.Fatal("probe gave no reason")
	}
}

// TestExecutorUntrustedDiskGateWiresThroughRunJob proves the executor Options
// reach the container backend: an untrusted job whose hard-quota gate is
// demanded fails closed at StartJob with the gate error.
func TestExecutorUntrustedDiskGateWiresThroughRunJob(t *testing.T) {
	installFakeBins(t)
	stubDiskQuota(t, DiskQuotaStatus{Hard: false, Detail: "no hard bound here"}, nil)
	ws := t.TempDir()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Untrusted: true, RequireUntrustedDiskQuota: true}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", BaseID: "j",
		Job: pipeline.Job{Runtime: "container", Image: "alpine:3.19", Steps: []pipeline.Step{{Run: "echo hi"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "hard workspace disk quota") {
		t.Fatalf("untrusted runJob = status %q error %q", res.Status, res.Error)
	}
}

// TestExecutorUntrustedDiskOptionsBudgetWiresThroughRunJob proves the
// per-executor untrusted budget override reaches the backend.
func TestExecutorUntrustedDiskOptionsBudgetWiresThroughRunJob(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	writeSizedFile(t, ws, "big.bin", 8192)
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Untrusted: true, UntrustedWorkspaceMaxBytes: 4096}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", BaseID: "j",
		Job: pipeline.Job{Runtime: "container", Image: "alpine:3.19", Steps: []pipeline.Step{{Run: "echo hi"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "resources.disk") || !strings.Contains(res.Error, "8192 bytes used") {
		t.Fatalf("untrusted budget override = status %q error %q", res.Status, res.Error)
	}
}

// TestExecutorTrustedJobSkipsDiskQuotaGate proves trusted jobs keep the
// documented behavior: no untrusted default budget, no capability probe.
func TestExecutorTrustedJobSkipsDiskQuotaGate(t *testing.T) {
	installFakeBins(t)
	probeCalls := 0
	orig := workspaceDiskQuotaSetup
	workspaceDiskQuotaSetup = func(string, int64) (DiskQuotaStatus, func() error) {
		probeCalls++
		return DiskQuotaStatus{Hard: false, Detail: "must not be consulted"}, nil
	}
	t.Cleanup(func() { workspaceDiskQuotaSetup = orig })
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r"}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", BaseID: "j",
		Job: pipeline.Job{Runtime: "container", Image: "alpine:3.19", Steps: []pipeline.Step{{Run: "echo hi"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("trusted runJob = status %q error %q", res.Status, res.Error)
	}
	if probeCalls != 0 {
		t.Fatalf("trusted job consulted the untrusted quota probe %d times", probeCalls)
	}
}
