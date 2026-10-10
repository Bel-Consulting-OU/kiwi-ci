//go:build !windows

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestSetupWorkspaceDiskQuotaUnsupportedFilesystem covers the non-XFS
// branches of the capability probe on the real host mount table: the status
// must carry the reason, never claim a hard bound.
func TestSetupWorkspaceDiskQuotaUnsupportedFilesystem(t *testing.T) {
	status, cleanup := setupWorkspaceDiskQuota(t.TempDir(), 1<<20)
	if cleanup != nil {
		t.Fatal("unsupported filesystem returned a cleanup")
	}
	if status.Hard {
		t.Fatal("unsupported filesystem claimed a hard quota")
	}
	if strings.TrimSpace(status.Detail) == "" {
		t.Fatal("unsupported filesystem reported no reason")
	}
}

// TestSetupXFSProjectQuotaRequiresRoot covers the privilege refusal with a
// synthetic prjquota mount entry.
func TestSetupXFSProjectQuotaRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the privilege refusal cannot trigger")
	}
	entry := mountInfoEntry{fsType: "xfs", mountPoint: "/mnt/xfs", superOptions: "rw,prjquota"}
	status, cleanup, err := setupXFSProjectQuotaWithHook(t.TempDir(), entry, 1<<20, nil)
	if err != nil || cleanup != nil {
		t.Fatalf("status = %+v cleanupNil=%v err=%v", status, cleanup == nil, err)
	}
	if !strings.Contains(status.Detail, "requires root") {
		t.Fatalf("detail = %q, want the privilege refusal", status.Detail)
	}
}

// TestValidateQuotaAssignmentRefusals covers the not-currently-mounted and
// non-XFS mount refusals that gate privileged cleanup.
func TestValidateQuotaAssignmentRefusals(t *testing.T) {
	err := validateQuotaAssignment(WorkspaceQuotaAssignment{MountPoint: "/definitely-not-mounted-xyz", XQ: "/bin/true"})
	if err == nil || !strings.Contains(err.Error(), "not currently mounted") {
		t.Fatalf("unmounted assignment = %v", err)
	}
	err = validateQuotaAssignment(WorkspaceQuotaAssignment{MountPoint: "/", XQ: "/bin/true"})
	if err == nil || !strings.Contains(err.Error(), "prjquota XFS") {
		t.Fatalf("root assignment = %v", err)
	}
}

// TestValidatePrivilegedToolRefusals covers the path-shape, stat and
// ownership gates.
func TestValidatePrivilegedToolRefusals(t *testing.T) {
	if err := validatePrivilegedTool("relative/tool"); err == nil {
		t.Fatal("relative tool accepted")
	}
	if err := validatePrivilegedTool("/usr/bin/../bin/true"); err == nil {
		t.Fatal("dot-dot tool accepted")
	}
	if err := validatePrivilegedTool(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing tool accepted")
	}
	if err := validatePrivilegedTool("/dev/null"); err == nil {
		t.Fatal("non-regular tool accepted")
	}
	if os.Geteuid() != 0 {
		if err := validatePrivilegedTool("/bin/sh"); err == nil || !strings.Contains(err.Error(), "not owned by the runner") {
			t.Fatalf("foreign-owned tool = %v", err)
		}
	}
}

// TestReclaimJobCgroupMalformed covers the path-shape refusal.
func TestReclaimJobCgroupMalformed(t *testing.T) {
	if err := ReclaimJobCgroup(""); err != nil {
		t.Fatalf("empty cgroup = %v, want nil", err)
	}
	if err := ReclaimJobCgroup("relative/path"); err == nil {
		t.Fatal("relative cgroup accepted")
	}
	if err := ReclaimJobCgroup("/job/../escape"); err == nil {
		t.Fatal("dot-dot cgroup accepted")
	}
	if err := ReclaimJobCgroup("/kiwi-nonexistent-cgroup-xyz"); err != nil {
		t.Fatalf("already-gone cgroup = %v, want nil", err)
	}
}

// TestClampObservedBounds covers the truncation and the drop-unsafe arms.
func TestClampObservedBounds(t *testing.T) {
	if got := clampObserved("  value  ", 64); got != "value" {
		t.Fatalf("trim = %q", got)
	}
	if got := clampObserved("abcdef", 3); got != "abc" {
		t.Fatalf("truncate = %q", got)
	}
	if got := clampObserved("bad\x00null", 64); got != "" {
		t.Fatalf("control char = %q, want dropped", got)
	}
	if got := clampObserved("line\nbreak", 64); got != "" {
		t.Fatalf("newline = %q, want dropped", got)
	}
	if got := clampObserved(string([]byte{0xff, 0xfe}), 64); got != "" {
		t.Fatalf("invalid UTF-8 = %q, want dropped", got)
	}
}

// TestServiceImageRefsArms covers the empty and anonymous-name derivations.
func TestServiceImageRefsArms(t *testing.T) {
	if got := serviceImageRefs(nil); got != nil {
		t.Fatalf("nil services = %v", got)
	}
	refs := serviceImageRefs([]pipeline.Service{{Image: "alpine:3.19"}, {Name: "db", Image: "postgres:16"}})
	if refs["alpine:3.19"] != "alpine:3.19" || refs["db"] != "postgres:16" {
		t.Fatalf("refs = %v", refs)
	}
}

// TestCaptureContainerObservedRuntimeDigestBound proves the distinct-image
// bound: beyond the cap, references are still recorded but no digest probe is
// attempted.
func TestCaptureContainerObservedRuntimeDigestBound(t *testing.T) {
	services := map[string]string{}
	for i := 0; i < maxObservedServiceImages+4; i++ {
		services[string(rune('a'+i))] = "img-" + string(rune('a'+i)) + ":latest"
	}
	obs := captureContainerObservedRuntime(context.Background(), "", "main:latest", services)
	if obs == nil || len(obs.ServiceImages) != len(services) {
		t.Fatalf("observed services = %v", obs.ServiceImages)
	}
	if len(obs.ServiceImageDigests) != 0 {
		t.Fatalf("digests captured without a docker CLI: %v", obs.ServiceImageDigests)
	}
}

// TestWriteOwnerOnlyUndeletablePath covers the replace-existing failure: a
// non-empty directory at the key path cannot be removed, so the write is
// refused instead of silently retrying forever.
func TestWriteOwnerOnlyUndeletablePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "occupied")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteOwnerOnly(dir, []byte("secret")); err == nil {
		t.Fatal("undeletable key path accepted")
	}
}

// TestJobCgroupBaseFailures covers the missing-docker and non-cgroupfs driver
// refusals plus the walk-to-root refusal.
func TestJobCgroupBaseFailures(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := dockerAcceptsCgroupPath(context.Background()); err == nil {
		t.Fatal("missing docker accepted")
	}

	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_INFO", "systemd")
	if err := dockerAcceptsCgroupPath(context.Background()); err == nil || !strings.Contains(err.Error(), "systemd") {
		t.Fatalf("systemd driver = %v, want the refusal", err)
	}

	if _, err := jobCgroupBase(t.TempDir(), []string{"memory"}, ""); err == nil {
		t.Fatal("undelegatable cgroup base accepted")
	}
	if _, err := jobCgroupBase(t.TempDir(), []string{"memory"}, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing override cgroup accepted")
	}
}
