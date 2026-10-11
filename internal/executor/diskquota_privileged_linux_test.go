//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

// TestValidateQuotaAssignmentRefusesForgedLedgerEntries pins the privileged
// cleanup guard: a recorded tool that is not an euid-owned executable, a
// relative path, and a mount point that is not a prjquota XFS mount are all
// refused before any command runs. The mount proof reads the real
// /proc/self/mountinfo, so the test is Linux-specific; the tool-ownership
// half runs on every unix in TestValidatePrivilegedToolRefusals.
func TestValidateQuotaAssignmentRefusesForgedLedgerEntries(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "xfs_quota")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Tool checks.
	if err := validatePrivilegedTool("relative/tool"); err == nil {
		t.Fatal("relative tool path accepted")
	}
	if err := validatePrivilegedTool(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing tool accepted")
	}
	nonExec := filepath.Join(dir, "nonexec")
	if err := os.WriteFile(nonExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivilegedTool(nonExec); err == nil {
		t.Fatal("non-executable tool accepted")
	}
	if err := validatePrivilegedTool(script); err != nil {
		t.Fatalf("valid tool refused: %v", err)
	}
	// Mount proof: an unmounted fake path is refused.
	err := validateQuotaAssignment(WorkspaceQuotaAssignment{
		Workspace: "/tmp/x", MountPoint: "/definitely-not-mounted", XQ: script, ProjectID: 5,
	})
	if err == nil {
		t.Fatal("unmounted ledger mount point accepted")
	}
}
