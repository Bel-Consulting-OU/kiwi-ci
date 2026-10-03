//go:build linux

package executor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// setupWorkspaceDiskQuota is the Linux capability probe: it inspects the
// filesystem backing the workspace and attempts to establish a real hard
// bound on the workspace tree. XFS is the only filesystem the executor can
// quota portably (project quotas via xfs_quota); ext4 project quotas need a
// per-mount prjquota option plus chattr/quotactl tooling the runner cannot
// rely on, and every other filesystem (overlay, tmpfs, ...) has no project
// quota story at all. In those cases Hard stays false with a reason, and the
// caller fails the untrusted job closed unless the operator escape hatch is
// set.
//
// The attempt is genuine: when XFS, prjquota and root are all present, a
// collision-free project ID is allocated for the workspace's filesystem, the
// project entry is created and a bhard limit is applied. The returned cleanup
// removes the project assignment (naming the ID) and the limit, and releases
// the ID.
func setupWorkspaceDiskQuota(workspace string, limit int64) (DiskQuotaStatus, func() error) {
	return setupWorkspaceDiskQuotaWithHook(workspace, limit, nil)
}

// setupWorkspaceDiskQuotaWithHook is setupWorkspaceDiskQuota plus the
// pre-assignment allocation callback (see WorkspaceDiskQuotaSetupWithHook).
func setupWorkspaceDiskQuotaWithHook(workspace string, limit int64, onAllocated func(WorkspaceQuotaAssignment)) (DiskQuotaStatus, func() error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return DiskQuotaStatus{Detail: fmt.Sprintf("read /proc/self/mountinfo: %v", err)}, nil
	}
	entry, ok := findWorkspaceMount(string(data), workspace)
	if !ok {
		return DiskQuotaStatus{Detail: fmt.Sprintf("workspace %s is not covered by any mount in /proc/self/mountinfo", workspace)}, nil
	}
	switch entry.fsType {
	case "xfs":
		return setupXFSProjectQuotaWithHook(workspace, entry, limit, onAllocated)
	case "ext4", "ext3", "ext2":
		return DiskQuotaStatus{Detail: fmt.Sprintf("%s mounted at %s: ext4 project quotas need a prjquota mount and chattr/quotactl tooling; the executor does not apply ext4 project quotas", entry.fsType, entry.mountPoint)}, nil
	default:
		return DiskQuotaStatus{Detail: fmt.Sprintf("workspace filesystem %s mounted at %s does not support project quotas", entry.fsType, entry.mountPoint)}, nil
	}
}

// setupXFSProjectQuota checks the host prerequisites for an XFS tree quota
// (prjquota mount option, root, xfs_quota on PATH) and then applies it through
// the portable core (setupXFSProjectQuotaOnMount).
func setupXFSProjectQuota(workspace string, entry mountInfoEntry, limit int64) (DiskQuotaStatus, func() error) {
	return setupXFSProjectQuotaWithHook(workspace, entry, limit, nil)
}

// setupXFSProjectQuotaWithHook is setupXFSProjectQuota plus the
// pre-assignment allocation callback.
func setupXFSProjectQuotaWithHook(workspace string, entry mountInfoEntry, limit int64, onAllocated func(WorkspaceQuotaAssignment)) (DiskQuotaStatus, func() error) {
	if !hasMountOption(entry.superOptions, "prjquota") && !hasMountOption(entry.superOptions, "pquota") {
		return DiskQuotaStatus{Detail: fmt.Sprintf("XFS mount %s is not mounted with prjquota (super options: %s)", entry.mountPoint, entry.superOptions)}, nil
	}
	if os.Geteuid() != 0 {
		return DiskQuotaStatus{Detail: fmt.Sprintf("setting an XFS project quota on %s requires root", entry.mountPoint)}, nil
	}
	xq, err := exec.LookPath("xfs_quota")
	if err != nil {
		return DiskQuotaStatus{Detail: fmt.Sprintf("xfs_quota not found: %v", err)}, nil
	}
	return setupXFSProjectQuotaOnMountHook(workspace, entry, limit, xq, onAllocated)
}

// validateQuotaAssignment proves a ledger-recorded assignment against HOST
// state before any privileged cleanup runs: the mount point must be a
// currently mounted XFS filesystem with project quotas, and the tool must be
// an absolute executable regular file owned by the effective user.
func validateQuotaAssignment(a WorkspaceQuotaAssignment) error {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("read /proc/self/mountinfo: %w", err)
	}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		entry, ok := parseMountInfoLine(line)
		if !ok || entry.mountPoint != a.MountPoint {
			continue
		}
		if entry.fsType != "xfs" || (!hasMountOption(entry.superOptions, "prjquota") && !hasMountOption(entry.superOptions, "pquota")) {
			return fmt.Errorf("recorded mount %s is not a prjquota XFS mount", a.MountPoint)
		}
		found = true
		break
	}
	if !found {
		return fmt.Errorf("recorded mount %s is not currently mounted", a.MountPoint)
	}
	return validatePrivilegedTool(a.XQ)
}

// validatePrivilegedTool proves a recorded helper before executing it as the
// runner (root for XFS): absolute path, regular executable file, owned by the
// effective user.
func validatePrivilegedTool(path string) error {
	if !filepath.IsAbs(path) || strings.Contains(path, "..") {
		return fmt.Errorf("recorded tool path %q is not a safe absolute path", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat recorded tool %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("recorded tool %s is not an executable regular file", path)
	}
	if !lockFileOwnerOK(info) {
		return fmt.Errorf("recorded tool %s is not owned by the runner", path)
	}
	return nil
}
