//go:build linux

package executor

import (
	"fmt"
	"os"
	"os/exec"
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
		return setupXFSProjectQuota(workspace, entry, limit)
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
	return setupXFSProjectQuotaOnMount(workspace, entry, limit, xq)
}
