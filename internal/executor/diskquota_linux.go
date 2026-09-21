//go:build linux

package executor

import (
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
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
// The attempt is genuine: when XFS, prjquota and root are all present, the
// project entry is created and a bhard limit is applied. The returned cleanup
// removes the project assignment and the limit.
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

// setupXFSProjectQuota applies an XFS project quota (tree quota) to the
// workspace directory: the containing XFS mount must carry the prjquota mount
// option, the process must be root (project quota manipulation needs
// CAP_SYS_ADMIN), and xfs_quota must be installed. Only when the project
// entry and the bhard limit are both accepted is Hard reported true.
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
	projID := workspaceProjectID(workspace)
	quoted := xfsQuote(workspace)
	run := func(command string) error {
		out, err := exec.Command(xq, "-x", "-c", command, entry.mountPoint).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %v: %s", command, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run(fmt.Sprintf("project -s -p %s %d", quoted, projID)); err != nil {
		return DiskQuotaStatus{Detail: "assign XFS project quota: " + err.Error()}, nil
	}
	if err := run(fmt.Sprintf("limit -p bhard=%d %d", limit, projID)); err != nil {
		// Leave nothing half-applied: drop the project assignment again.
		_ = run(fmt.Sprintf("project -C -p %s", quoted))
		return DiskQuotaStatus{Detail: "apply XFS project hard limit: " + err.Error()}, nil
	}
	cleanup := func() error {
		var errs []string
		if err := run(fmt.Sprintf("project -C -p %s", quoted)); err != nil {
			errs = append(errs, err.Error())
		}
		if err := run(fmt.Sprintf("limit -p bhard=0 %d", projID)); err != nil {
			errs = append(errs, err.Error())
		}
		if len(errs) > 0 {
			return fmt.Errorf("remove XFS project quota: %s", strings.Join(errs, "; "))
		}
		return nil
	}
	return DiskQuotaStatus{
		Hard:   true,
		Detail: fmt.Sprintf("XFS project quota %d enforces a hard %d-byte bound on %s (mount %s)", projID, limit, workspace, entry.mountPoint),
	}, cleanup
}

// workspaceProjectID derives a stable, nonzero 31-bit project ID from the
// absolute workspace path. XFS project IDs are 32-bit; keeping the high bit
// clear avoids signedness surprises in xfs_quota arguments.
func workspaceProjectID(workspace string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(workspace))
	id := h.Sum32() & 0x7fffffff
	if id == 0 {
		id = 1
	}
	return id
}

// xfsQuote single-quotes a path argument for the xfs_quota command language,
// escaping embedded single quotes.
func xfsQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}
