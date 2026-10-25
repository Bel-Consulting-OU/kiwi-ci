//go:build linux

package executor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// configureProcessCgroup assigns Setpgid and, when cgroupParent is non-empty,
// clone-into-cgroup (UseCgroupFD/CgroupFD) so the child is born inside the
// durably recorded job cgroup. There is no Start→addPID race: a hard crash
// between fork and the first userspace instruction still leaves the process
// under cgroup.kill recovery.
//
// The returned closer MUST be called after cmd.Start (success or failure):
// it releases the cgroup directory fd the kernel consumed. Callers that
// fall back to Setpgid-only still get a non-nil closer (no-op).
func configureProcessCgroup(cmd *exec.Cmd, cgroupParent string) (func(), error) {
	configureProcess(cmd)
	if cgroupParent == "" || cmd.SysProcAttr == nil {
		return func() {}, nil
	}
	dir := cgroupAbsDir(cgroupParent)
	if dir == "" {
		return func() {}, fmt.Errorf("cgroup %q escapes the cgroup root", cgroupParent)
	}
	f, err := os.Open(dir)
	if err != nil {
		return func() {}, fmt.Errorf("open job cgroup %s for clone-into-cgroup: %w", dir, err)
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = int(f.Fd())
	return func() { _ = f.Close() }, nil
}

// cgroupAbsDir maps a job-cgroup parent ("/rel/path") to an absolute
// filesystem path under the cgroup root. Empty when the path is malformed.
func cgroupAbsDir(parent string) string {
	parent = strings.TrimSpace(parent)
	if parent == "" || !strings.HasPrefix(parent, "/") || strings.Contains(parent, "..") {
		return ""
	}
	root := jobCgroupRoot()
	dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(parent, "/")))
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return dir
}

// writePIDToJobCgroup is the post-Start fallback when UseCgroupFD was not
// available (older kernels return EINVAL for the attr).
func writePIDToJobCgroup(parent string, pid int) error {
	dir := cgroupAbsDir(parent)
	if dir == "" {
		return fmt.Errorf("refusing to add pid to malformed cgroup %q", parent)
	}
	return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)+"\n"), 0o644)
}

// ensure syscall is referenced for build-tag completeness on some toolchains.
var _ = syscall.ENOSYS

// cgroupFDActive reports whether the command still carries UseCgroupFD.
func cgroupFDActive(cmd *exec.Cmd) bool {
	return cmd.SysProcAttr != nil && cmd.SysProcAttr.UseCgroupFD
}
