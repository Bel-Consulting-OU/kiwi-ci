//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Environment overrides for the job-scoped parent cgroup (see jobcgroup.go):
//
//	KIWI_JOB_CGROUP_ROOT   non-standard cgroup v2 mount root (default
//	                       /sys/fs/cgroup); also used by tests.
//	KIWI_JOB_CGROUP_PARENT an EXISTING delegated cgroup directory that job
//	                       cgroups are created under. It is the operator
//	                       escape hatch for daemons whose cgroupfs driver
//	                       cannot infer the runner's own subtree; the runner
//	                       then assumes the daemon accepts that cgroup path
//	                       as --cgroup-parent.
const (
	jobCgroupRootEnv   = "KIWI_JOB_CGROUP_ROOT"
	jobCgroupParentEnv = "KIWI_JOB_CGROUP_PARENT"
	// defaultJobCgroupRoot is the cgroup v2 unified mount point.
	defaultJobCgroupRoot = "/sys/fs/cgroup"
)

// jobCgroupRoot resolves the cgroup v2 mount root.
func jobCgroupRoot() string {
	if v := strings.TrimSpace(os.Getenv(jobCgroupRootEnv)); v != "" {
		return v
	}
	return defaultJobCgroupRoot
}

// setupJobCgroup creates the job-scoped parent cgroup on Linux and returns
// the docker --cgroup-parent value. It only reports Enabled when a real
// kernel-enforced parent exists:
//
//   - the cgroup v2 unified hierarchy must be mounted at the cgroup root;
//   - the daemon's cgroup driver must accept a cgroup path as
//     --cgroup-parent. The cgroupfs driver does; the systemd driver only
//     accepts a systemd slice name (runc's ExpandSlice rejects paths), and
//     creating a per-job slice needs systemd unit delegation the runner
//     cannot assume, so it is reported as unsupported here. An operator can
//     set KIWI_JOB_CGROUP_PARENT to an existing delegated cgroup directory
//     and skip this check;
//   - a delegated base cgroup must exist (the runner's own cgroup or the
//     nearest ancestor) whose cgroup.subtree_control already enables every
//     controller the declared envelope needs. The cgroup-v2 "no internal
//     processes" rule makes enabling a controller on the runner's own cgroup
//     impossible, so pre-existing delegation (systemd Delegate=yes) is
//     required.
//
// Every other outcome returns Enabled=false with the exact reason in Detail,
// and the caller keeps the per-container caps.
func setupJobCgroup(ctx context.Context, req jobCgroupRequest) (JobCgroupStatus, func() error) {
	if !req.declared() {
		return JobCgroupStatus{Detail: "job declares no resources.cpu/memory/pids: the scheduler reserved nothing, so no job-scoped cgroup is created"}, nil
	}
	root := jobCgroupRoot()
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return JobCgroupStatus{Detail: fmt.Sprintf("cgroup v2 unified hierarchy is not available at %s: %v", root, err)}, nil
	}
	parentOverride := strings.TrimSpace(os.Getenv(jobCgroupParentEnv))
	if parentOverride == "" {
		if err := dockerAcceptsCgroupPath(ctx); err != nil {
			return JobCgroupStatus{Detail: err.Error()}, nil
		}
	}
	base, err := jobCgroupBase(root, jobCgroupControllers(req), parentOverride)
	if err != nil {
		return JobCgroupStatus{Detail: err.Error()}, nil
	}
	dir, cleanup, err := createJobCgroupUnder(base, jobCgroupDirName(req.JobID, jobCgroupSuffix()), jobCgroupControllers(req), jobCgroupLimits(req))
	if err != nil {
		return JobCgroupStatus{Detail: err.Error()}, nil
	}
	rel, rerr := filepath.Rel(root, dir)
	if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		_ = cleanup()
		return JobCgroupStatus{Detail: fmt.Sprintf("job cgroup %s is not inside the cgroup root %s", dir, root)}, nil
	}
	parent := "/" + filepath.ToSlash(rel)
	return JobCgroupStatus{
		Enabled: true,
		Parent:  parent,
		Detail:  fmt.Sprintf("job-scoped cgroup %s (declared envelope %s) enforces the main container and every service together", parent, jobCgroupEnvelopeSummary(req)),
	}, cleanup
}

// dockerAcceptsCgroupPath verifies that the docker daemon's cgroup driver
// accepts a delegated cgroup path as --cgroup-parent. The systemd driver
// requires a slice unit name instead, which the runner cannot create per job
// without systemd delegation.
func dockerAcceptsCgroupPath(ctx context.Context) error {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker CLI not found: %v", err)
	}
	out, err := exec.CommandContext(ctx, docker, "info", "--format", "{{.CgroupDriver}}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect docker cgroup driver: %v: %s", err, strings.TrimSpace(string(out)))
	}
	switch driver := strings.ToLower(strings.TrimSpace(string(out))); driver {
	case "cgroupfs":
		return nil
	case "systemd":
		return errors.New("docker daemon uses the systemd cgroup driver, which only accepts a systemd slice name as --cgroup-parent (runc rejects a delegated cgroup path) and needs systemd unit delegation the runner cannot assume; set " + jobCgroupParentEnv + " to an existing delegated cgroup to override")
	case "":
		return errors.New("docker daemon reported no cgroup driver")
	default:
		return fmt.Errorf("docker daemon cgroup driver %q does not accept a delegated cgroup path", driver)
	}
}

// jobCgroupBase resolves the directory the job cgroup is created under: the
// operator override when set (verified to be delegated), otherwise the
// deepest directory on the path from the runner's own cgroup up to the cgroup
// root that already delegates the required controllers.
func jobCgroupBase(root string, need []string, override string) (string, error) {
	if override != "" {
		dir := override
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(root, dir)
		}
		if err := ensureDelegatedCgroupBase(dir, need); err != nil {
			return "", fmt.Errorf("%s=%s: %w", jobCgroupParentEnv, override, err)
		}
		return dir, nil
	}
	self, ok := runnerCgroupDir(root)
	if !ok {
		return "", errors.New("cannot determine the runner's own cgroup path from /proc/self/cgroup")
	}
	for {
		if err := ensureDelegatedCgroupBase(self, need); err == nil {
			return self, nil
		}
		if self == root || !strings.HasPrefix(self, root+string(filepath.Separator)) {
			break
		}
		self = filepath.Dir(self)
	}
	return "", fmt.Errorf("neither the runner's cgroup nor any of its ancestors delegates the controller(s) %s needed for the declared envelope; a rootless daemon or a runner outside a delegated cgroup-v2 subtree cannot host a job cgroup (set %s to an existing delegated cgroup to override)", strings.Join(need, ","), jobCgroupParentEnv)
}

// runnerCgroupDir reads the runner process's own cgroup v2 directory from
// /proc/self/cgroup (the "0::<path>" line of the unified hierarchy).
func runnerCgroupDir(root string) (string, bool) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue
		}
		rel := strings.TrimSpace(parts[2])
		if rel == "" || rel == "/" {
			return root, true
		}
		return filepath.Join(root, strings.TrimPrefix(rel, "/")), true
	}
	return "", false
}
