//go:build !linux

package executor

import "context"

// setupJobCgroup is the non-Linux default: a job-scoped parent cgroup is a
// Linux cgroup-v2 mechanism, so every other host reports the exact reason and
// the executor falls back to per-container caps plus the aggregate service
// budget.
func setupJobCgroup(context.Context, jobCgroupRequest) (JobCgroupStatus, func() error) {
	return JobCgroupStatus{Detail: "job resource cgroups (docker --cgroup-parent) require a Linux host with a delegated cgroup v2 hierarchy"}, nil
}
