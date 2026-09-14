package executor

import "os/exec"

// jobObjectLimitKillOnJobClose mirrors the Windows
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag (0x2000). Applied to a Job Object
// it makes Windows terminate every process assigned to the job when the last
// handle to the job is closed, so an executor that dies (or a cancelled
// command whose job handle is closed after Wait) never leaves a detached
// child process tree behind. Kept in a portable file so tests can assert the
// flag value on every platform.
const jobObjectLimitKillOnJobClose = 0x2000

// processSetQuotaOrTerminate is the OpenProcess access mask
// AssignProcessToJobObject requires on the child process handle:
// PROCESS_SET_QUOTA (0x0100) | PROCESS_TERMINATE (0x0001). Kept in a
// portable file so tests can pin the value on every platform.
const processSetQuotaOrTerminate = 0x0100 | 0x0001

// superviseChildNow is the portable wrapper around the per-platform
// superviseChild that enforces the post-Start supervision ordering contract:
// it must be called synchronously in the caller goroutine immediately after
// exec.Cmd.Start() has materialized cmd.Process and before any goroutine
// reads that process. On Windows the platform helper performs the real
// open-and-assign sequence (Job Object) before returning; on Unix it is a
// no-op because the process group set by configureProcess already covers the
// whole tree. track, when non-nil, receives each completed phase name in
// execution order so the portable ordering test can assert the sequence on
// every platform.
func superviseChildNow(cmd *exec.Cmd, track *[]string) (func(), error) {
	if track != nil {
		*track = append(*track, "start")
	}
	cleanup, err := superviseChild(cmd)
	if track != nil {
		*track = append(*track, "assigned")
	}
	return cleanup, err
}
