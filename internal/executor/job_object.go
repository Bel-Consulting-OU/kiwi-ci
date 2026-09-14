package executor

// jobObjectLimitKillOnJobClose mirrors the Windows
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag (0x2000). Applied to a Job Object
// it makes Windows terminate every process assigned to the job when the last
// handle to the job is closed, so an executor that dies (or a cancelled
// command whose job handle is closed after Wait) never leaves a detached
// child process tree behind. Kept in a portable file so tests can assert the
// flag value on every platform.
const jobObjectLimitKillOnJobClose = 0x2000
