package executor

import "testing"

// TestJobObjectLimitKillOnJobCloseFlag pins the JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
// value the Windows Job Object helper applies, so a typo in the flag constant
// cannot silently disable kill-on-close tree termination.
func TestJobObjectLimitKillOnJobCloseFlag(t *testing.T) {
	if jobObjectLimitKillOnJobClose != 0x2000 {
		t.Fatalf("jobObjectLimitKillOnJobClose = %#x, want 0x2000", jobObjectLimitKillOnJobClose)
	}
}
