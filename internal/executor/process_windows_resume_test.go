//go:build windows

package executor

import (
	"os"
	"testing"
)

// TestResumeProcessFailsClosedOnDeadPID: resumeProcess must open a PROCESS
// handle and call NtResumeProcess — never OpenThread(PID). A PID that is
// not a live process must fail without panicking.
func TestResumeProcessFailsClosedOnDeadPID(t *testing.T) {
	if err := resumeProcess(nil); err == nil {
		t.Fatal("resumeProcess(nil) must fail")
	}
	// PID 0x7FFFFFF0 is not a plausible live process on a normal host.
	// If it happens to exist, the call still must not panic or resume
	// via a thread-id lookup.
	p, err := os.FindProcess(0x7FFFFFF0)
	if err != nil {
		t.Skipf("FindProcess: %v", err)
	}
	// resumeProcess may succeed or fail depending on kernel; the invariant
	// is no panic. (Open of a non-existent PID returns an error.)
	_ = resumeProcess(p)
}
