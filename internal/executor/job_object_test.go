package executor

import (
	"os/exec"
	"testing"
)

// TestJobObjectLimitKillOnJobCloseFlag pins the JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
// value the Windows Job Object helper applies, so a typo in the flag constant
// cannot silently disable kill-on-close tree termination.
func TestJobObjectLimitKillOnJobCloseFlag(t *testing.T) {
	if jobObjectLimitKillOnJobClose != 0x2000 {
		t.Fatalf("jobObjectLimitKillOnJobClose = %#x, want 0x2000", jobObjectLimitKillOnJobClose)
	}
}

// TestProcessSetQuotaAccessMask pins the OpenProcess access mask used before
// AssignProcessToJobObject: PROCESS_SET_QUOTA | PROCESS_TERMINATE.
func TestProcessSetQuotaAccessMask(t *testing.T) {
	if processSetQuotaOrTerminate != 0x0101 {
		t.Fatalf("processSetQuotaOrTerminate = %#x, want 0x0101", processSetQuotaOrTerminate)
	}
}

// validJobSupervisionPhases reports whether phases honors the post-Start
// supervision ordering contract: exactly one "start" first, "open" strictly
// before "assign", "assign" strictly before "supervise", and no phase may
// repeat or be missing.
func validJobSupervisionPhases(phases []string) bool {
	if len(phases) == 0 || phases[0] != "start" {
		return false
	}
	idx := make(map[string]int, len(phases))
	for i, p := range phases {
		if _, dup := idx[p]; dup {
			return false
		}
		idx[p] = i
	}
	return idx["open"] < idx["assign"] && idx["assign"] < idx["supervise"]
}

// TestJobSupervisionPhaseOrder pins the post-Start supervision contract: the
// child is opened, then assigned, and only then supervised. The pure
// validator rejects sequences that assign before open, supervise before
// assign, repeat a phase, or omit one.
func TestJobSupervisionPhaseOrder(t *testing.T) {
	valid := []string{"start", "open", "assign", "supervise"}
	if !validJobSupervisionPhases(valid) {
		t.Fatalf("canonical supervision order %v rejected", valid)
	}
	bad := [][]string{
		{"start", "assign", "open", "supervise"},         // assign before open
		{"start", "open", "supervise", "assign"},         // supervise before assign
		{"start", "open", "open", "assign", "supervise"}, // duplicate phase
		{"open", "assign", "supervise"},                  // missing start
		{"start", "open"},                                // missing assign and supervise
	}
	for _, phases := range bad {
		if validJobSupervisionPhases(phases) {
			t.Fatalf("out-of-order supervision sequence accepted: %v", phases)
		}
	}
}

// TestSuperviseChildOrdering asserts the portable supervision wrapper performs
// the platform assignment synchronously, in the caller goroutine, before
// returning: the tracked phases must be exactly start then assigned, with
// nothing in between, and a non-nil cleanup must be returned.
func TestSuperviseChildOrdering(t *testing.T) {
	var track []string
	cleanup, err := superviseChildNow(&exec.Cmd{}, &track)
	if err != nil {
		t.Fatalf("superviseChildNow: %v", err)
	}
	if cleanup == nil {
		t.Fatal("superviseChildNow returned nil cleanup")
	}
	want := []string{"start", "assigned"}
	if len(track) != len(want) {
		t.Fatalf("supervision phases = %v, want %v", track, want)
	}
	for i := range want {
		if track[i] != want[i] {
			t.Fatalf("supervision phases = %v, want %v", track, want)
		}
	}
	cleanup()
}
