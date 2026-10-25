package model

import "testing"

func TestSupportsExecutionSemantics(t *testing.T) {
	// Legacy runner (no advertisement): only v2.
	if SupportsExecutionSemantics(nil, ExecutionSemanticsVersion) {
		t.Fatal("legacy runner must not receive a stamped current job")
	}
	if !SupportsExecutionSemantics(nil, LegacyExecutionSemanticsVersion) {
		t.Fatal("legacy runner must still receive v2 jobs")
	}
	// Current runner.
	cur := []string{ExecutionSemanticsVersion}
	if !SupportsExecutionSemantics(cur, ExecutionSemanticsVersion) {
		t.Fatal("current runner must receive current jobs")
	}
	if SupportsExecutionSemantics(cur, LegacyExecutionSemanticsVersion) {
		t.Fatal("current-only runner must not interpret a foreign stamp")
	}
	// Empty job stamp (pre-stamp legacy record) is always admitted at lease
	// time; replay owns the empty-stamp warning.
	if !SupportsExecutionSemantics(nil, "") {
		t.Fatal("empty job stamp must lease")
	}
}
