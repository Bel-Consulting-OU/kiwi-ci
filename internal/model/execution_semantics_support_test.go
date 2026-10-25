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

func TestLeaseInterpreterFor(t *testing.T) {
	// Stamped job always records the stamp (the lease gate required the
	// runner to advertise it).
	if got := LeaseInterpreterFor([]string{ExecutionSemanticsVersion}, ExecutionSemanticsVersion); got != ExecutionSemanticsVersion {
		t.Fatalf("stamped v3 = %q", got)
	}
	if got := LeaseInterpreterFor(nil, LegacyExecutionSemanticsVersion); got != LegacyExecutionSemanticsVersion {
		t.Fatalf("stamped v2 with no advertisement = %q", got)
	}
	// Unstamped + empty advertisement → legacy pre-field contract.
	if got := LeaseInterpreterFor(nil, ""); got != LegacyExecutionSemanticsVersion {
		t.Fatalf("unstamped no-ad = %q, want legacy", got)
	}
	// Unstamped + advertising runner → current engine.
	if got := LeaseInterpreterFor([]string{ExecutionSemanticsVersion}, ""); got != ExecutionSemanticsVersion {
		t.Fatalf("unstamped advertising = %q", got)
	}
	// Unstamped + only legacy advertised → legacy.
	if got := LeaseInterpreterFor([]string{LegacyExecutionSemanticsVersion}, ""); got != LegacyExecutionSemanticsVersion {
		t.Fatalf("unstamped legacy-ad = %q", got)
	}
}
