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
	// A current engine always reads as the current version — INCLUDING
	// when it leases an older-stamped job. Collapsing to the job stamp
	// (the first implementation) would have let a v2 job leased to a
	// current engine masquerade as a legacy-v2 lease and authorize an
	// omitted completion.
	if got := LeaseInterpreterFor([]string{ExecutionSemanticsVersion}, ExecutionSemanticsVersion); got != ExecutionSemanticsVersion {
		t.Fatalf("stamped v3 = %q", got)
	}
	if got := LeaseInterpreterFor(nil, LegacyExecutionSemanticsVersion); got != LegacyExecutionSemanticsVersion {
		t.Fatalf("stamped v2 with no advertisement = %q", got)
	}
	// The reachable dual-engine case: a runner advertising BOTH can lease a
	// v2-stamped job, and its identity must be the CURRENT engine — an
	// omitted completion from it is refused (only legacy leases bridge).
	if got := LeaseInterpreterFor([]string{LegacyExecutionSemanticsVersion, ExecutionSemanticsVersion}, LegacyExecutionSemanticsVersion); got != ExecutionSemanticsVersion {
		t.Fatalf("dual-advertising engine on a v2 job = %q, want the engine's current identity", got)
	}
	// v2-only advertisement (post-field, pre-current): its own advertised
	// engine is the identity.
	if got := LeaseInterpreterFor([]string{LegacyExecutionSemanticsVersion}, LegacyExecutionSemanticsVersion); got != LegacyExecutionSemanticsVersion {
		t.Fatalf("v2-only advertisement on a v2 job = %q", got)
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
