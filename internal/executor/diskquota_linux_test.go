//go:build linux

package executor

import "testing"

// TestWorkspaceProjectIDStableAndNonzero pins the project-id derivation: the
// same workspace always maps to the same nonzero 31-bit id, and distinct
// workspaces map to distinct ids.
func TestWorkspaceProjectIDStableAndNonzero(t *testing.T) {
	a := workspaceProjectID("/var/lib/kiwi/run-1")
	b := workspaceProjectID("/var/lib/kiwi/run-1")
	if a != b || a == 0 {
		t.Fatalf("project id not stable/nonzero: %d vs %d", a, b)
	}
	if a > 0x7fffffff {
		t.Fatalf("project id %d outside the 31-bit range", a)
	}
	if c := workspaceProjectID("/var/lib/kiwi/run-2"); c == a {
		t.Fatalf("distinct workspaces share project id %d", a)
	}
}

// TestXFSQuoteEscapesSingleQuotes proves paths with quotes stay one command
// argument for the xfs_quota command language.
func TestXFSQuoteEscapesSingleQuotes(t *testing.T) {
	if got := xfsQuote("/tmp/plain"); got != "'/tmp/plain'" {
		t.Fatalf("plain quote = %q", got)
	}
	if got := xfsQuote("/tmp/it's"); got != `'/tmp/it'\''s'` {
		t.Fatalf("embedded quote = %q", got)
	}
}

// TestSetupXFSProjectQuotaWithoutPrjquotaReportsReason proves the XFS branch
// fails closed (no hard bound, no cleanup) when the mount lacks prjquota.
func TestSetupXFSProjectQuotaWithoutPrjquotaReportsReason(t *testing.T) {
	status, cleanup := setupXFSProjectQuota("/tmp/ws", mountInfoEntry{mountPoint: "/", fsType: "xfs", superOptions: "rw,relatime"}, 1<<20)
	if status.Hard || cleanup != nil || status.Detail == "" {
		t.Fatalf("non-prjquota XFS = %+v, cleanup=%v", status, cleanup != nil)
	}
}
