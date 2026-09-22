//go:build linux

package executor

import "testing"

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
