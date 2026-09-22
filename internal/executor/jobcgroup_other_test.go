//go:build !linux

package executor

import (
	"context"
	"strings"
	"testing"
)

// TestSetupJobCgroupNonLinuxReportsReason proves the documented contract on
// hosts without Linux cgroup v2: no job cgroup, a hard reason in Detail, and
// no cleanup for the caller to run.
func TestSetupJobCgroupNonLinuxReportsReason(t *testing.T) {
	status, cleanup := setupJobCgroup(context.Background(), jobCgroupRequest{JobID: "j", CPU: 2, Memory: 1 << 30, PIDs: 64})
	if status.Enabled || cleanup != nil {
		t.Fatalf("non-Linux job cgroup = %+v, cleanup=%v", status, cleanup != nil)
	}
	if status.Detail == "" || !strings.Contains(status.Detail, "Linux") {
		t.Fatalf("reason = %q, want an explanation naming Linux", status.Detail)
	}
}
