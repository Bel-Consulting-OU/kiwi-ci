//go:build !linux

package executor

import (
	"fmt"
	"runtime"
)

// setupWorkspaceDiskQuota reports that no hard OS-level workspace bound can be
// established on this platform. Project quotas are a Linux filesystem feature;
// on darwin (and Windows) the executor therefore relies on the mandatory
// untrusted default budget plus step-boundary enforcement, and the caller
// fails untrusted jobs closed unless the operator escape hatch is set.
func setupWorkspaceDiskQuota(workspace string, limit int64) (DiskQuotaStatus, func() error) {
	status, cleanup, _ := setupWorkspaceDiskQuotaWithHook(workspace, limit, nil)
	return status, cleanup
}

// setupWorkspaceDiskQuotaWithHook accepts the allocation callback for
// interface symmetry; no assignment can exist on platforms without project
// quotas, so the hook is never invoked.
func setupWorkspaceDiskQuotaWithHook(workspace string, limit int64, onAllocated func(WorkspaceQuotaAssignment) error) (DiskQuotaStatus, func() error, error) {
	return DiskQuotaStatus{Detail: fmt.Sprintf("OS-level project quotas are only implemented on Linux (this host is %s); the workspace bound is step-boundary only", runtime.GOOS)}, nil, nil
}

// validateQuotaAssignment refuses ledger-recorded quota cleanups off Linux:
// project quotas are never created there, so no valid assignment exists.
func validateQuotaAssignment(WorkspaceQuotaAssignment) error {
	return fmt.Errorf("XFS project quotas are not supported on this platform")
}
