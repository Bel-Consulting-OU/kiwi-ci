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
	return DiskQuotaStatus{Detail: fmt.Sprintf("OS-level project quotas are only implemented on Linux (this host is %s); the workspace bound is step-boundary only", runtime.GOOS)}, nil
}
