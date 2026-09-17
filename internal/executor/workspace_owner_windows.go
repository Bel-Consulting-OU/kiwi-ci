//go:build windows

package executor

// provisionWorkspaceTree is a no-op on Windows: Docker Desktop bind mounts do
// not map host uids into Linux containers, so there is no host-side ownership
// to provision. The job container keeps the same hardened flags as before;
// only the workspace chown/restore path is Unix-specific.
func provisionWorkspaceTree(string, int, int) (func() error, error) {
	return func() error { return nil }, nil
}
