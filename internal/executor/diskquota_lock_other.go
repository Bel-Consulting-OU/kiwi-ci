//go:build !unix

package executor

// lockXFSAllocation is a no-op on platforms without XFS project quotas: the
// capability itself is unsupported there, so there is nothing to serialize.
func lockXFSAllocation(string) (func(), error) {
	return func() {}, nil
}
