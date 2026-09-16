//go:build !linux && !windows

package safefs

// openRelPlatform is the non-Linux unix stub: no kernel-side fast path is
// available, so the caller always uses the component-wise openat walk.
func openRelPlatform(rootFd int, rel string) (int, bool, error) {
	return 0, false, nil
}
