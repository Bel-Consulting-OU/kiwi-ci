//go:build linux

package safefs

import (
	"golang.org/x/sys/unix"
)

// openRelPlatform opens rel beneath rootFd with openat2, which resolves the
// whole path atomically in the kernel: RESOLVE_BENEATH forbids escaping the
// root and RESOLVE_NO_SYMLINKS forbids every symlink component. On kernels
// without openat2 (or without the resolve flags) it reports handled=false so
// the caller falls back to the component-wise openat walk.
func openRelPlatform(rootFd int, rel string) (int, bool, error) {
	fd, err := unix.Openat2(rootFd, rel, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	})
	if err == nil {
		return fd, true, nil
	}
	if err == unix.ENOSYS || err == unix.EINVAL {
		return 0, false, nil
	}
	if err == unix.ELOOP || err == unix.EXDEV || err == unix.ENOTDIR {
		return 0, true, ErrSymlinkParent
	}
	return 0, true, err
}
