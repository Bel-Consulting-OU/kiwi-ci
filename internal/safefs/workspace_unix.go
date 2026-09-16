//go:build !windows

package safefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openRel implements WorkspaceRoot.OpenRel on unix. It prefers the
// openat2-based platform fast path (RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS on
// Linux) and falls back to a component-wise openat walk with O_NOFOLLOW
// from the held root descriptor. The returned descriptor is verified to be
// a regular file.
func (w *WorkspaceRoot) openRel(rel string) (*os.File, error) {
	rel, err := validateRel(rel)
	if err != nil {
		return nil, err
	}
	rootFd := int(w.F.Fd())
	if fd, handled, err := openRelPlatform(rootFd, rel); handled {
		if err != nil {
			return nil, err
		}
		return w.verifiedFile(fd, rel)
	} else if err != nil {
		return nil, err
	}
	fd, err := openRelWalk(rootFd, rel)
	if err != nil {
		return nil, err
	}
	return w.verifiedFile(fd, rel)
}

// openRelWalk opens rel beneath the held root descriptor one component at a
// time. Every intermediate component is opened with O_NOFOLLOW|O_DIRECTORY
// and the final component with O_NOFOLLOW, so no symlink anywhere in the
// chain can redirect the open. The caller owns the returned descriptor.
func openRelWalk(rootFd int, rel string) (int, error) {
	fd := rootFd
	opened := false
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		child, err := unix.Openat(fd, p, flags, 0)
		if opened {
			unix.Close(fd)
		}
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return -1, ErrSymlinkParent
			}
			return -1, err
		}
		fd = child
		opened = true
	}
	return fd, nil
}

// verifiedFile fstats the descriptor and rejects anything that is not a
// regular file before handing it back as an *os.File.
func (w *WorkspaceRoot) verifiedFile(fd int, rel string) (*os.File, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, fmt.Errorf("%w: %q", ErrNotRegular, rel)
	}
	return os.NewFile(uintptr(fd), filepath.Join(w.Canonical, filepath.FromSlash(rel))), nil
}
