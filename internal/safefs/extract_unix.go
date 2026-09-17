//go:build !windows

package safefs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// openRootHandle opens the destination directory with O_NOFOLLOW so a
// symlinked destination is rejected outright. The directory must already
// exist: no component is ever created here. With O_DIRECTORY a symlinked
// destination surfaces as ENOTDIR on some platforms, not ELOOP.
func openRootHandle(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, ErrSymlinkParent
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// dupRootFD is a test-only seam over unix.Dup. Production behavior is
// unchanged; it lets the descriptor-duplication failure be exercised.
var dupRootFD = unix.Dup

// openParentChain walks the parent components of name beneath the held root
// descriptor one component at a time: each existing component is opened with
// O_NOFOLLOW|O_DIRECTORY, and each missing component is created with a
// single-component mkdirat followed by an immediate O_NOFOLLOW re-open.
// Every open is relative to a held descriptor (openat), never to a path, so
// renames or symlink swaps above or inside the root cannot redirect the
// write. The caller owns the returned descriptor of the deepest parent.
func openParentChain(root *Root, name string) (int, error) {
	fd, err := dupRootFD(int(root.F.Fd()))
	if err != nil {
		return -1, err
	}
	parts := strings.Split(name, "/")
	for _, p := range parts[:len(parts)-1] {
		if p == "" {
			continue
		}
		child, err := openatFn(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == nil {
			unix.Close(fd)
			fd = child
			continue
		}
		if err != unix.ENOENT {
			unix.Close(fd)
			if errors.Is(err, unix.ELOOP) {
				return -1, ErrSymlinkParent
			}
			return -1, err
		}
		if e := unix.Mkdirat(fd, p, 0o755); e != nil && !errors.Is(e, unix.EEXIST) {
			unix.Close(fd)
			return -1, e
		}
		child, err = openatFn(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			if errors.Is(err, unix.ELOOP) {
				return -1, ErrSymlinkParent
			}
			return -1, err
		}
		fd = child
	}
	return fd, nil
}

// openatFn is a test-only seam over unix.Openat. Production behavior is
// unchanged; it lets the re-open failure branches after a missing-component
// mkdirat (a TOCTOU with a concurrently appearing component) be exercised
// deterministically.
var openatFn = unix.Openat

// mkdirNoFollow creates the directory entry name (and parents) under the
// root handle, requiring every component to be a real directory.
func mkdirNoFollow(root *Root, name string) error {
	parentFd, err := openParentChain(root, name)
	if err != nil {
		return err
	}
	defer unix.Close(parentFd)
	parts := strings.Split(name, "/")
	base := parts[len(parts)-1]
	if err := unix.Mkdirat(parentFd, base, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	fd, err := openatFn(parentFd, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return ErrSymlinkParent
		}
		return err
	}
	return unix.Close(fd)
}

func writeFileNoFollow(root *Root, name string, r io.Reader, size int64, limits ExtractLimits) error {
	parentFd, err := openParentChain(root, name)
	if err != nil {
		return err
	}
	defer unix.Close(parentFd)
	parts := strings.Split(name, "/")
	base := parts[len(parts)-1]
	fd, err := unix.Openat(parentFd, base, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EEXIST) || errors.Is(err, syscall.EPERM) {
			return ErrSymlinkParent
		}
		return err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(root.Canonical, filepath.FromSlash(name)))
	defer f.Close()
	if _, err := io.CopyN(f, r, size); err != nil {
		return err
	}
	return nil
}
