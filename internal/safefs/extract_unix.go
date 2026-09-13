//go:build !windows

package safefs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openRoot opens the destination directory with O_NOFOLLOW so a symlinked
// destination is rejected outright.
func openRoot(dest string) (*os.File, error) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(dest, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrSymlinkParent
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), dest), nil
}

// ensureParentDirs creates each missing component of name under root and
// verifies every existing component is a real directory (never a symlink)
// using O_NOFOLLOW at every step.
func ensureParentDirs(root *os.File, name string) (string, error) {
	rootName := root.Name()
	comp := rootName
	parts := strings.Split(name, "/")
	for _, p := range parts[:len(parts)-1] {
		if p == "" {
			continue
		}
		comp = filepath.Join(comp, p)
		fd, err := syscall.Open(comp, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err == nil {
			syscall.Close(fd)
			continue
		}
		if err != syscall.ENOENT {
			if errors.Is(err, syscall.ELOOP) {
				return "", ErrSymlinkParent
			}
			return "", err
		}
		if e := os.Mkdir(comp, 0o755); e != nil && !errors.Is(e, syscall.EEXIST) && !os.IsExist(e) {
			return "", e
		}
		fd, err = syscall.Open(comp, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				return "", ErrSymlinkParent
			}
			return "", err
		}
		syscall.Close(fd)
	}
	return filepath.Join(rootName, filepath.FromSlash(name)), nil
}

// mkdirNoFollow creates the directory entry name (and parents) under root,
// requiring every component to be a real directory.
func mkdirNoFollow(root *os.File, name string) error {
	target, err := ensureParentDirs(root, name)
	if err != nil {
		return err
	}
	if err := os.Mkdir(target, 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	fd, err := syscall.Open(target, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return ErrSymlinkParent
		}
		return err
	}
	return syscall.Close(fd)
}

func writeFileNoFollow(root *os.File, name string, r io.Reader, size int64, limits ExtractLimits) error {
	target, err := ensureParentDirs(root, name)
	if err != nil {
		return err
	}
	fd, err := syscall.Open(target, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o644)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EEXIST) || errors.Is(err, syscall.EPERM) {
			return ErrSymlinkParent
		}
		return err
	}
	f := os.NewFile(uintptr(fd), target)
	defer f.Close()
	if _, err := io.CopyN(f, r, size); err != nil {
		return err
	}
	return nil
}

func foldPath(name string) string {
	if caseInsensitiveFS {
		return strings.ToLower(name)
	}
	return name
}
