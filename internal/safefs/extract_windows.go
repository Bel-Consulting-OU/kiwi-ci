//go:build windows

package safefs

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

func openRoot(dest string) (*os.File, error) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dest)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil, ErrSymlinkParent
	}
	return os.Open(dest)
}

// rejectSymlinkComponents walks every existing component of path and fails if
// any of them is a symlink/reparse point.
func rejectSymlinkComponents(root, name string) error {
	comp := root
	for _, p := range strings.Split(name, "/") {
		comp = filepath.Join(comp, p)
		fi, err := os.Lstat(comp)
		if os.IsNotExist(err) {
			return nil // remaining components do not exist yet
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return ErrSymlinkParent
		}
	}
	return nil
}

func mkdirNoFollow(root *os.File, name string) error {
	rootName := root.Name()
	target := filepath.Join(rootName, filepath.FromSlash(name))
	if err := rejectSymlinkComponents(rootName, name); err != nil {
		return err
	}
	return os.MkdirAll(target, 0o755)
}

func writeFileNoFollow(root *os.File, name string, r io.Reader, size int64, limits ExtractLimits) error {
	rootName := root.Name()
	target := filepath.Join(rootName, filepath.FromSlash(name))
	if err := rejectSymlinkComponents(rootName, name); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return ErrSymlinkParent
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return ErrSymlinkParent
	}
	if _, err := io.CopyN(f, r, size); err != nil {
		return err
	}
	return nil
}

func foldPath(name string) string {
	return strings.ToLower(name)
}
