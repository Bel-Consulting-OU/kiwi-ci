//go:build windows

package safefs

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// openRootHandle opens the destination directory without following a
// symlink: the destination must already exist, be a real directory and not
// a reparse point.
func openRootHandle(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil, ErrSymlinkParent
	}
	return os.Open(path)
}

// openBeneathHandle implements OpenRootBeneath on Windows: it verifies (and
// creates) every component of rel beneath the held root with Lstat, rejecting
// reparse points, then opens the final directory with the no-follow root
// opener.
func openBeneathHandle(ws *Root, rel string) (*os.File, error) {
	target := ws.Canonical
	if rel != "" {
		if err := ensureParentDirs(ws, rel+"/."); err != nil {
			return nil, err
		}
		target = filepath.Join(ws.Canonical, filepath.FromSlash(rel))
	}
	return openRootHandle(target)
}

// ensureParentDirs walks the parent components of name beneath the canonical
// root path one component at a time: existing components are verified with
// Lstat to be real directories (never reparse points), missing components are
// created with a single-component os.Mkdir (never MkdirAll) and immediately
// re-verified with Lstat. Every component is re-verified at open time.
func ensureParentDirs(root *Root, name string) error {
	comp := root.Canonical
	parts := strings.Split(name, "/")
	for _, p := range parts[:len(parts)-1] {
		if p == "" {
			continue
		}
		comp = filepath.Join(comp, p)
		fi, err := os.Lstat(comp)
		if os.IsNotExist(err) {
			if e := os.Mkdir(comp, 0o755); e != nil && !os.IsExist(e) {
				return e
			}
			fi, err = os.Lstat(comp)
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

func mkdirNoFollow(root *Root, name string) error {
	if err := ensureParentDirs(root, name); err != nil {
		return err
	}
	target := filepath.Join(root.Canonical, filepath.FromSlash(name))
	if err := os.Mkdir(target, 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	fi, err := os.Lstat(target)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return ErrSymlinkParent
	}
	return nil
}

func writeFileNoFollow(root *Root, name string, r io.Reader, size int64, limits ExtractLimits) error {
	if err := ensureParentDirs(root, name); err != nil {
		return err
	}
	target := filepath.Join(root.Canonical, filepath.FromSlash(name))
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
