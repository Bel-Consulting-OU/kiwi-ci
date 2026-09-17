//go:build windows

package safefs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// openRel implements WorkspaceRoot.OpenRel on Windows. Windows has no
// O_NOFOLLOW and no openat, so every component of the path is Lstat-verified
// (a reparse point/symlink anywhere in the chain is rejected) immediately
// before the final open, which is then re-verified to be a regular file.
// This is best-effort against concurrent swaps; the workspace cleanup model
// bounds the residual window.
func (w *WorkspaceRoot) openRel(rel string) (*os.File, error) {
	rel, err := validateRel(rel)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(rel, "/")
	cur := w.Canonical
	for _, p := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if err != nil {
			return nil, err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, ErrSymlinkParent
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("%w: %q", ErrNotRegular, p)
		}
	}
	target := filepath.Join(w.Canonical, filepath.FromSlash(rel))
	fi, err := os.Lstat(target)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, ErrSymlinkParent
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", ErrNotRegular, rel)
	}
	f, err := os.Open(target)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: %q", ErrNotRegular, rel)
	}
	return f, nil
}
