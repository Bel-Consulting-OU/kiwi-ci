//go:build windows

package executor

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// readFileNoFollow opens path for reading and refuses symlinks. Windows has
// no O_NOFOLLOW, so the final component is checked with Lstat before the open
// (best-effort; a concurrent swap between check and open is mitigated by the
// workspace cleanup model).
//
// Because only the final component is protected, callers reading a path that
// may traverse workspace directories must use readFileWithinRoot instead: an
// intermediate component swapped for a junction/reparse point would
// otherwise be followed.
func readFileNoFollow(path string, maxBytes int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to follow symlink: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCapped(f, maxBytes)
}

// readFileWithinRoot opens path provided it resolves inside root with the
// safefs Windows discipline: the root is canonicalized once, then every
// component is Lstat-verified against reparse points immediately before the
// open and the opened file must be regular, so neither a final symlink nor an
// intermediate junction can redirect the read outside the workspace. A
// missing file is reported as os.ErrNotExist.
func readFileWithinRoot(root, path string, maxBytes int64) ([]byte, error) {
	ws, err := safefs.OpenWorkspaceRoot(root)
	if err != nil {
		return nil, err
	}
	defer ws.Close()
	rel, ok := relWithinRoot(ws, root, path)
	if !ok {
		if _, serr := os.Stat(path); os.IsNotExist(serr) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("read path %q is outside the workspace", path)
	}
	f, err := ws.OpenRel(filepath.ToSlash(rel))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCapped(f, maxBytes)
}
