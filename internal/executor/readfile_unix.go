//go:build !windows

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// readFileNoFollow opens path for reading and refuses to follow a symlink in
// the final path component (O_NOFOLLOW turns that into ELOOP). This prevents
// an attacker-controlled workspace from redirecting step-output reads to
// arbitrary host files.
//
// Because only the final component is protected, callers reading a path that
// may traverse workspace directories must use readFileWithinRoot instead: an
// intermediate component swapped for a symlink would otherwise be followed.
func readFileNoFollow(path string, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCapped(f, maxBytes)
}

// readFileWithinRoot opens path provided it resolves inside root. The root
// is canonicalized once, so platform symlinks such as /var -> /private/var
// are accounted for; every component below the root is then opened
// O_NOFOLLOW relative to the root descriptor and must be a regular file, so
// a symlink anywhere below the workspace cannot redirect the read to host
// content — not just a symlink in the final component. A missing file (or
// missing parent directory) is reported as os.ErrNotExist.
func readFileWithinRoot(root, path string, maxBytes int64) ([]byte, error) {
	ws, err := safefs.OpenWorkspaceRoot(root)
	if err != nil {
		return nil, err
	}
	defer ws.Close()
	rel, err := filepath.Rel(ws.Canonical, path)
	if err != nil || escapesRoot(rel) {
		// The caller may spell the path through platform-level symlinks
		// (tmpdirs on macOS are /var/... while the canonical root is
		// /private/var/...). Canonicalize the parent only to reconcile the
		// spelling; the read itself is still anchored to the root handle.
		parent, base := filepath.Split(path)
		realParent, perr := filepath.EvalSymlinks(filepath.Clean(parent))
		if perr != nil {
			if os.IsNotExist(perr) {
				return nil, os.ErrNotExist
			}
			return nil, perr
		}
		rel, err = filepath.Rel(ws.Canonical, filepath.Join(realParent, base))
		if err != nil || escapesRoot(rel) {
			return nil, fmt.Errorf("read path %q is outside the workspace", path)
		}
	}
	f, err := ws.OpenRel(filepath.ToSlash(rel))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCapped(f, maxBytes)
}

func escapesRoot(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
