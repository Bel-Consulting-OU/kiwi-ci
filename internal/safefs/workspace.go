package safefs

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
)

// ErrNotRegular reports that a workspace-relative path did not resolve to a
// regular file.
var ErrNotRegular = errors.New("safefs: not a regular file")

// WorkspaceRoot is an opened, canonicalized workspace root for host-side
// reads of attacker-controlled workspace content. Every read of workspace
// data (artifact capture, cache save, snapshot creation, hashFiles) must go
// through OpenRel: the returned descriptor is opened relative to the held
// root handle with a no-follow discipline, so replacing a validated file
// with a symlink after validation can never redirect the read to content
// outside the workspace — the open either yields the original file or
// fails.
type WorkspaceRoot struct {
	*Root
}

// OpenWorkspaceRoot opens an existing directory as a workspace read root.
// Like OpenRootNoFollow, the directory must already exist and must not be
// a symlink; its canonical path (all symlink components resolved) is
// recorded once at open time.
func OpenWorkspaceRoot(path string) (*WorkspaceRoot, error) {
	f, err := openRootHandle(path)
	if err != nil {
		return nil, err
	}
	canonical, err := evalSymlinks(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &WorkspaceRoot{Root: &Root{F: f, Canonical: canonical}}, nil
}

// OpenRel opens the workspace-relative file rel for reading and returns a
// verified regular-file descriptor. The path must be relative, must not
// traverse above the workspace, and no component may be a symlink: on
// Linux the open uses openat2 with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS
// when the kernel supports it, falling back to a component-wise
// openat/O_NOFOLLOW walk from the held root descriptor; on other unix
// systems the component-wise walk is used directly; on Windows every
// component is Lstat-verified (reparse points rejected) before the open.
// The caller owns the returned file.
func (w *WorkspaceRoot) OpenRel(rel string) (*os.File, error) {
	return w.openRel(rel)
}

// validateRel normalizes a workspace-relative path for OpenRel: it must be
// non-empty, not absolute, and contain no ".." component or backslash.
func validateRel(rel string) (string, error) {
	if strings.ContainsRune(rel, '\x00') {
		return "", fmt.Errorf("safefs: NUL byte in relative path")
	}
	if strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return "", fmt.Errorf("safefs: absolute path %q", rel)
	}
	clean := path.Clean(rel)
	if clean == "." || clean == "" {
		return "", fmt.Errorf("safefs: empty relative path")
	}
	for _, comp := range strings.Split(clean, "/") {
		if comp == ".." {
			return "", fmt.Errorf("safefs: parent traversal in %q", rel)
		}
	}
	return clean, nil
}
