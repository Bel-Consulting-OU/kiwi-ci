//go:build !windows

package executor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// errWorkspaceNotOwned refuses provisioning of a workspace tree that does not
// belong to the runner: chowning another user's tree would corrupt unrelated
// ownership (and would silently mix inodes the runner never created).
var errWorkspaceNotOwned = errors.New("workspace tree is not owned by the runner")

// runnerWorkspaceOwner returns the uid/gid the workspace tree belongs to: the
// runner process identity. A seam for tests that must simulate a tree owned by
// another user without running as root.
var runnerWorkspaceOwner = func() (int, int) { return os.Getuid(), os.Getgid() }

// lchownWorkspaceEntry changes the ownership of one tree entry without
// following symlinks. Fault-injection seam for tests.
var lchownWorkspaceEntry = os.Lchown

// lstatOwner returns the uid/gid owning path's inode; symlinks are not
// followed, so a link cannot redirect provisioning outside the tree.
func lstatOwner(path string) (int, int, error) {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return -1, -1, err
	}
	return int(st.Uid), int(st.Gid), nil
}

// provisionWorkspaceTree chowns the runner-owned checkout to the container
// workload and makes the workspace root traverse-only (0711). It validates the
// whole tree BEFORE mutating anything, so a tree the runner does not own is
// refused instead of partially rewritten. The returned restore function
// chowns every entry back to the runner uid/gid and reinstates the original
// root mode, which is what lets the runner read job results (artifacts,
// snapshots, test reports) again after the container is gone.
func provisionWorkspaceTree(workspace string, uid, gid int) (func() error, error) {
	// Resolve a symlinked workspace root first: an unresolved link would make
	// WalkDir treat the root itself as a leaf and silently skip the tree.
	root, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("stat workspace: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("workspace %s is not a directory", root)
	}
	runnerUID, runnerGID := runnerWorkspaceOwner()
	if err := validateWorkspaceOwnership(root, runnerUID, uid); err != nil {
		return nil, err
	}
	originalMode := info.Mode().Perm()
	if err := os.Chmod(root, workspaceTraverseMode); err != nil {
		return nil, fmt.Errorf("make workspace root traverse-only: %w", err)
	}
	if err := chownWorkspaceTree(root, uid, gid); err != nil {
		// Best effort: put the tree back under the runner so a failed
		// provision never leaves the checkout inaccessible to its owner.
		_ = chownWorkspaceTree(root, runnerUID, runnerGID)
		_ = os.Chmod(root, originalMode)
		return nil, fmt.Errorf("chown workspace to %d:%d: %w", uid, gid, err)
	}
	return func() error {
		if err := chownWorkspaceTree(root, runnerUID, runnerGID); err != nil {
			return fmt.Errorf("restore workspace ownership to %d:%d: %w", runnerUID, runnerGID, err)
		}
		if err := os.Chmod(root, originalMode); err != nil {
			return fmt.Errorf("restore workspace mode %#o: %w", originalMode, err)
		}
		return nil
	}, nil
}

// validateWorkspaceOwnership walks the tree and refuses when any entry has an
// owner that is neither the runner nor (for an idempotent re-provision after
// an interrupted restore) the target workload uid.
func validateWorkspaceOwnership(root string, runnerUID, targetUID int) error {
	return filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		ownerUID, _, oerr := lstatOwner(path)
		if oerr != nil {
			return fmt.Errorf("ownership of %s: %w", path, oerr)
		}
		if ownerUID != runnerUID && ownerUID != targetUID {
			return fmt.Errorf("%w: %s is owned by uid %d (runner uid %d)", errWorkspaceNotOwned, path, ownerUID, runnerUID)
		}
		return nil
	})
}

// chownWorkspaceTree lchowns every entry of the tree, including the root.
func chownWorkspaceTree(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := lchownWorkspaceEntry(path, uid, gid); cerr != nil {
			return fmt.Errorf("%s: %w", path, cerr)
		}
		return nil
	})
}
