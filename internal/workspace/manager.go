// Package workspace provides isolated per-job workspace snapshots for local
// CI runs. Every job gets its own directory under a run-scoped Root so
// parallel matrix jobs can never observe or clobber each other's files, and
// the source checkout is never used as a job workspace directly.
//
// Snapshot strategy, in preference order:
//
//  1. git worktree: when Source is a git repository with a clean working
//     tree, `git worktree add --detach <target> HEAD` checks out the
//     committed state. This is the fastest strategy for large trees.
//  2. APFS reflink copy (darwin only): `cp -c -R` clones files cheaply via
//     clonefile; if the source and the run root live on different volumes
//     the copy falls back automatically.
//  3. Plain recursive copy: walks the source tree, skipping the `.git`
//     directory and the in-repo `.kiwi/cache` directory.
//
// Cleanup removes worktrees via `git worktree remove --force` plus
// `git worktree prune` and deletes copied workspaces with os.RemoveAll.
package workspace

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Manager snapshots a source directory into isolated per-job workspaces.
type Manager struct {
	// Source is the directory every job workspace is derived from. It is
	// never used as a job workspace itself.
	Source string
	// Root is the base directory that job workspaces are created under.
	Root string

	mu sync.Mutex
}

// NewManager validates the source directory and creates a fresh,
// run-scoped Root under the system temp directory.
func NewManager(source string) (*Manager, error) {
	abs, err := filepath.Abs(source)
	if err != nil {
		return nil, fmt.Errorf("workspace source: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("workspace source: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("workspace source %q is not a directory", abs)
	}
	root, err := os.MkdirTemp("", "kiwi-workspaces-")
	if err != nil {
		return nil, fmt.Errorf("workspace root: %w", err)
	}
	return &Manager{Source: abs, Root: root}, nil
}

// Close removes the run-scoped Root and every workspace created under it.
func (m *Manager) Close() error {
	if m.Root == "" {
		return nil
	}
	return os.RemoveAll(m.Root)
}

// Prepare creates an isolated workspace for one job and returns its path,
// a cleanup function that removes it, and any error. The cleanup function
// is idempotent. Callers should invoke it exactly once, after the job's
// steps, artifacts, and caches have been collected.
func (m *Manager) Prepare(ctx context.Context, jobID string) (string, func(), error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	target := filepath.Join(m.Root, sanitizeJobID(jobID))
	if _, err := os.Lstat(target); err == nil {
		return "", nil, fmt.Errorf("job workspace %q already exists", target)
	}
	strategy, err := m.snapshot(ctx, target)
	if err != nil {
		_ = os.RemoveAll(target)
		return "", nil, fmt.Errorf("prepare workspace for %q: %w", jobID, err)
	}
	switch strategy {
	case "worktree":
		return target, func() { removeWorktree(m.Source, target) }, nil
	default:
		return target, func() { _ = os.RemoveAll(target) }, nil
	}
}

// snapshot materializes the source tree at target and reports which
// strategy produced it.
func (m *Manager) snapshot(ctx context.Context, target string) (string, error) {
	if gitRepo(ctx, m.Source) {
		clean, err := gitStatusClean(ctx, m.Source)
		if err == nil && clean {
			cmd := exec.CommandContext(ctx, "git", "-C", m.Source, "worktree", "add", "--detach", target, "HEAD")
			if err := cmd.Run(); err == nil {
				return "worktree", nil
			} else if ctx.Err() != nil {
				return "", ctx.Err()
			}
			_ = os.RemoveAll(target)
		}
	}
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("cp"); err == nil {
			cmd := exec.CommandContext(ctx, "cp", "-c", "-R", m.Source, target)
			if err := cmd.Run(); err == nil {
				// Reflinked clone: strip metadata directories the copy
				// strategies deliberately exclude.
				_ = os.RemoveAll(filepath.Join(target, ".git"))
				_ = os.RemoveAll(filepath.Join(target, ".kiwi", "cache"))
				return "reflink", nil
			} else if ctx.Err() != nil {
				_ = os.RemoveAll(target)
				return "", ctx.Err()
			}
			_ = os.RemoveAll(target)
		}
	}
	if err := copyTree(m.Source, target); err != nil {
		return "", err
	}
	return "copy", nil
}

// gitRepo reports whether dir is inside a git working tree.
func gitRepo(ctx context.Context, dir string) bool {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

// gitStatusClean reports whether the git working tree has no uncommitted
// changes. Only clean trees are eligible for the worktree snapshot strategy
// so that a dirty local checkout (the common `kiwi run` case) snapshots the
// developer's current files, including uncommitted edits.
func gitStatusClean(ctx context.Context, dir string) (bool, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "status", "--porcelain")
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			return false, nil
		}
	}
	return true, nil
}

// removeWorktree drops a previously added worktree registration and prunes
// stale metadata.
func removeWorktree(source, target string) {
	cmd := exec.Command("git", "-C", source, "worktree", "remove", "--force", target)
	_ = cmd.Run()
	prune := exec.Command("git", "-C", source, "worktree", "prune")
	_ = prune.Run()
}

// copyTree recursively copies src into dst (created if missing), skipping
// the .git directory and the in-repo .kiwi/cache directory. Symlinks are
// preserved as symlinks.
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		cacheRel := filepath.Join(".kiwi", "cache")
		if rel == cacheRel || strings.HasPrefix(rel, cacheRel+string(filepath.Separator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			return os.Symlink(link, target)
		case info.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		default:
			return copyFile(path, target, info.Mode().Perm())
		}
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// sanitizeJobID returns a filesystem-safe single path component for a job
// ID. Characters outside [A-Za-z0-9_-] are replaced with "-" (runs are
// collapsed) and the result is trimmed of leading and trailing "-", so the
// output can never contain "..", path separators, or be empty.
func sanitizeJobID(id string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range id {
		ok := r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	out := strings.Trim(b.String(), "-")
	if out == "" || out == "." || out == ".." {
		out = "job"
	}
	return out
}
