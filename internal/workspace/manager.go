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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executil"
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
// It takes Manager.mu so it can never race a concurrent Prepare: without the
// lock, RemoveAll could delete the Root while snapshot() is materializing a
// workspace under it, leaving a half-created tree behind a "prepared" path.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
// snapshotCopyTree is copyTree unless a fallback test substitutes a
// failing copy to exercise the reflink/cancel paths.
var snapshotCopyTree = copyTree

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
	// Prefer copyTree (skips build-output dirs). APFS reflink clones the
	// ENTIRE tree including multi-GB target/ before any strip — on a dirty
	// Rust checkout that materializes tens of gigabytes and looks hung.
	// snapshotCopyTree is a test seam so fallback tests can force the
	// reflink path without disabling copyTree in production.
	if err := snapshotCopyTree(m.Source, target); err == nil {
		return "copy", nil
	}
	_ = os.RemoveAll(target)
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("cp"); err == nil {
			cmd := exec.CommandContext(ctx, "cp", "-c", "-R", m.Source, target)
			if err := cmd.Run(); err == nil {
				_ = os.RemoveAll(filepath.Join(target, ".git"))
				_ = os.RemoveAll(filepath.Join(target, ".kiwi", "cache"))
				stripBuildOutputDirs(target, m.Source)
				return "reflink", nil
			} else if ctx.Err() != nil {
				_ = os.RemoveAll(target)
				return "", ctx.Err()
			}
			_ = os.RemoveAll(target)
		}
	}
	return "", fmt.Errorf("workspace snapshot failed for %s", m.Source)
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
	out, truncated, err := executil.CaptureBounded(cmd, 1<<20)
	if err != nil {
		return false, err
	}
	if truncated {
		// Far more changes than the capture limit: definitely not clean.
		return false, nil
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

// copyTreeSkipDirs are build-output directory names never copied into a job
// workspace. A dirty checkout of a Rust repo can carry a multi-gigabyte
// target/ tree; copying it made workspace materialization look hung and
// filled the disk. Jobs rebuild from source.
var copyTreeSkipDirs = map[string]bool{
	"target":        true, // cargo/rustc
	"dist":          true, // release output (tracked assets are kept)
	"node_modules":  true,
	"__pycache__":   true,
	".venv":         true,
	"venv":          true,
	".tox":          true,
	".mypy_cache":   true,
	".pytest_cache": true,
	".ruff_cache":   true,
	".cache":        true,
}


// isGitTracked reports whether exactly this path is in the git index.
func isGitTracked(src, rel string) bool {
	cmd := exec.Command("git", "-C", src, "ls-files", "--error-unmatch", "--", rel)
	return cmd.Run() == nil
}


// isSkipRoot reports whether rel is exactly one of the kept skip roots
// (those must stay so the walk can reach tracked children).
func isSkipRoot(roots []string, rel string) bool {
	for _, root := range roots {
		if rel == root {
			return true
		}
	}
	return false
}

// inPreservedSkip reports whether rel is inside one of the kept skip-name
// directories (whose tracked files must survive the snapshot).
func inPreservedSkip(roots []string, rel string) bool {
	for _, root := range roots {
		if rel == root || strings.HasPrefix(rel, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// hasTrackedFiles reports whether any path under rel is tracked by git in
// src. Used so a source directory named target/ (or node_modules/, ...) is
// not mistaken for build output and stripped from the job workspace.
func hasTrackedFiles(src, rel string) bool {
	cmd := exec.Command("git", "-C", src, "ls-files", "--", rel)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(out)) > 0
}

// copyTree recursively copies src into dst (created if missing), skipping
// build-output directory names, the in-repo .kiwi/cache directory and the
// DESTINATION subtree itself. .git IS copied: audit tools that shell out to
// `git ls-files` (and any pipeline step that inspects the commit) must see a
// real repository inside the job workspace. The destination exclusion
// matters when the workspace root lives under the source (a TMPDIR inside
// the repository): without it the walk descends into the half-copied
// workspace and copies it into itself until the path length explodes.
func copyTree(src, dst string) error {
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	var preserveTrackedUnder []string
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if pathAbs, aerr := filepath.Abs(path); aerr == nil {
			if pathAbs == dstAbs || strings.HasPrefix(pathAbs, dstAbs+string(filepath.Separator)) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if info.IsDir() && copyTreeSkipDirs[info.Name()] {
			// A skip-name directory that carries TRACKED paths is source
			// (tools/redteam/target, dist/ release assets). Keep only the
			// tracked subtree; untracked build output inside it is omitted.
			if hasTrackedFiles(src, rel) {
				preserveTrackedUnder = append(preserveTrackedUnder, rel)
			} else {
				return filepath.SkipDir
			}
		}
		// Inside a kept skip-name directory, copy only git-tracked paths.
		// The root itself always stays so the walk reaches its children.
		// Directories stay if they hold tracked descendants (a bare dir is
		// not in the index; its files are).
		if inPreservedSkip(preserveTrackedUnder, rel) && !isSkipRoot(preserveTrackedUnder, rel) {
			if info.IsDir() {
				if !hasTrackedFiles(src, rel) {
					return filepath.SkipDir
				}
			} else if !isGitTracked(src, rel) {
				return nil
			}
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
			if err := mkdirParents(filepath.Dir(target), info.Mode().Perm()); err != nil {
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

// stripBuildOutputDirs removes build-output directory names from a
// materialized workspace (reflink clones copy them before this runs).
// source is the original checkout: a skip-name directory that carries
// tracked paths there is kept (tools/redteam/target is source, not cargo
// output).
func stripBuildOutputDirs(root, source string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}
		if copyTreeSkipDirs[info.Name()] {
			rel, rerr := filepath.Rel(root, path)
			if rerr == nil && hasTrackedFiles(source, rel) {
				return nil
			}
			_ = os.RemoveAll(path)
			return filepath.SkipDir
		}
		return nil
	})
}

// mkdirParents creates missing parent directories using the source entry's
// permission bits instead of forcing 0755. Forcing a mode is a silent
// normalization: tracked files that are 0644/0664/0755 stay as they are in
// the checkout, and the deletion guard no longer sees phantom mode diffs.
func mkdirParents(dir string, mode os.FileMode) error {
	if dir == "" || dir == "." {
		return nil
	}
	perm := mode.Perm()
	if perm == 0 {
		perm = 0o755
	}
	// Build the path from the root so every missing component gets the same
	// source-derived mode; existing directories are left untouched.
	parts := strings.Split(dir, string(filepath.Separator))
	cur := ""
	if filepath.IsAbs(dir) {
		cur = string(filepath.Separator)
	}
	for _, part := range parts {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		if err := os.MkdirAll(cur, perm); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := mkdirParents(filepath.Dir(dst), 0o755); err != nil {
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
//
// The mapping is INJECTIVE: when the sanitized form differs from the input
// (i.e. the ID was lossy), a short SHA-256 suffix of the original ID is
// appended. Without it, distinct IDs such as "a/b" and "a.b" both collapsed
// to "a-b" and shared one workspace path (Prepare would then refuse the
// second job as "already exists", or worse, a stale workspace could be
// reused). The suffix is derived from the raw ID, so the mapping is stable
// across processes and a replayed job always lands on the same directory.
func sanitizeJobID(id string) string {
	out := sanitizeJobIDBare(id)
	if out == id {
		return out
	}
	sum := sha256.Sum256([]byte(id))
	return out + "-" + hex.EncodeToString(sum[:4])
}

// sanitizeJobIDBare is the lossy, human-readable sanitizer used for the
// injective wrapper above and by callers that only need a safe component.
func sanitizeJobIDBare(id string) string {
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
