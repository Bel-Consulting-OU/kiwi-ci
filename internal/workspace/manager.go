// Package workspace provides isolated per-job workspace snapshots for local
// CI runs. Every job gets its own directory under a run-scoped Root so
// parallel matrix jobs can never observe or clobber each other's files, and
// the source checkout is never used as a job workspace directly.
//
// Snapshot strategy, in preference order:
//
//  1. Plain recursive copy (copyTree): walks the source tree and copies
//     everything the developer can see — tracked, untracked and ignored
//     files alike (except build-output directory names and the in-repo
//     `.kiwi/cache`). This is the ONLY strategy used by default: a local
//     `kiwi run` must see the working directory as it is on disk, including
//     `.env` and untracked files. A git-worktree of HEAD silently drops
//     ignored/untracked content and flipped between that and a full copy
//     whenever `git status` raced, which staged wildly different workspaces
//     for identical probes (K15).
//  2. APFS reflink copy (darwin only): `cp -c -R` fallback when copyTree
//     cannot run.
//
// Set KIWI_WORKSPACE_STRATEGY=worktree to opt into the clean-tree
// `git worktree add --detach <target> HEAD` snapshot (committed state only).
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
	// base is the immutable run-base snapshot (Root/run-base) once Freeze
	// has run. Job workspaces are copied from base, not from the live
	// source tree, so every job in one run sees the same source state.
	base string
	// baseEntries is the source top-level listing captured at Freeze time.
	baseEntries []os.DirEntry
}

// NewManager validates the source directory and creates a fresh,
// run-scoped Root under the system temp directory.
func NewManager(source string) (*Manager, error) {
	abs, err := filepath.Abs(source)
	if err != nil {
		return nil, fmt.Errorf("workspace source: %w", err)
	}
	// Resolve symlinks (macOS /tmp → /private/tmp, user symlinks, …).
	// filepath.Walk does NOT follow a symlinked root: it visits only the
	// symlink itself, copies nothing, and returns nil — which staged an
	// empty workspace and only failed at verify (K15).
	if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil {
		abs = resolved
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("workspace source: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("workspace source %q is not a directory", abs)
	}
	root, err := newWorkspaceRoot()
	if err != nil {
		return nil, fmt.Errorf("workspace root: %w", err)
	}
	return &Manager{Source: abs, Root: root}, nil
}

// newWorkspaceRoot picks a Docker-shareable location for job workspaces.
// The system temp dir (TMPDIR, often /var/folders/...) is NOT shared by
// Docker Desktop on macOS, so a container job's bind mount is empty. Prefer
// a directory under the user's home, which is shared by default.
func newWorkspaceRoot() (string, error) {
	// Only use HOME when it already exists: creating a tree under a
	// missing HOME would invent a home directory the user never had.
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if _, serr := os.Stat(home); serr == nil {
			base := filepath.Join(home, ".kiwi", "workspaces")
			if err := os.MkdirAll(base, 0o755); err == nil {
				return os.MkdirTemp(base, "run-")
			}
		}
	}
	return os.MkdirTemp("", "kiwi-workspaces-")
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

// Freeze captures ONE immutable run-base snapshot of Source under
// Root/run-base. Subsequent Prepare calls copy from that base, so a single
// `kiwi run` always stages the same source state for every job even if an
// editor or build tool mutates the working tree mid-run. Freeze is
// idempotent; the first call wins.
func (m *Manager) Freeze(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.freezeLocked(ctx)
}

func (m *Manager) freezeLocked(ctx context.Context) error {
	if m.base != "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(m.Source)
	if err != nil {
		return fmt.Errorf("run base: read source: %w", err)
	}
	// When Root lives inside Source (HOME=project, TMPDIR fallback, …),
	// creating run-base under Root mutates the source mid-freeze. Skip the
	// manager's own Root in every manifest so that is not a false change.
	skip := m.Root
	before, err := freezeManifest(m.Source, skip)
	if err != nil {
		return fmt.Errorf("run base: source manifest: %w", err)
	}
	base := filepath.Join(m.Root, "run-base")
	// Freeze ALWAYS uses a plain working-tree copy (never the opt-in
	// worktree strategy): run-base must match the developer's source
	// listing including ignored/untracked files, and a worktree of HEAD
	// would silently drop them before any job runs.
	strategy, err := m.snapshotFrom(ctx, m.Source, base, true)
	if err != nil {
		_ = os.RemoveAll(base)
		return fmt.Errorf("run base snapshot: %w", err)
	}
	after, err := freezeManifest(m.Source, skip)
	if err != nil {
		_ = os.RemoveAll(base)
		return fmt.Errorf("run base: source re-manifest: %w", err)
	}
	if before != after {
		// One retry: a transient editor write during the copy. After that,
		// refuse a hybrid snapshot rather than invent a tree that never
		// existed.
		_ = os.RemoveAll(base)
		base = filepath.Join(m.Root, "run-base")
		before2, err := freezeManifest(m.Source, skip)
		if err != nil {
			return fmt.Errorf("run base: source manifest: %w", err)
		}
		strategy, err = m.snapshotFrom(ctx, m.Source, base, true)
		if err != nil {
			_ = os.RemoveAll(base)
			return fmt.Errorf("run base snapshot: %w", err)
		}
		after2, err := freezeManifest(m.Source, skip)
		if err != nil {
			_ = os.RemoveAll(base)
			return fmt.Errorf("run base: source re-manifest: %w", err)
		}
		if before2 != after2 {
			_ = os.RemoveAll(base)
			return fmt.Errorf("run base: source tree changed during freeze (retry also unstable); re-run when the working tree is quiet")
		}
	}
	if err := verifyStagedTree(m.Source, entries, base, strategy); err != nil {
		_ = os.RemoveAll(base)
		return fmt.Errorf("run base verify: %w", err)
	}
	m.base = base
	m.baseEntries = entries
	return nil
}

// freezeManifest is a deterministic digest of path/type/size/mtime for
// every entry under root (symlinks record their target). skip, when
// non-empty and under root, is omitted (the manager's own Root under a
// HOME-as-source layout). Used to detect concurrent mutation while the
// run-base is being copied.
func freezeManifest(root, skip string) (string, error) {
	skip = filepath.Clean(skip)
	h := sha256.New()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if skip != "" && skip != "." {
			if path == skip || strings.HasPrefix(path, skip+string(filepath.Separator)) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		kind := "f"
		if info.IsDir() {
			kind = "d"
		} else if info.Mode()&os.ModeSymlink != 0 {
			kind = "l"
			target, lerr := os.Readlink(path)
			if lerr != nil {
				return lerr
			}
			fmt.Fprintf(h, "%s\x00%s\x00%s\n", rel, kind, target)
			return nil
		}
		fmt.Fprintf(h, "%s\x00%s\x00%d\x00%d\x00%016x\n", rel, kind, info.Size(), info.Mode().Perm(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// BasePath returns the immutable run-base directory, or "" if Freeze has
// not run. Useful for local execution metadata and replay.
func (m *Manager) BasePath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.base
}

// Prepare creates an isolated workspace for one job and returns its path,
// a cleanup function that removes it, and any error. The cleanup function
// is idempotent. Callers should invoke it exactly once, after the job's
// steps, artifacts, and caches have been collected.
//
// When Freeze has run, the job is staged from the immutable run-base so
// every job in one run shares one source state. Otherwise the live source
// is snapshotted (legacy / unfrozen callers).
//
// Staging is deterministic (K15): a snapshot that lost top-level
// directories fails closed instead of handing the job a truncated tree.
func (m *Manager) Prepare(ctx context.Context, jobID string) (string, func(), error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if m.base == "" {
		if err := m.freezeLocked(ctx); err != nil {
			return "", nil, err
		}
	}
	target := filepath.Join(m.Root, sanitizeJobID(jobID))
	if _, err := os.Lstat(target); err == nil {
		return "", nil, fmt.Errorf("job workspace %q already exists", target)
	}
	// Verify against the listing captured at freeze time (immutable base).
	srcEntries := m.baseEntries
	srcPath := m.base
	if srcEntries == nil {
		var err error
		srcEntries, err = os.ReadDir(m.Source)
		if err != nil {
			return "", nil, fmt.Errorf("prepare workspace for %q: read source: %w", jobID, err)
		}
		srcPath = m.Source
	}
	strategy, err := m.snapshotFrom(ctx, srcPath, target, false)
	if err != nil {
		_ = os.RemoveAll(target)
		return "", nil, fmt.Errorf("prepare workspace for %q: %w", jobID, err)
	}
	if err := verifyStagedTree(srcPath, srcEntries, target, strategy); err != nil {
		_ = os.RemoveAll(target)
		return "", nil, fmt.Errorf("prepare workspace for %q: %w", jobID, err)
	}
	switch strategy {
	case "worktree":
		// Worktree was created from the snapshot source (run-base or the
		// live source), not always m.Source — cleanup must match.
		wtSrc := srcPath
		return target, func() { removeWorktree(wtSrc, target) }, nil
	default:
		return target, func() { _ = os.RemoveAll(target) }, nil
	}
}

// verifyStagedTree fails closed when a snapshot lost top-level directories
// from the pre-copied source listing or produced an implausibly small tree.
// srcEntries must be the listing taken BEFORE the copy so concurrent
// source mutations cannot invent phantom missing directories.
func verifyStagedTree(src string, srcEntries []os.DirEntry, target, strategy string) error {
	dstEntries, err := os.ReadDir(target)
	if err != nil {
		return fmt.Errorf("verify staged tree: read target: %w", err)
	}
	have := map[string]bool{}
	dstFiles := 0
	for _, e := range dstEntries {
		have[e.Name()] = true
	}
	_ = filepath.Walk(target, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			dstFiles++
		}
		return nil
	})
	var missing []string
	srcTopDirs := 0
	for _, e := range srcEntries {
		name := e.Name()
		if name == ".git" && strategy == "reflink" {
			// reflink strips .git on purpose
			continue
		}
		if !e.IsDir() {
			continue
		}
		if copyTreeSkipDirs[name] && !hasTrackedFiles(src, name) {
			continue
		}
		if name == ".kiwi" {
			// only .kiwi/cache is excluded; the dir itself should remain
			// if the source has anything besides cache. Keep the check
			// simple: require the dir when the source has other entries.
			if !have[name] {
				// count non-cache children
				kids, _ := os.ReadDir(filepath.Join(src, name))
				for _, k := range kids {
					if k.Name() != "cache" {
						missing = append(missing, name)
						break
					}
				}
			}
			continue
		}
		srcTopDirs++
		if !have[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("staged workspace is truncated: missing top-level dir(s) %v (strategy=%s, staged %d files; source has %d top-level dirs)", missing, strategy, dstFiles, srcTopDirs)
	}
	if srcTopDirs > 0 && dstFiles == 0 {
		return fmt.Errorf("staged workspace is empty but the source has %d top-level dirs (strategy=%s)", srcTopDirs, strategy)
	}
	return nil
}

// snapshot materializes the source tree at target and reports which
// strategy produced it.
// snapshotCopyTree is copyTree unless a fallback test substitutes a
// failing copy to exercise the reflink/cancel paths.
var snapshotCopyTree = copyTree

// workspaceStrategyEnv selects the snapshot strategy. Empty (default) is
// always copyTree — the deterministic working-tree copy. "worktree" opts
// into the clean-tree `git worktree add` snapshot (committed files only).
const workspaceStrategyEnv = "KIWI_WORKSPACE_STRATEGY"

func (m *Manager) snapshotFrom(ctx context.Context, src, target string, forceCopy bool) (string, error) {
	// K15: staging must be deterministic. copyTree is the default; the
	// worktree path is opt-in only and never used for freeze (forceCopy).
	//
	// When Root lives inside src (HOME/TMPDIR under the project), walking
	// src would also stage OTHER job workspaces under Root into this
	// snapshot. Exclude Root from every copy.
	skip := ""
	if r := filepath.Clean(m.Root); r != "" && r != "." {
		if r == filepath.Clean(src) || strings.HasPrefix(r, filepath.Clean(src)+string(filepath.Separator)) {
			skip = r
		}
	}
	if !forceCopy && os.Getenv(workspaceStrategyEnv) == "worktree" && gitRepo(ctx, src) {
		clean, err := gitStatusClean(ctx, src)
		if err == nil && clean {
			cmd := exec.CommandContext(ctx, "git", "-C", src, "worktree", "add", "--detach", target, "HEAD")
			if err := cmd.Run(); err == nil {
				return "worktree", nil
			} else if ctx.Err() != nil {
				return "", ctx.Err()
			}
			_ = os.RemoveAll(target)
		}
	}
	// Prefer copyTree (skips build-output dirs). APFS reflink clones the
	// ENTIRE tree — never use it when we must exclude Root (skip), because
	// `cp -R` cannot honor skip and would nest sibling workspaces.
	if forceCopy || skip != "" {
		if err := copyTreeSkip(src, target, skip); err != nil {
			_ = os.RemoveAll(target)
			return "", err
		}
		return "copy", nil
	}
	if err := snapshotCopyTree(src, target); err == nil {
		return "copy", nil
	}
	_ = os.RemoveAll(target)
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("cp"); err == nil {
			cmd := exec.CommandContext(ctx, "cp", "-c", "-R", src, target)
			if err := cmd.Run(); err == nil {
				_ = os.RemoveAll(filepath.Join(target, ".git"))
				_ = os.RemoveAll(filepath.Join(target, ".kiwi", "cache"))
				stripBuildOutputDirs(target, src)
				return "reflink", nil
			} else if ctx.Err() != nil {
				_ = os.RemoveAll(target)
				return "", ctx.Err()
			}
			_ = os.RemoveAll(target)
		}
	}
	return "", fmt.Errorf("workspace snapshot failed for %s", src)
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
// A git failure (lock contention, corrupt index) is NOT "untracked":
// treating it as such silently dropped source directories during the
// copy (K15-class truncation). Fail closed — the path is kept.
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
// On git failure the answer is "keep the directory" (true): a lock or
// index race must never turn into a silent SkipDir (K15).
func hasTrackedFiles(src, rel string) bool {
	cmd := exec.Command("git", "-C", src, "ls-files", "--", rel)
	out, err := cmd.Output()
	if err != nil {
		return true
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
	return copyTreeSkip(src, dst, "")
}

func copyTreeSkip(src, dst, skip string) error {
	// Resolve symlinked roots/components so Walk can descend (macOS /tmp,
	// /var/folders) AND so destination-exclusion compares the same
	// resolved paths. Without this: (1) a symlinked source stages zero
	// files (K15), or (2) a TMPDIR destination under a symlinked parent
	// is not recognized as under the source and gets copied into itself.
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	}
	if resolved, err := filepath.EvalSymlinks(dst); err == nil {
		dst = resolved
	} else if parent, perr := filepath.EvalSymlinks(filepath.Dir(dst)); perr == nil {
		// dst does not exist yet (normal); resolve its parent only.
		dst = filepath.Join(parent, filepath.Base(dst))
	}
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	// Resolve skip the same way as src/dst so a symlinked TMPDIR/HOME
	// path prefix still matches during the walk.
	if skip != "" {
		if r, rerr := filepath.EvalSymlinks(skip); rerr == nil {
			skip = r
		} else {
			skip = filepath.Clean(skip)
		}
	}
	var preserveTrackedUnder []string
	walkErr := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if pathAbs, aerr := filepath.Abs(path); aerr == nil {
			// src and dst are already EvalSymlinks-resolved above, so Walk
			// emits resolved paths under src; dstAbs is the resolved dest.
			if pathAbs == dstAbs || strings.HasPrefix(pathAbs, dstAbs+string(filepath.Separator)) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if skip != "" && skip != "." {
				if pathAbs == skip || strings.HasPrefix(pathAbs, skip+string(filepath.Separator)) {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
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
	if walkErr != nil {
		return walkErr
	}
	// An empty source (or a walk that only skipped) never creates dst via
	// mkdirParents: materialize it so Freeze/verify always see a directory.
	if _, serr := os.Stat(dst); serr != nil {
		return os.MkdirAll(dst, 0o755)
	}
	return nil
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
