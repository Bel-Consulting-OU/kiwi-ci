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
	// git is the Git context captured FROM THE SOURCE during Freeze, so
	// RunLocal never trusts a copied .git (linked worktrees point at live
	// admin dirs and can change HEAD after freeze).
	git FrozenGit
	// refs carries explicit --base/--head/--merge-base inputs captured
	// before Freeze so their ref resolutions are part of the frozen
	// transaction instead of a post-Freeze live-Git read.
	refs RefQuery
	// tracked is the immutable index membership captured once at Freeze:
	// the freeze manifest and the run-base copy are computed from this
	// SAME set, and Prepare never re-queries Git on the frozen tree.
	tracked trackedIndex
}

// RefQuery is the explicit ref context the caller wants frozen with the
// tree (--base / --head / --merge-base from kiwi run). Set it before
// Freeze; an empty query means "use the captured default range".
type RefQuery struct {
	Base      string
	Head      string
	MergeBase string
}

// explicit reports whether the caller asked for a non-default ref range.
func (q RefQuery) explicit() bool {
	return q.Base != "" || q.MergeBase != "" || (q.Head != "" && q.Head != "HEAD")
}

// CaptureRefs records the explicit ref query used by the frozen Git
// capture. It must be called BEFORE Freeze; after a run-base exists the
// call is ignored (the transaction is already closed).
func (m *Manager) CaptureRefs(q RefQuery) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.base != "" {
		return
	}
	m.refs = q
}

// FrozenGitState is the post-Freeze repository state. Every state is
// captured at Freeze time; RunLocal must switch on it instead of
// re-reading live Git.
type FrozenGitState string

const (
	// FrozenGitNotRepo: the source was not a Git repository at Freeze.
	FrozenGitNotRepo FrozenGitState = "not-repo"
	// FrozenGitRepoNoHead: a repository with an unborn HEAD (no commits).
	// SHA stays empty for the whole run, even if a commit lands later.
	FrozenGitRepoNoHead FrozenGitState = "repo-no-head"
	// FrozenGitStateCaptured: HEAD was sampled atomically.
	FrozenGitStateCaptured FrozenGitState = "captured"
	// FrozenGitUnstableState: the repository exists but identity capture
	// failed (HEAD moved mid-read). Freeze refuses after one retry.
	FrozenGitUnstableState FrozenGitState = "unstable"
)

// FrozenGit is the identity captured at freeze time from the source tree.
//
// States (see State()):
//   - not-repo: no repository; SHA/ref/branch/repo identity stay empty
//     forever for this run — a repository created AFTER Freeze is never
//     consulted.
//   - repo-no-head: repository with unborn HEAD; SHA stays empty forever,
//     but branch/ref/repo identity are captured.
//   - captured: atomic capture succeeded.
//   - unstable: a repository exists but the atomic capture failed (HEAD
//     moved mid-read). Freeze must retry and then fail; RunLocal must
//     NEVER fall back to live Git after Freeze.
type FrozenGit struct {
	Captured bool   `json:"captured"`
	Unstable bool   `json:"unstable,omitempty"`
	Repo     bool   `json:"repo,omitempty"`
	SHA      string `json:"sha,omitempty"`
	Ref      string `json:"ref,omitempty"`
	Branch   string `json:"branch,omitempty"`
	// RepoURL/RepoFullName are the repository identity derived from the
	// source's remote AT FREEZE TIME. A linked worktree's .git pointer is
	// stripped from the run-base, so a post-Freeze detectGitRepo would
	// lose them — they must travel inside FrozenGit.
	RepoURL      string `json:"repo_url,omitempty"`
	RepoFullName string `json:"repo_full_name,omitempty"`
	// Explicit carries the resolved --base/--head/--merge-base changed-file
	// set, computed from the SOURCE inside the frozen transaction.
	Explicit     *FrozenRefs `json:"explicit_refs,omitempty"`
	ChangedFiles []string    `json:"changed_files,omitempty"`
	ChangedKnown bool        `json:"changed_known"`
}

// FrozenRefs is one explicit ref-range resolution captured at Freeze.
type FrozenRefs struct {
	Base      string   `json:"base,omitempty"`
	Head      string   `json:"head,omitempty"`
	MergeBase string   `json:"merge_base,omitempty"`
	Files     []string `json:"files,omitempty"`
	Known     bool     `json:"known"`
}

// State classifies the frozen repository context.
func (g FrozenGit) State() FrozenGitState {
	switch {
	case g.Unstable:
		return FrozenGitUnstableState
	case g.Captured:
		return FrozenGitStateCaptured
	case g.Repo:
		return FrozenGitRepoNoHead
	default:
		return FrozenGitNotRepo
	}
}

// Unstable reports a Git repository whose identity could not be captured
// atomically — distinct from "not a repository".
func (g FrozenGit) CaptureFailed() bool { return g.Unstable && !g.Captured }

// FrozenGitInfo returns the Git context captured at Freeze (zero if none).
func (m *Manager) FrozenGitInfo() FrozenGit {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.git
	g.ChangedFiles = append([]string(nil), m.git.ChangedFiles...)
	return g
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
	// The freeze transaction runs as ONE attempt function with a single
	// retry. Every instability — a source tree that moves, an unstable Git
	// capture, a byte-proof failure, OR a manifest that cannot establish
	// content identity (unreadable file, size race mid-read) — is a
	// retryable instability on the first attempt. Only the SECOND attempt
	// decides which specific authority failed. This keeps the fail-closed
	// content-identity rule compatible with the transaction's transient-
	// mutation tolerance: a busy tree gets one retry instead of an
	// immediate abort, and a persistently unprovable tree still fails.
	type attemptResult struct {
		strategy  string
		unstable  bool
		integrity error
		changed   bool
		err       error
	}
	clean := func(r attemptResult) bool {
		return r.err == nil && !r.unstable && r.integrity == nil && !r.changed
	}
	attempt := func() attemptResult {
		var res attemptResult
		// ONE immutable index membership per attempt: the manifests, the
		// copy, and the byte proof all read this same captured set — no
		// live `git ls-files` decisions during the walk.
		idx, err := captureTrackedIndex(ctx, m.Source)
		if err != nil {
			res.err = fmt.Errorf("run base: capture tracked paths: %w", err)
			return res
		}
		m.tracked = idx
		if freezeBeforeManifestHook != nil {
			freezeBeforeManifestHook()
		}
		proofs := map[string]freezeFileProof{}
		before, err := freezeManifestIndex(m.Source, skip, idx, proofs)
		if err != nil {
			res.err = fmt.Errorf("run base: source manifest: %w", err)
			return res
		}
		// Capture Git identity from the SOURCE before copying. Never use
		// the copied .git later: a linked worktree's gitdir stays on the
		// live repo.
		m.git = captureFrozenGit(m.Source, m.refs)
		res.unstable = m.git.CaptureFailed()
		base := filepath.Join(m.Root, "run-base")
		// Freeze ALWAYS uses a plain working-tree copy (never the opt-in
		// worktree strategy): run-base must match the developer's source
		// listing including ignored/untracked files, and a worktree of HEAD
		// would silently drop them before any job runs.
		strategy, err := m.snapshotFrom(ctx, m.Source, base, true, idx)
		if err != nil {
			_ = os.RemoveAll(base)
			res.err = fmt.Errorf("run base snapshot: %w", err)
			return res
		}
		// Byte proof: re-hash every copied regular file against its source
		// and require the source's identity to be the one the pre-copy
		// manifest observed. This catches what before/after manifests
		// cannot: a source mutated DURING the copy and restored before the
		// after-manifest, which leaves A==B while the run-base holds
		// hybrid bytes.
		if freezeAfterCopyHook != nil {
			freezeAfterCopyHook()
		}
		res.integrity = verifyRunBaseByteProof(m.Source, base, proofs)
		after, err := freezeManifestIndex(m.Source, skip, idx, nil)
		if err != nil {
			_ = os.RemoveAll(base)
			res.err = fmt.Errorf("run base: source re-manifest: %w", err)
			return res
		}
		res.strategy = strategy
		res.changed = before != after
		return res
	}
	res := attempt()
	if !clean(res) {
		// One retry over a freshly recaptured index, Git state and copy —
		// the same transaction boundary the mutating-source design always
		// had, now also covering manifest/identity-proof failures.
		_ = os.RemoveAll(filepath.Join(m.Root, "run-base"))
		res = attempt()
	}
	if !clean(res) {
		_ = os.RemoveAll(filepath.Join(m.Root, "run-base"))
		switch {
		case res.err != nil:
			return res.err
		case res.integrity != nil:
			return fmt.Errorf("run base: %w", res.integrity)
		case res.unstable:
			return fmt.Errorf("run base: Git identity capture failed atomically (HEAD moved during freeze); re-run when the repository is quiet")
		default:
			return fmt.Errorf("run base: source tree changed during freeze (retry also unstable); re-run when the working tree is quiet")
		}
	}
	base := filepath.Join(m.Root, "run-base")
	if err := verifyStagedTreeIndex(m.Source, entries, base, res.strategy, m.tracked); err != nil {
		_ = os.RemoveAll(base)
		return fmt.Errorf("run base verify: %w", err)
	}
	// A linked worktree's .git is a FILE pointing at a live administration
	// directory outside the freeze tree. Leaving it lets any job run
	// `git rev-parse` / `git status` against the moving original checkout.
	// FrozenGit is the sole authority; the pointer is removed so Git inside
	// the run-base fails closed instead of lying.
	if err := stripLiveGitPointer(base); err != nil {
		_ = os.RemoveAll(base)
		return fmt.Errorf("run base freeze git pointer: %w", err)
	}
	m.base = base
	m.baseEntries = entries
	return nil
}

// stripLiveGitPointer removes a linked-worktree .git FILE (not directory)
// from the frozen tree. A real .git directory (normal clone with its own
// admin dir under the tree) is left intact.
func stripLiveGitPointer(base string) error {
	p := filepath.Join(base, ".git")
	st, err := os.Lstat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Mode().IsDir() {
		return nil
	}
	return os.Remove(p)
}

// trackedIndex answers skip-directory membership questions for one freeze
// transaction. The captured form is immutable: the freeze manifest and the
// run-base copy both consult the SAME index, so Git-index churn during the
// copy can never change what enters the snapshot while the before/after
// manifests stay identical.
type trackedIndex interface {
	// dirTracked reports whether any tracked path lives under rel.
	dirTracked(rel string) bool
	// fileTracked reports whether exactly rel is tracked.
	fileTracked(rel string) bool
}

// liveTrackedIndex queries the live Git index per path. It backs the
// legacy direct copyTree entry points and the keep-on-error helpers; the
// freeze transaction itself always uses a captured index.
type liveTrackedIndex struct{ src string }

func (l liveTrackedIndex) dirTracked(rel string) bool  { return hasTrackedFiles(l.src, rel) }
func (l liveTrackedIndex) fileTracked(rel string) bool { return isGitTracked(l.src, rel) }

// capturedTrackedIndex is the immutable index snapshot taken once per
// freeze attempt (git ls-files -z in a single invocation).
type capturedTrackedIndex struct {
	files map[string]bool // slash-normalized tracked file paths
	dirs  map[string]bool // slash-normalized dirs containing tracked files
}

func (c *capturedTrackedIndex) dirTracked(rel string) bool {
	return c.dirs[filepath.ToSlash(rel)]
}
func (c *capturedTrackedIndex) fileTracked(rel string) bool {
	return c.files[filepath.ToSlash(rel)]
}

// allTrackedIndex treats everything as tracked: used to copy the ALREADY
// canonical run-base verbatim, where build-output filtering and index
// membership were resolved once at Freeze and must never be re-derived.
type allTrackedIndex struct{}

func (allTrackedIndex) dirTracked(string) bool  { return true }
func (allTrackedIndex) fileTracked(string) bool { return true }

// captureTrackedIndex snapshots Git index membership for src ONCE.
//
//   - Not a Git repository: empty index (skip-name directories are build
//     output by name — there is no index that could say otherwise), and
//     the manifest and copy agree on that.
//   - A repository whose index cannot be read: FAIL CLOSED. A lock or
//     index race during freeze must never become a silent SkipDir or a
//     silent extra file (K15), and a partial freeze must never certify a
//     tree the index did not describe.
func captureTrackedIndex(ctx context.Context, src string) (trackedIndex, error) {
	idx := &capturedTrackedIndex{files: map[string]bool{}, dirs: map[string]bool{}}
	if !gitRepo(ctx, src) {
		return idx, nil
	}
	cmd := exec.CommandContext(ctx, "git", "-C", src, "ls-files", "-z")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	for _, p := range strings.Split(string(out), "\x00") {
		p = strings.TrimSuffix(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		idx.files[p] = true
		// Ancestor directories of a tracked file are "containing tracked
		// files" for the skip-dir walk.
		for d := filepath.ToSlash(filepath.Dir(filepath.FromSlash(p))); d != "." && d != "/" && d != ""; d = filepath.ToSlash(filepath.Dir(filepath.FromSlash(d))) {
			idx.dirs[d] = true
		}
	}
	return idx, nil
}

// freezeManifest is a deterministic digest of path/type/size/mtime for
// every entry under root (symlinks record their target). skip, when
// non-empty and under root, is omitted (the manager's own Root under a
// HOME-as-source layout). Used to detect concurrent mutation while the
// run-base is being copied.
//
// The two-argument form binds the LIVE index (tests and legacy callers);
// the freeze transaction uses freezeManifestIndex with the captured set so
// manifest membership and copy membership are byte-for-byte the same rule.
func freezeManifest(root, skip string) (string, error) {
	return freezeManifestIndex(root, skip, liveTrackedIndex{src: root}, nil)
}

// freezeFileProof is the pre-copy identity of one source regular file: the
// FileInfo the manifest observed, used after the copy to prove the source
// inode/size/mode/mtime never moved while the run-base was built.
type freezeFileProof struct {
	info os.FileInfo
}

// freezeManifestIndex digests exactly the entries the copy with the SAME
// index would include: a skip-name directory enters iff the index says it
// carries tracked paths, and inside it only indexed files are digested —
// so an untracked temp file churning under dist/ can never destabilize the
// freeze, and index changes are decided by one captured set instead of
// repeated live queries.
//
// When proofs is non-nil it is populated with the pre-copy identity of
// every included regular file (the freeze transaction's byte-proof input).
// Content identity is FAIL-CLOSED: if a file's bytes cannot be fully
// hashed (unreadable, or it changed size mid-read), the manifest fails
// instead of silently degrading to size/mode/mtime — metadata is fast
// invalidation, not proof that the byte stream did not change.
func freezeManifestIndex(root, skip string, idx trackedIndex, proofs map[string]freezeFileProof) (string, error) {
	skip = filepath.Clean(skip)
	h := sha256.New()
	var preserve []string
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
		// Same inclusion rule as copyTree: .kiwi/cache never enters the
		// snapshot, so a busy cache must not fail the freeze stability
		// oracle either.
		cacheRel := filepath.Join(".kiwi", "cache")
		if rel == cacheRel || strings.HasPrefix(rel, cacheRel+string(filepath.Separator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		kind := "f"
		if info.IsDir() {
			// Same inclusion rule as copyTree: a skip-name directory is
			// omitted unless the captured index tracks paths under it
			// (tracked dist/ etc. must stay visible to the stability oracle).
			if copyTreeSkipDirs[info.Name()] {
				if idx.dirTracked(rel) {
					preserve = append(preserve, rel)
				} else {
					return filepath.SkipDir
				}
			}
			// Inside a preserved skip directory, directories without
			// tracked descendants never enter the copy — exclude them here
			// too so both walks describe one input set.
			if inPreservedSkip(preserve, rel) && !isSkipRoot(preserve, rel) && !idx.dirTracked(rel) {
				return filepath.SkipDir
			}
			kind = "d"
		} else {
			if inPreservedSkip(preserve, rel) && !idx.fileTracked(rel) {
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				kind = "l"
				target, lerr := os.Readlink(path)
				if lerr != nil {
					return lerr
				}
				fmt.Fprintf(h, "%s\x00%s\x00%s\n", rel, kind, target)
				return nil
			}
		}
		fmt.Fprintf(h, "%s\x00%s\x00%d\x00%d\x00%016x", rel, kind, info.Size(), info.Mode().Perm(), info.ModTime().UnixNano())
		// Content identity: EVERY regular file is fully hashed (no sampled
		// shortcut — run-base is the canonical authority from which
		// execution and evidence derive, so equality cannot be
		// probabilistic for any size). A digest that cannot be obtained
		// fails the freeze: metadata-only rows are invalidation hints, not
		// byte proof.
		if kind == "f" {
			if proofs != nil {
				proofs[rel] = freezeFileProof{info: info}
			}
			if info.Size() > 0 {
				d, ok := freezeContentDigest(path, info.Size())
				if !ok {
					return fmt.Errorf("freeze: content identity for %q could not be established (refusing a metadata-only freeze proof)", rel)
				}
				fmt.Fprintf(h, "\x00%s", d)
			}
		}
		fmt.Fprint(h, "\n")
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// freezeContentDigest returns the hex digest of the file's COMPLETE byte
// stream. ok is false when the bytes cannot be fully read or the file's
// size moved while it was being read (the caller then refuses the freeze
// rather than accepting metadata as a substitute). Every size gets the
// full hash: sampled equality was acceptable for fast invalidation, never
// for the canonical run-base proof.
func freezeContentDigest(path string, size int64) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil || n != size {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)[:8]), true
}

// freezeBeforeManifestHook is a test-only seam invoked at the start of
// every freeze attempt, before the source manifest runs, so tests can
// script per-attempt instability (for example, a file that is unreadable
// for the first manifest and readable for the retry). Nil in production.
var freezeBeforeManifestHook func()

// freezeAfterCopyHook is a test-only seam invoked after the run-base copy
// and before the byte proof, so tests can fabricate exactly the race the
// proof exists for (source mutated after its bytes were copied). Nil in
// production.
var freezeAfterCopyHook func()

// verifyRunBaseByteProof re-hashes every copied regular file against its
// source and requires the source's identity to match the pre-copy manifest
// proof. This is the equality proof before/after manifests cannot give: a
// source mutated DURING the copy and restored before the after-manifest
// leaves both manifests equal while the run-base holds bytes that were
// never the source's certified state at any single observation.
//
// The manager-created namespaces (.kiwi-frozen adoptions and the frozen
// link-target store) are excluded: their bytes do not come from the source
// tree copy.
func verifyRunBaseByteProof(srcRoot, baseRoot string, proofs map[string]freezeFileProof) error {
	return filepath.Walk(baseRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(baseRoot, path)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if rel == ".kiwi-frozen" || strings.HasPrefix(relSlash, ".kiwi-frozen/") ||
			rel == ".kiwi-frozen-link-targets" || strings.HasPrefix(relSlash, ".kiwi-frozen-link-targets/") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// Symlink identity (the target string) is bound by the
			// manifests; byte proof covers regular file content only.
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("run base: %q is not a regular file", rel)
		}
		p, ok := proofs[rel]
		if !ok {
			return fmt.Errorf("run base: %q has no source proof from the pre-copy manifest", rel)
		}
		srcPath := filepath.Join(srcRoot, rel)
		stNow, serr := os.Stat(srcPath)
		if serr != nil {
			return fmt.Errorf("run base: source file %q vanished during freeze: %w", rel, serr)
		}
		if !os.SameFile(p.info, stNow) ||
			p.info.Size() != stNow.Size() ||
			p.info.Mode() != stNow.Mode() ||
			!p.info.ModTime().Equal(stNow.ModTime()) {
			return fmt.Errorf("source identity for %q moved during freeze (inode/size/mode/mtime)", rel)
		}
		baseDigest, berr := hashFileContent(path)
		if berr != nil {
			return fmt.Errorf("run base: content identity for %q could not be established: %w", rel, berr)
		}
		srcDigest, serr := hashFileContent(srcPath)
		if serr != nil {
			return fmt.Errorf("run base: content identity for source %q could not be established: %w", rel, serr)
		}
		if baseDigest != srcDigest {
			return fmt.Errorf("copied bytes do not match source for %q (content integrity)", rel)
		}
		return nil
	})
}

// hashFileContent returns the hex digest of a file's complete byte stream.
// A read failure is an error: byte proof never degrades to metadata.
func hashFileContent(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// adoptStat is the adopted-file stability seam: tests substitute a changing
// size/mtime sequence to prove AdoptFile refuses a file that mutated while
// it was being read (a hybrid of two writes must never become run
// authority).
var adoptStat = os.Stat

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
	// Frozen run-base is the CANONICAL tree: a job workspace is an exact
	// copy of it. Git-dependent source selection (skip-name filtering,
	// index membership) was resolved ONCE at Freeze against the live
	// source; re-running it here would re-derive a DIFFERENT set on a
	// run-base whose live Git was stripped (linked worktrees) or whose
	// index moved — silently dropping tracked dist/ content the freeze
	// already certified as source. allTrackedIndex copies every byte the
	// freeze chose to keep.
	strategy, err := m.snapshotFrom(ctx, m.base, target, false, allTrackedIndex{})
	if err != nil {
		_ = os.RemoveAll(target)
		return "", nil, fmt.Errorf("prepare workspace for %q: %w", jobID, err)
	}
	switch strategy {
	case "worktree":
		// Worktree was created from the frozen base (opt-in strategy),
		// which carries its own copy of the frozen .git — never from the
		// live source. Verify against the immutable source listing with
		// the captured index (same rules as the freeze copy).
		if err := verifyStagedTreeIndex(m.Source, m.baseEntries, target, strategy, m.tracked); err != nil {
			removeWorktree(m.base, target)
			return "", nil, fmt.Errorf("prepare workspace for %q: %w", jobID, err)
		}
		return target, func() { removeWorktree(m.base, target) }, nil
	default:
		// Exact copy: verify against the run-base itself (the authority).
		if err := verifyExactTree(m.base, target, strategy); err != nil {
			_ = os.RemoveAll(target)
			return "", nil, fmt.Errorf("prepare workspace for %q: %w", jobID, err)
		}
		return target, func() { _ = os.RemoveAll(target) }, nil
	}
}

// verifyExactTree fails closed unless every top-level entry of the
// canonical run-base made it into the job workspace, and the file counts
// match. Used for frozen Prepare, where no filtering decision may be
// re-derived: the base IS the expected content.
//
// strategy "reflink" (the darwin cp -c fallback) deliberately strips .git
// from the materialized tree — the same exemption verifyStagedTree applies
// — so the .git subtree is excluded from both the presence check and the
// file count instead of failing a legitimately complete copy.
func verifyExactTree(base, target, strategy string) error {
	baseEntries, err := os.ReadDir(base)
	if err != nil {
		return fmt.Errorf("verify exact copy: read base: %w", err)
	}
	dstEntries, err := os.ReadDir(target)
	if err != nil {
		return fmt.Errorf("verify exact copy: read target: %w", err)
	}
	have := map[string]bool{}
	for _, e := range dstEntries {
		have[e.Name()] = true
	}
	var missing []string
	for _, e := range baseEntries {
		if strategy == "reflink" && e.Name() == ".git" {
			continue
		}
		if !have[e.Name()] {
			missing = append(missing, e.Name())
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("staged workspace is truncated: missing base entr(y/ies) %v (strategy=%s)", missing, strategy)
	}
	countFiles := func(root string, excludeGit bool) (n int) {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info != nil && !info.IsDir() {
				if excludeGit {
					rel, rerr := filepath.Rel(root, path)
					if rerr == nil && (rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator))) {
						return nil
					}
				}
				n++
			}
			return nil
		})
		return n
	}
	excludeGit := strategy == "reflink"
	bn, dn := countFiles(base, excludeGit), countFiles(target, false)
	if bn > 0 && dn == 0 {
		return fmt.Errorf("staged workspace is empty but the run-base has %d files", bn)
	}
	if dn < bn {
		return fmt.Errorf("staged workspace has %d files, run-base has %d (truncated copy, strategy=%s)", dn, bn, strategy)
	}
	return nil
}

// verifyStagedTree fails closed when a snapshot lost top-level directories
// from the pre-copied source listing or produced an implausibly small tree.
// srcEntries must be the listing taken BEFORE the copy so concurrent
// source mutations cannot invent phantom missing directories.
// The unqualified form binds the LIVE index (tests and the legacy
// unfrozen branch); freeze/Prepare use verifyStagedTreeIndex with the
// captured set.
func verifyStagedTree(src string, srcEntries []os.DirEntry, target, strategy string) error {
	return verifyStagedTreeIndex(src, srcEntries, target, strategy, liveTrackedIndex{src: src})
}

func verifyStagedTreeIndex(src string, srcEntries []os.DirEntry, target, strategy string, idx trackedIndex) error {
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
		if copyTreeSkipDirs[name] && !idx.dirTracked(name) {
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
// snapshotCopyTree is copyTree bound to an index (the snapshot caller's
// index) unless a fallback test substitutes a failing copy to exercise the
// reflink/cancel paths.
var snapshotCopyTree = func(src, dst string, idx trackedIndex) error {
	return copyTreeSkipIndex(src, dst, "", idx)
}

// workspaceStrategyEnv selects the snapshot strategy. Empty (default) is
// always copyTree — the deterministic working-tree copy. "worktree" opts
// into the clean-tree `git worktree add` snapshot (committed files only).
const workspaceStrategyEnv = "KIWI_WORKSPACE_STRATEGY"

func (m *Manager) snapshotFrom(ctx context.Context, src, target string, forceCopy bool, idx trackedIndex) (string, error) {
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
		if err := copyTreeSkipIndex(src, target, skip, idx); err != nil {
			_ = os.RemoveAll(target)
			return "", err
		}
		return "copy", nil
	}
	if err := snapshotCopyTree(src, target, idx); err == nil {
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
	return copyTreeSkipIndex(src, dst, "", liveTrackedIndex{src: src})
}

func copyTreeSkip(src, dst, skip string) error {
	return copyTreeSkipIndex(src, dst, skip, liveTrackedIndex{src: src})
}

// copyTreeSkipIndex copies with an explicit index for skip-directory
// membership. The freeze transaction passes its captured index (one
// immutable membership for manifest AND copy); direct/live copies pass
// liveTrackedIndex; frozen Prepare passes allTrackedIndex for an exact
// copy of the canonical run-base.
func copyTreeSkipIndex(src, dst, skip string, idx trackedIndex) error {
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
			// Membership comes from the transaction's index — never a
			// second live `git ls-files` decision mid-copy.
			if idx.dirTracked(rel) {
				preserveTrackedUnder = append(preserveTrackedUnder, rel)
			} else {
				return filepath.SkipDir
			}
		}
		// Inside a kept skip-name directory, copy only indexed paths.
		// The root itself always stays so the walk reaches its children.
		// Directories stay if they hold tracked descendants (a bare dir is
		// not in the index; its files are).
		if inPreservedSkip(preserveTrackedUnder, rel) && !isSkipRoot(preserveTrackedUnder, rel) {
			if info.IsDir() {
				if !idx.dirTracked(rel) {
					return filepath.SkipDir
				}
			} else if !idx.fileTracked(rel) {
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
			return materializeSymlink(path, link, src, dst, target)
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

// captureFrozenGit records repository identity (HEAD SHA/ref/branch, the
// remote's repo coordinates, the changed-file set, and any explicit
// --base/--head/--merge-base resolution) from dir (the SOURCE, before
// copy). known is false when git cannot produce a trustworthy diff.
//
// Package-level var so tests can substitute an unstable capture and prove
// Freeze refuses to fall back to live Git.
var captureFrozenGit = captureFrozenGitSource

// Atomicity: HEAD is sampled once and every subsequent command must still
// resolve to that same SHA. On a linked worktree the administration
// directory lives outside the freeze tree and can move mid-read; a
// mismatched sample yields Unstable (not "not a repo"), which Freeze
// treats as a hard failure after one retry.
//
// After this returns, NO caller may re-read live Git: everything RunLocal
// needs (including remote coordinates, which a stripped linked-worktree
// run-base can no longer answer) is inside the returned struct.
func captureFrozenGitSource(dir string, refs RefQuery) FrozenGit {
	g := FrozenGit{}
	if !gitRepo(context.Background(), dir) {
		// Not a repository: leave Captured=false, Unstable=false, Repo=false.
		return g
	}
	g.Repo = true
	g.RepoURL, g.RepoFullName = captureRepoIdentity(dir)
	// Unstable means "HEAD was sampled once and then MOVED" — never
	// "HEAD missing". An empty repository (git init, no commits) has no
	// identity to freeze and must not fail Freeze; it is its own state
	// (repo-no-head): SHA stays empty for the whole run even if a commit
	// lands a millisecond later, because RunLocal never re-reads Git.
	unstable := FrozenGit{Unstable: true, Repo: true, RepoURL: g.RepoURL, RepoFullName: g.RepoFullName}
	headOut, err := exec.Command("git", "-C", dir, "rev-parse", "--verify", "--quiet", "HEAD").Output()
	if err != nil || len(headOut) == 0 {
		// Distinguish unborn HEAD (empty repo — symbolic-ref still works)
		// from an unreadable/corrupt HEAD (unstable capture).
		if refOut, refErr := exec.Command("git", "-C", dir, "symbolic-ref", "-q", "HEAD").Output(); refErr == nil && len(refOut) > 0 {
			// repo-no-head: capture everything that does NOT depend on a
			// commit so the run keeps stable branch/ref/repo identity.
			g.Ref = strings.TrimSpace(string(refOut))
			if out, berr := exec.Command("git", "-C", dir, "symbolic-ref", "--short", "-q", "HEAD").Output(); berr == nil {
				g.Branch = strings.TrimSpace(string(out))
			}
			if refs.explicit() {
				// No HEAD to resolve against; record the request as
				// unresolved so RunLocal reports unknown instead of
				// re-running Git against the live tree after Freeze.
				g.Explicit = &FrozenRefs{Base: refs.Base, Head: refs.Head, MergeBase: refs.MergeBase, Known: false}
			}
			return g
		}
		return unstable // HEAD claimed but unreadable / mid-operation
	}
	head := strings.TrimSpace(string(headOut))
	if head == "" {
		return g
	}
	g.Captured = true
	g.SHA = head
	// Bracket: every further Git read must still see the same HEAD.
	sameHEAD := func() bool {
		out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
		return err == nil && strings.TrimSpace(string(out)) == head
	}
	if out, err := exec.Command("git", "-C", dir, "symbolic-ref", "-q", "HEAD").Output(); err == nil {
		g.Ref = strings.TrimSpace(string(out))
	} else {
		g.Ref = head
	}
	if !sameHEAD() {
		// HEAD moved between samples: unstable, never a hybrid of two states
		// and never "not a repo" (which would send RunLocal to live Git).
		return unstable
	}
	if out, err := exec.Command("git", "-C", dir, "symbolic-ref", "--short", "-q", "HEAD").Output(); err == nil {
		g.Branch = strings.TrimSpace(string(out))
	}
	if !sameHEAD() {
		return unstable
	}
	// Changed files: HEAD~1..HEAD like the local default, from SOURCE.
	out, err := exec.Command("git", "-C", dir, "diff", "--name-only", "HEAD~1", "HEAD").Output()
	if !sameHEAD() {
		return unstable
	}
	if err != nil {
		// HEAD is stable but the diff failed (no parent commit, etc.):
		// identity is captured; only the change set is unknown.
		g.ChangedKnown = false
		g.ChangedFiles = nil
	} else {
		g.ChangedKnown = true
		for _, s := range strings.Split(string(out), "\n") {
			if s = strings.TrimSpace(s); s != "" {
				g.ChangedFiles = append(g.ChangedFiles, s)
			}
		}
	}
	// Explicit --base/--head/--merge-base: resolve inside the SAME
	// transaction so a post-Freeze live read can never reinterpret the
	// range against a tree (or a stripped run-base) that cannot answer it.
	if refs.explicit() {
		fr := &FrozenRefs{Base: refs.Base, Head: refs.Head, MergeBase: refs.MergeBase}
		resolveBase := refs.Base
		if refs.MergeBase != "" {
			mb, mberr := exec.Command("git", "-C", dir, "merge-base", "HEAD", refs.MergeBase).Output()
			if !sameHEAD() {
				return unstable
			}
			if mberr != nil {
				g.Explicit = fr // Known=false: unresolved, never guessed
				return g
			}
			resolveBase = strings.TrimSpace(string(mb))
		}
		if resolveBase == "" {
			resolveBase = "HEAD~1"
		}
		dh := refs.Head
		if dh == "" {
			dh = "HEAD"
		}
		dout, derr := exec.Command("git", "-C", dir, "diff", "--name-only", resolveBase, dh).Output()
		if !sameHEAD() {
			return unstable
		}
		if derr != nil {
			g.Explicit = fr
			return g
		}
		fr.Known = true
		for _, s := range strings.Split(string(dout), "\n") {
			if s = strings.TrimSpace(s); s != "" {
				fr.Files = append(fr.Files, s)
			}
		}
		g.Explicit = fr
	}
	return g
}

// captureRepoIdentity reads the source's remote (origin, then upstream,
// then any remote) and derives repo coordinates — the same pure string
// derivation detectGitRepo applies, but ONCE at freeze time so a stripped
// linked-worktree run-base can never lose CI_REPO / GITHUB_REPOSITORY.
func captureRepoIdentity(dir string) (repoURL, fullName string) {
	for _, remote := range []string{"origin", "upstream"} {
		out, err := exec.Command("git", "-C", dir, "remote", "get-url", remote).Output()
		if err != nil {
			continue
		}
		url := strings.TrimSpace(string(out))
		if url == "" {
			continue
		}
		return RemoteRepoCoords(url)
	}
	out, err := exec.Command("git", "-C", dir, "remote", "-v").Output()
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] != "" {
			return RemoteRepoCoords(fields[1])
		}
	}
	return "", ""
}

// RemoteRepoCoords derives the clone URL and canonical full name from a
// repository remote / --repo value: a URL is used as-is (full name from the
// first host segment onward); an owner/name pair defaults to GitHub.
// Pure string math — no Git — so frozen identity can be derived after the
// run-base has sealed the repository away.
func RemoteRepoCoords(remote string) (repoURL, fullName string) {
	repo := strings.TrimSpace(remote)
	if strings.Contains(repo, "://") {
		repoURL = repo
		fullName = repo
		if i := strings.Index(fullName, "://"); i >= 0 {
			fullName = fullName[i+3:]
		}
		fullName = strings.TrimSuffix(fullName, "/")
		if i := strings.Index(fullName, "/"); i >= 0 {
			fullName = fullName[i+1:]
		}
		fullName = strings.TrimSuffix(fullName, ".git")
		return repoURL, fullName
	}
	fullName = repo
	repoURL = "https://github.com/" + fullName + ".git"
	return repoURL, fullName
}

// materializeSymlink writes a freeze-safe link (or file snapshot) instead of
// blindly copying Readlink bytes. A link that still points at the live
// source or an external path would let job A and job B see different
// contents despite one run-base (deterministic-local P1).
//
//   - target inside src (after resolve): rewrite to a relative link under dst
//   - target is a regular file outside src: snapshot bytes into a hidden
//     store under dst and rewrite as a relative symlink to that snapshot
//     (filesystem semantics preserved: the entry stays a symlink)
//   - target is a directory outside src: refuse (cannot snapshot cheaply)
//   - dangling / lexically escaping: refuse (a later-created external path
//     would re-enter the supposedly immutable run-base)
func materializeSymlink(path, link, src, dst, target string) error {
	res, rerr := filepath.EvalSymlinks(path)
	if rerr != nil {
		if filepath.IsAbs(link) || escapesFrozen(link) {
			return fmt.Errorf("freeze: symlink %q is dangling and escapes the frozen tree (target %q); refusing a non-deterministic run-base", path, link)
		}
		return os.Symlink(link, target)
	}
	absSrc, _ := filepath.Abs(src)
	absRes, _ := filepath.Abs(res)
	inside := absRes == absSrc || strings.HasPrefix(absRes, absSrc+string(filepath.Separator))
	if inside {
		relIn, err := filepath.Rel(absSrc, absRes)
		if err != nil {
			return err
		}
		absTarget, _ := filepath.Abs(filepath.Join(dst, relIn))
		relLink, err := filepath.Rel(filepath.Dir(target), absTarget)
		if err != nil {
			relLink = relIn
		}
		return os.Symlink(relLink, target)
	}
	st, err := os.Stat(res)
	if err != nil {
		if filepath.IsAbs(link) || escapesFrozen(link) {
			return fmt.Errorf("freeze: symlink %q target %q is unreadable and escapes the frozen tree", path, res)
		}
		return os.Symlink(link, target)
	}
	if st.IsDir() {
		return fmt.Errorf("freeze: symlink %q points outside the source to directory %q; refusing a non-deterministic run-base", path, res)
	}
	sum := sha256.Sum256([]byte(absRes))
	storeRel := filepath.Join(".kiwi-frozen-link-targets", hex.EncodeToString(sum[:8]))
	storeAbs := filepath.Join(dst, storeRel)
	if err := mkdirParents(filepath.Dir(storeAbs), 0o755); err != nil {
		return err
	}
	if _, serr := os.Stat(storeAbs); serr != nil {
		if err := copyFile(res, storeAbs, st.Mode().Perm()); err != nil {
			return err
		}
	}
	relLink, err := filepath.Rel(filepath.Dir(target), storeAbs)
	if err != nil {
		return err
	}
	return os.Symlink(relLink, target)
}

// escapesFrozen reports whether a relative link target can climb out of the
// run-base via ".." components.
func escapesFrozen(link string) bool {
	if link == "" {
		return false
	}
	clean := filepath.Clean(link)
	return clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

// AdoptFile copies an external file (e.g. -f ../shared/pipeline.yaml) into
// the frozen run-base so the run identity covers the pipeline bytes. The
// source is read under a stability bracket: a file mutating mid-read is
// retried once and then refused, never adopted as a hybrid of two writes.
// AdoptedInputs is the result of one joint adoption transaction.
type AdoptedInputs struct {
	// PipelineDst is where the pipeline bytes were placed ("" when no
	// pipeline path was given).
	PipelineDst string
	// LockRoot is the structured lock root to pass to applyLocalImageLock
	// ("" when no lock path was given).
	LockRoot string
}

// AdoptInputs adopts the external pipeline and its image lock (either may
// be empty) under ONE stabilization transaction: every input is stat-sampled,
// read, and stat-sampled again inside a single window, so the returned set
// was simultaneously stable. Individually-stable reads could otherwise
// certify pipeline A with lock B even though that combination never
// existed. The whole transaction retries once, then fails closed.
func (m *Manager) AdoptInputs(pipelinePath, lockPath string) (AdoptedInputs, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out AdoptedInputs
	if m.base == "" {
		return out, fmt.Errorf("AdoptInputs: freeze first")
	}
	if pipelinePath == "" && lockPath == "" {
		return out, fmt.Errorf("AdoptInputs: nothing to adopt")
	}
	type planned struct {
		abs   string
		dst   string
		isPip bool
	}
	var plan []planned
	if pipelinePath != "" {
		abs, err := filepath.Abs(pipelinePath)
		if err != nil {
			return out, err
		}
		plan = append(plan, planned{
			abs:   abs,
			dst:   filepath.Join(m.base, ".kiwi-frozen", filepath.Base(filepath.Clean(pipelinePath))),
			isPip: true,
		})
	}
	if lockPath != "" {
		abs, err := filepath.Abs(lockPath)
		if err != nil {
			return out, err
		}
		plan = append(plan, planned{
			abs: abs,
			dst: filepath.Join(m.base, ".kiwi-frozen", "lockroot", ".kiwi", "lock.json"),
		})
	}

	type sample struct {
		info os.FileInfo
	}
	// One window across the whole set: stat-all, read-all, stat-all again.
	// Any movement between a file's samples — size, mode, mtime, OR inode
	// identity (an unlink/recreate that spoofs the metadata) — fails the
	// WHOLE set: the combination was never simultaneously stable.
	attempt := func() ([][]byte, string, error) {
		s1 := make([]sample, len(plan))
		for i, p := range plan {
			st, err := adoptStat(p.abs)
			if err != nil {
				return nil, "", err
			}
			if st.IsDir() {
				return nil, "", fmt.Errorf("adopt: %s is a directory; adopt the specific file", p.abs)
			}
			s1[i] = sample{info: st}
		}
		datas := make([][]byte, len(plan))
		for i, p := range plan {
			b, err := os.ReadFile(p.abs)
			if err != nil {
				return nil, "", err
			}
			datas[i] = b
		}
		for i, p := range plan {
			st2, err := adoptStat(p.abs)
			if err != nil {
				return nil, "", err
			}
			// Inode identity: an unlink/recreate that clones size/mode/mtime
			// is a different FILE. Stats without a Sys payload (test seam
			// fixtures) skip the inode leg; every real os.Stat carries one.
			inodeMoved := s1[i].info.Sys() != nil && st2.Sys() != nil && !os.SameFile(s1[i].info, st2)
			if inodeMoved ||
				s1[i].info.Size() != st2.Size() ||
				s1[i].info.Mode() != st2.Mode() ||
				!s1[i].info.ModTime().Equal(st2.ModTime()) {
				return nil, p.abs, nil
			}
		}
		return datas, "", nil
	}
	datas, changed, err := attempt()
	if err != nil {
		return out, err
	}
	if changed != "" {
		datas, changed, err = attempt()
		if err != nil {
			return out, err
		}
		if changed != "" {
			return out, fmt.Errorf("adopt: %s changed while it was being read (the adoption set must stabilize as one transaction)", changed)
		}
	}
	for i, p := range plan {
		if err := os.MkdirAll(filepath.Dir(p.dst), 0o755); err != nil {
			return out, err
		}
		if err := os.WriteFile(p.dst, datas[i], 0o644); err != nil {
			return out, err
		}
		if p.isPip {
			out.PipelineDst = p.dst
		} else {
			out.LockRoot = filepath.Join(m.base, ".kiwi-frozen", "lockroot")
		}
	}
	return out, nil
}

// AdoptFile copies an external file (e.g. -f ../shared/pipeline.yaml) into
// the frozen run-base so the run identity covers the pipeline bytes.
// It is the single-input form of AdoptInputs.
func (m *Manager) AdoptFile(srcPath string) (string, error) {
	res, err := m.AdoptInputs(srcPath, "")
	if err != nil {
		return "", err
	}
	return res.PipelineDst, nil
}

// AdoptLock freezes an image lockfile into a self-contained lock root under
// the run-base and returns the root directory to pass to applyLocalImageLock
// (Join(root, ".kiwi/lock.json") must resolve to the adopted bytes). This
// preserves the lockfilePath layout instead of flattening lock.json next to
// the pipeline, and never leaves the live original path as authority.
// It is the single-input form of AdoptInputs.
func (m *Manager) AdoptLock(srcLockFile string) (string, error) {
	res, err := m.AdoptInputs("", srcLockFile)
	if err != nil {
		return "", err
	}
	return res.LockRoot, nil
}
