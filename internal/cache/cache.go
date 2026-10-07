package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// MaxArchiveBytes is the ONE authoritative compressed-size bound for a cache
// archive. Every layer of the cache contract resolves its default to this
// single constant: the runner-side restore stream
// (defaultMaxCompressedBytes), the Store's local and remote archive bound
// (defaultCacheArchiveBytes), and the control plane's upload endpoint
// (server's cacheUploadMaxBytes). One bound means an archive one layer
// accepts can always be transferred and restored through another; the former
// split (4 GiB client, 8 GiB store/endpoint) rejected valid large archives on
// restore. It is a hard const, never derived per call site.
const MaxArchiveBytes int64 = 8 << 30

// cacheKeyRE is the accepted archive key shape: an alphanumeric first
// character followed by up to 127 [A-Za-z0-9._-] characters. Keys produced
// by Key are hex SHA-256 digests (a strict subset); the wider shape keeps
// caller-supplied keys usable while rejecting path separators, "..",
// absolute paths and URL-hostile characters, so no store operation (local
// path or remote URL) can address anything outside the cache root.
var cacheKeyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validKey(key string) bool { return cacheKeyRE.MatchString(key) }

// Store is a content-addressed cache archive store. Extraction goes through
// safefs (no symlink following, hard resource limits). When RemoteURL is set
// the local cache transparently falls back to (restore) and mirrors (save)
// the control plane's cache endpoints, authenticated with the runner token.
type Store struct {
	Root          string
	RemoteURL     string
	Token         string
	Client        *http.Client
	MaxCacheBytes int64
	// Retention bounds the whole local cache tree (see RetentionPolicy).
	// Set it before concurrent use; Prune serializes passes internally.
	// When Manager is set, the manager owns the aggregate policy AND the
	// cross-job serialization instead (the store's own fields are then only
	// advisory).
	Retention RetentionPolicy
	pruneMu   sync.Mutex
	// Manager, when non-nil, is the runner-wide aggregate cache budget owner:
	// saves and remote restores reserve capacity through it before writing
	// bytes, and Prune delegates to its shared lock.
	Manager *Manager
	// ReportCleanupDebt, when non-nil, receives one report for every cache
	// filesystem artifact whose removal could not be proven: a restore
	// rollback that could not remove a path it had already published (the
	// live workspace then contains partially restored files) and a staging
	// tree left behind by a restore. It is the same "unproven removal is
	// durable debt" contract as the executor's OnCleanupDebt, and
	// RestoreContextWithDebt lets one call use a caller-owned reporter
	// without mutating this field (set it before concurrent use). A rollback
	// residue is ALSO surfaced in the returned PublishRollbackError even when
	// no reporter is configured; the only reporter-less residue is a leftover
	// staging tree after a successful restore (outside the live workspace, so
	// it cannot corrupt the job).
	ReportCleanupDebt func(kind, path string, err error)
}

// Cleanup kinds reported through Store.ReportCleanupDebt. They are stable
// strings so a consumer (the executor, the runner's recovery ledger) can map
// them onto its own debt taxonomy.
const (
	// CleanupKindRestoreRollback names one workspace path a failed publish's
	// rollback could not remove: the path is still live, so the workspace
	// holds a partially restored tree.
	CleanupKindRestoreRollback = "cache-restore-rollback"
	// CleanupKindStagingResidue names a restore staging tree whose removal
	// failed. Staging lives OUTSIDE the live workspace (a sibling), so the
	// residue occupies disk but never corrupts the restored tree.
	CleanupKindStagingResidue = "cache-staging-residue"
)

func Default() *Store {
	home, _ := os.UserHomeDir()
	return &Store{Root: filepath.Join(home, ".kiwi", "cache")}
}

// storeStallTimeout is the sliding inactivity bound for every remote Store
// transfer body. The watchdog cancels the request context when no byte has
// flowed through a request or response body for this long; every successful
// read or write re-arms it, so a bulk archive transfer may run for an
// arbitrarily long total time as long as it keeps making progress. It is a
// variable (a test seam) so tests can shrink it.
var storeStallTimeout = 90 * time.Second

// ErrTransferStalled reports a remote cache transfer canceled by the Store's
// inactivity watchdog (no byte moved for storeStallTimeout). It is
// deliberately distinct from context cancellation: errors.Is(err,
// ErrTransferStalled) is true only when the watchdog fired, while a caller's
// own context cancellation surfaces as context.Canceled/DeadlineExceeded.
var ErrTransferStalled = errors.New("cache: transfer stalled")

// storeStallGuardHook, when set (tests only), observes watchdog arm and stop
// events so a test can prove every armed timer is stopped.
var storeStallGuardHook func(armed bool)

// Test-only seams over otherwise unreachable OS branches. Production
// behavior is unchanged: removeCacheFile is os.Remove (retention eviction),
// extractCacheArchive is safefs.Extract (local restore extraction).
var (
	removeCacheFile     = os.Remove
	extractCacheArchive = safefs.Extract
)

// Bounded transport phases for cache HTTP traffic. These bound each control
// phase of an exchange without imposing a total transfer deadline: bulk
// archive bodies must be able to run as long as they make progress, so no
// Client.Timeout is ever set by default.
const (
	defaultDialTimeout           = 10 * time.Second
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultResponseHeaderTimeout = 30 * time.Second
	defaultIdleConnTimeout       = 90 * time.Second
)

// defaultTransport returns a transport with bounded dial, TLS handshake,
// response-header and idle phases. Proxy settings, HTTP/2 support and other
// defaults are preserved from http.DefaultTransport.
func defaultTransport() *http.Transport {
	var t *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		t = base.Clone()
	} else {
		t = &http.Transport{}
	}
	t.DialContext = (&net.Dialer{Timeout: defaultDialTimeout, KeepAlive: 30 * time.Second}).DialContext
	t.TLSHandshakeTimeout = defaultTLSHandshakeTimeout
	t.ResponseHeaderTimeout = defaultResponseHeaderTimeout
	t.IdleConnTimeout = defaultIdleConnTimeout
	t.ExpectContinueTimeout = time.Second
	return t
}

// defaultContext is the context the legacy wrapper methods use. It is
// deliberately TIMEOUT-FREE: a bulk cache transfer must be able to run for
// arbitrarily long as long as it keeps making progress, so no total
// wall-clock deadline is imposed. The no-hang guarantee is layered instead:
//
//   - With no caller-supplied Client the wrapper uses the default client
//     whose transport bounds every control phase (dial, TLS handshake,
//     response headers, idle connection).
//   - With a caller-supplied Client the client's own bounds (and the
//     defaultTransport phases when it has none) apply.
//   - In BOTH cases every remote request/response body is wrapped by the
//     sliding storeStallTimeout watchdog, which is the Store's own
//     enforcement and cancels a transfer that stops making progress with
//     ErrTransferStalled.
//
// Callers that need an absolute wall-clock bound (or their own lifetime) must
// use RestoreContext/SaveContext (or configure Client, as the runner does).
// The former 30-second total body deadline on the no-client path killed a
// continuously-progressing large restore outright, contradicting the sliding
// watchdog layered under it.
func (s *Store) defaultContext() (context.Context, context.CancelFunc) {
	return context.Background(), func() {}
}

// storeStallGuard is a sliding inactivity watchdog for one remote transfer.
// It cancels the transfer context when no byte has moved for idle, is
// re-armed by every successful body read or write, and is stopped when the
// transfer finishes. Exactly one timer is armed per transfer and stopped on
// completion, so a finished transfer leaves no timer or goroutine behind.
//
// Unlike the runner-side stall guard, the Store guard maps its own
// cancellation to ErrTransferStalled (see stallError) so direct Store callers
// can tell a stalled peer from their own canceled context.
type storeStallGuard struct {
	cancel context.CancelFunc
	idle   time.Duration
	timer  *time.Timer

	mu      sync.Mutex
	last    time.Time
	fired   bool
	stopped bool
}

// newStoreStallGuard derives a cancelable context from parent and arms the
// watchdog on it. The returned context must be released via release once the
// transfer is done.
func newStoreStallGuard(parent context.Context, idle time.Duration) (context.Context, *storeStallGuard) {
	ctx, cancel := context.WithCancel(parent)
	g := &storeStallGuard{cancel: cancel, idle: idle, last: time.Now()}
	g.timer = time.AfterFunc(idle, g.check)
	if storeStallGuardHook != nil {
		storeStallGuardHook(true)
	}
	return ctx, g
}

// check runs when the watchdog timer fires. Progress recorded after the timer
// was scheduled re-arms it for the remainder of the window; otherwise the
// guard is latched as fired and the transfer context is canceled.
func (g *storeStallGuard) check() {
	g.mu.Lock()
	if g.stopped {
		g.mu.Unlock()
		return
	}
	if left := g.idle - time.Since(g.last); left > 0 {
		g.timer.Reset(left)
		g.mu.Unlock()
		return
	}
	g.fired = true
	g.mu.Unlock()
	g.cancel()
}

// progress records a successful body transfer and re-arms the watchdog.
func (g *storeStallGuard) progress() {
	g.mu.Lock()
	g.last = time.Now()
	g.mu.Unlock()
}

// stop disarms the watchdog. It is idempotent, and a stopped guard never
// fires or reports a stall.
func (g *storeStallGuard) stop() {
	g.mu.Lock()
	first := !g.stopped
	g.stopped = true
	g.mu.Unlock()
	if first {
		g.timer.Stop()
		if storeStallGuardHook != nil {
			storeStallGuardHook(false)
		}
	}
}

// release stops the watchdog and releases the derived context.
func (g *storeStallGuard) release() {
	g.stop()
	g.cancel()
}

// stalled reports whether the watchdog canceled the transfer.
func (g *storeStallGuard) stalled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fired
}

// stallError maps a failed remote operation: a watchdog cancellation is
// surfaced as ErrTransferStalled, everything else (including the caller's own
// context cancellation) is passed through unchanged.
func stallError(ctx context.Context, guard *storeStallGuard, err error) error {
	if err == nil {
		return nil
	}
	if guard.stalled() && ctx.Err() == nil {
		return fmt.Errorf("cache: remote transfer made no progress for %s: %w", guard.idle, ErrTransferStalled)
	}
	return err
}

// stallGuardReader re-arms a watchdog on every successful read. It wraps
// request (upload) bodies: when the transport stops pulling bytes because the
// peer applies backpressure, the watchdog fires and cancels the request.
//
// An abnormal underlying reader that returns (0, nil) for a non-empty buffer
// makes no progress and reports no error; retrying it would re-probe the
// source forever. That case latches io.ErrNoProgress, exactly like the
// bounded readers, so every later read reports the same error without
// touching the source again. A zero-length request is a legal no-op and never
// latches.
type stallGuardReader struct {
	r     io.Reader
	guard *storeStallGuard
	err   error
}

func (r *stallGuardReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.r.Read(p)
	if n > 0 {
		r.guard.progress()
	}
	if n == 0 && err == nil && len(p) > 0 {
		r.err = io.ErrNoProgress
		return 0, r.err
	}
	return n, err
}

// stallGuardedBody wraps a response body so every read re-arms the watchdog
// and Close disarms it and releases the transfer context. Like
// stallGuardReader, a (0, nil) read of a non-empty buffer latches
// io.ErrNoProgress instead of permitting an indefinite no-progress read loop.
type stallGuardedBody struct {
	io.ReadCloser
	guard *storeStallGuard
	err   error
}

func (b *stallGuardedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.guard.progress()
	}
	if n == 0 && err == nil && len(p) > 0 {
		b.err = io.ErrNoProgress
		return 0, b.err
	}
	return n, err
}

func (b *stallGuardedBody) Close() error {
	// The inner Close may still move bytes (a verifying reader drains the
	// remaining stream to validate its digest), so the watchdog must stay
	// armed until that drain returns: releasing first would let a peer that
	// stops sending hang Close forever.
	defer b.guard.release()
	return b.ReadCloser.Close()
}

// Key computes the cache key for base and the workspace's hashFiles. Every
// file is read through a held safefs.WorkspaceRoot: matches are opened
// relative to the root handle with a no-follow discipline, so a hash file
// swapped for a symlink fails the key computation instead of hashing
// content outside the workspace.
func (s *Store) Key(base string, workspace string, hashFiles []string) (string, error) {
	return s.KeyContext(context.Background(), base, workspace, hashFiles)
}

// KeyContext computes the cache key like Key while observing ctx: hashing is
// the first thing a cache restore does, before any steps run, so a job
// deadline must be able to stop a huge hash_files input instead of letting
// the task goroutine hash gigabytes past its own lifetime. The context is
// checked at entry, between glob patterns and between matched files, and the
// reader handed to the digest copy is context-aware.
func (s *Store) KeyContext(ctx context.Context, base string, workspace string, hashFiles []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	h := sha256.New()
	io.WriteString(h, base)
	io.WriteString(h, "\x00")
	root, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return "", err
	}
	defer root.Close()
	var files []string
	for _, p := range hashFiles {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		matches, err := filepath.Glob(filepath.Join(root.Canonical, p))
		if err != nil {
			return "", fmt.Errorf("cache hash_files %q: %w", p, err)
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		rel, err := filepath.Rel(root.Canonical, f)
		if err != nil {
			return "", fmt.Errorf("cache hash_files: %w", err)
		}
		fh, err := root.OpenRel(filepath.ToSlash(rel))
		if err != nil {
			return "", err
		}
		io.WriteString(h, rel)
		_, cpErr := copyCacheDigest(h, safefs.NewContextReader(ctx, fh))
		fh.Close()
		if cpErr != nil {
			return "", cpErr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Restore is RestoreContext with the Store's default context. That context
// carries no total wall-clock deadline: the transfer may run for as long as
// it keeps making progress. A direct call cannot hang because the default
// client's transport bounds every control phase (dial, TLS handshake,
// response headers, idle connection) and the sliding storeStallTimeout
// watchdog cancels a body that stops making progress with ErrTransferStalled.
// Callers that need an absolute wall-clock bound supply their own context to
// RestoreContext.
func (s *Store) Restore(key, workspace string, paths []string) (bool, error) {
	ctx, cancel := s.defaultContext()
	defer cancel()
	return s.RestoreContext(ctx, key, workspace, paths)
}

// RestoreContext restores a cache archive for key into workspace. The context
// is checked before any work and bounds every remote (HTTP) phase; local
// hashing and extraction are separately bounded by the archive size limits.
//
// Restriction semantics are explicit: paths must either contain the
// deliberate whole-root marker "." or a non-empty list of clean
// workspace-relative roots (validated by cleanRoots). An empty list restores
// NOTHING; it is never treated as "everything".
func (s *Store) RestoreContext(ctx context.Context, key, workspace string, paths []string) (bool, error) {
	return s.restoreContext(ctx, key, workspace, paths, s.ReportCleanupDebt)
}

// RestoreContextWithDebt is RestoreContext with a per-call cleanup-debt
// reporter. A non-nil report takes precedence over the Store's
// ReportCleanupDebt field for this call only; it lets a caller that already
// owns a debt ledger (the executor's OnCleanupDebt) receive debt from a
// SUCCESSFUL restore (a staging tree whose removal failed) without mutating
// the shared Store. The reporter receives the same kinds and coordinates as
// the Store field.
func (s *Store) RestoreContextWithDebt(ctx context.Context, key, workspace string, paths []string, report func(kind, path string, err error)) (bool, error) {
	if report == nil {
		report = s.ReportCleanupDebt
	}
	return s.restoreContext(ctx, key, workspace, paths, report)
}

func (s *Store) restoreContext(ctx context.Context, key, workspace string, paths []string, report func(kind, path string, err error)) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !validKey(key) {
		return false, fmt.Errorf("cache: invalid cache key")
	}
	hit, err := s.restoreLocalWithReporter(ctx, key, workspace, paths, report)
	if hit {
		s.touchLocal(key)
		return true, nil
	}
	if err != nil && !errors.Is(err, errLocalUnverified) {
		return false, err
	}
	if s.RemoteURL == "" {
		// A plain miss is (false, nil); an unverifiable local archive is
		// fail-closed and surfaced rather than silently extracted.
		return false, err
	}
	if ferr := s.fetchRemoteContext(ctx, key); ferr != nil {
		if ferr == errRemoteNotFound {
			return false, nil
		}
		return false, ferr
	}
	return s.restoreLocalWithReporter(ctx, key, workspace, paths, report)
}

var errRemoteNotFound = fmt.Errorf("cache entry not found on remote")

// errLocalUnverified marks a local archive that exists but has no stored
// digest sidecar (or an unreadable one): the key is a hash of the cache
// inputs, not of the archive bytes, so without the sidecar there is no way to
// bind the file to the key. It is fail-closed: the archive is never
// extracted, and Restore falls back to the remote (or reports a miss).
var errLocalUnverified = errors.New("cache: local archive has no stored digest to verify against")

// closeCacheFile, syncCacheFile, renameCacheFile and copyCacheDigest are
// test-only seams over os.File.Close, os.File.Sync, os.Rename and io.Copy.
// Production behavior is unchanged; they let the checked close/sync, rename
// and copy-failure branches be exercised.
var (
	closeCacheFile  = (*os.File).Close
	syncCacheFile   = (*os.File).Sync
	renameCacheFile = os.Rename
	// removeCacheTemp removes an aborted operation's temp file. A failure
	// with a manager configured becomes retained cleanup debt (see
	// Manager.RetainTempCleanup), never a silent charge release.
	removeCacheTemp = os.Remove
	copyCacheDigest = io.Copy
)

// renameFn, removeFn and removeAllFn are test-only seams over the filesystem
// primitives restore publication and rollback are built from (rename a staged
// entry into place, remove one published path, remove a created directory or
// staging tree). Production behavior is unchanged; tests replace them to
// inject rename/removal faults and prove a failed rollback surfaces its
// residue as durable cleanup debt instead of discarding the removal error.
var (
	renameFn    = os.Rename
	removeFn    = os.Remove
	removeAllFn = os.RemoveAll
)

// removeStagingDir removes one restore staging tree, returning the removal
// error (nil when the tree is already gone). It exists so a removal error is
// never discarded with `_ =`: callers either report it as cleanup debt or
// join it into the error they are already returning.
func removeStagingDir(dir string) error {
	if dir == "" {
		return nil
	}
	if err := removeAllFn(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// reportCleanupDebt forwards one unproven-removal report to the reporter for
// the current call (a per-call reporter, else the Store field). A nil error
// or a nil reporter is never a report.
func reportCleanupDebt(report func(kind, path string, err error), kind, path string, err error) {
	if err == nil || report == nil {
		return
	}
	report(kind, path, err)
}

// discardStaging removes a staging tree and reports a failure as cleanup debt
// through the call's reporter. It is the failure-path helper: the caller is
// already returning a restore error, so the leftover tree is debt instead of
// a second return value.
func discardStaging(report func(kind, path string, err error), dir string) {
	if err := removeStagingDir(dir); err != nil {
		reportCleanupDebt(report, CleanupKindStagingResidue, dir, err)
	}
}

// countWriter counts the bytes written through it so Save can report the
// archive size without a second read of the file.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// archivePath returns the on-disk archive path for key.
func (s *Store) archivePath(key string) string {
	return filepath.Join(s.Root, key+".tar.gz")
}

// stripChecksumPath returns the sidecar path storing the archive's SHA-256.
func (s *Store) stripChecksumPath(key string) string {
	return filepath.Join(s.Root, key+".tar.gz.sha256")
}

// writeStoredDigest durably records the archive digest next to it, so a later
// restore can bind the (key-addressed, not content-addressed) archive to the
// exact bytes that were saved.
func (s *Store) writeStoredDigest(key, digest string) error {
	return fsutil.AtomicWriteFile(s.stripChecksumPath(key), []byte(digest+"\n"), 0o600)
}

// readStoredDigest returns the stored archive digest, or errLocalUnverified
// when the sidecar is missing or malformed.
func (s *Store) readStoredDigest(key string) (string, error) {
	b, err := os.ReadFile(s.stripChecksumPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return "", errLocalUnverified
		}
		return "", err
	}
	digest := strings.TrimSpace(string(b))
	if !sha256RE.MatchString(digest) {
		return "", fmt.Errorf("cache restore: stored digest for %s is malformed", key)
	}
	return digest, nil
}

// defaultCacheArchiveBytes bounds a cache archive when MaxCacheBytes is not
// configured. It resolves to the ONE shared cache-archive contract
// (MaxArchiveBytes), so the Store, the runner-side client and the
// control-plane upload endpoint all accept the same compressed range. A
// variable so tests can shrink it and prove an UNCONFIGURED store still
// enforces the default contract (the historical bug branched on
// MaxCacheBytes==0 and wrote unbounded archives).
var defaultCacheArchiveBytes int64 = MaxArchiveBytes

// maxStoredBytes resolves the compressed-size bound for a cache archive:
// MaxCacheBytes when configured, otherwise defaultCacheArchiveBytes.
func (s *Store) maxStoredBytes() int64 {
	if s.MaxCacheBytes > 0 {
		return s.MaxCacheBytes
	}
	return defaultCacheArchiveBytes
}

// MaxStoredBytes exposes the resolved ONE logical archive bound (configured
// MaxCacheBytes, else the shared 8 GiB default) so every consumer drives the
// same number: the local archive cap, the restore verification, the remote
// push cap and the runner's transfer preflight. Branching on the raw
// MaxCacheBytes field is what previously made an unconfigured runner
// preflight against ZERO bytes while its transfers were capped at 8 GiB.
func (s *Store) MaxStoredBytes() int64 {
	return s.maxStoredBytes()
}

// restoreLocal is restoreLocalWithReporter with the Store's own debt reporter.
func (s *Store) restoreLocal(ctx context.Context, key, workspace string, paths []string) (bool, error) {
	return s.restoreLocalWithReporter(ctx, key, workspace, paths, s.ReportCleanupDebt)
}

func (s *Store) restoreLocalWithReporter(ctx context.Context, key, workspace string, paths []string, report func(kind, path string, err error)) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	roots, err := cleanRoots(paths)
	if err != nil {
		return false, err
	}
	dst := s.archivePath(key)
	fi, err := os.Lstat(dst)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("cache restore: archive %q is a symlink", dst)
	}
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("cache restore: archive %q is not a regular file", dst)
	}
	bound := s.maxStoredBytes()
	if fi.Size() > bound {
		return false, fmt.Errorf("cache restore: archive is %d bytes, exceeds the %d-byte bound", fi.Size(), bound)
	}
	// Bind the key-addressed archive to its content before anything is
	// extracted: the cache key hashes the cache inputs, not the archive, so
	// the sidecar written by Save is the only binding. A missing sidecar is
	// unverifiable and fails closed; a mismatching digest is an integrity
	// failure.
	want, err := s.readStoredDigest(key)
	if err != nil {
		return false, err
	}
	f, err := os.Open(dst)
	if err != nil {
		return false, err
	}
	defer f.Close()
	// Verification reads through the context reader: a multi-gigabyte local
	// archive must not keep hashing after the job deadline.
	h := sha256.New()
	n, err := copyCacheDigest(h, safefs.NewContextReader(ctx, io.LimitReader(f, bound+1)))
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return false, cerr
		}
		return false, fmt.Errorf("cache restore: hash archive: %w", err)
	}
	if n > bound {
		return false, fmt.Errorf("cache restore: archive exceeds the %d-byte bound", bound)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return false, fmt.Errorf("cache restore: archive digest %s does not match stored digest %s", got, want)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, fmt.Errorf("cache restore: rewind archive: %w", err)
	}
	root, err := openExtractRoot(workspace)
	if err != nil {
		return false, err
	}
	defer root.Close()
	// Make the restriction explicit: "." is the deliberate whole-root choice
	// and is the only thing that maps to safefs AllowAll. Any other list is
	// passed verbatim as Allowed; an empty list therefore restores nothing
	// instead of silently extracting the whole archive.
	limits := safefs.DefaultLimits()
	limits.AllowAll = len(roots) == 1 && roots[0] == "."
	if !limits.AllowAll {
		limits.Allowed = roots
	}
	limits.MaxArchiveBytes = bound
	// Restores are transactional: the archive is extracted into a fresh
	// job-private staging directory that is a SIBLING of the workspace root
	// (same filesystem as every publish destination, but OUTSIDE the live
	// workspace) and is only published after the whole extraction and every
	// collision check succeeded. The live workspace is therefore untouched
	// until every archive member has validated and the pre-check passed.
	// Extraction streams through the context reader too: a large archive
	// stops being unpacked when the job context ends instead of finishing
	// its filesystem walk under a dead deadline.
	stageDir, stage, err := createCacheStage(root.Canonical)
	if err != nil {
		return false, err
	}
	if _, err := extractCacheArchive(stage, safefs.NewContextReader(ctx, f), limits); err != nil {
		_ = stage.Close()
		discardStaging(report, stageDir)
		if cerr := ctx.Err(); cerr != nil {
			return false, cerr
		}
		return false, fmt.Errorf("cache restore: %w", err)
	}
	// Close the staging handle before any cleanup: Windows cannot remove an
	// open directory.
	if err := stage.Close(); err != nil {
		discardStaging(report, stageDir)
		return false, fmt.Errorf("cache restore: close staging directory: %w", err)
	}
	entries, err := collectStagedEntries(stageDir)
	if err != nil {
		discardStaging(report, stageDir)
		return false, fmt.Errorf("cache restore: %w", err)
	}
	if err := ctx.Err(); err != nil {
		discardStaging(report, stageDir)
		return false, err
	}
	// Nothing before this point touched the live workspace; publishStaged
	// pre-checks every destination path and rolls back every path it created
	// on failure, so a restore error leaves the workspace byte-for-byte
	// unchanged (no new files, no removed files, no overwritten files). A
	// rollback that could not remove every path is FIRST CLASS: the typed
	// error names the residue, the caller is told the workspace may contain
	// partially restored files, and every residue path is reported as
	// cleanup debt.
	if err := publishStaged(root, stageDir, entries); err != nil {
		var residue *PublishRollbackError
		if errors.As(err, &residue) {
			for _, rel := range residue.Remaining {
				reportCleanupDebt(report, CleanupKindRestoreRollback, filepath.Join(root.Canonical, filepath.FromSlash(rel)), residue)
			}
		}
		discardStaging(report, stageDir)
		return false, fmt.Errorf("cache restore: %w", err)
	}
	// Publication succeeded: the restored files are live and the restore is a
	// SUCCESS. A staging tree that cannot be removed is cleanup debt, never a
	// restore failure (it lives outside the workspace, so it cannot affect
	// the job), and the removal error is reported instead of discarded.
	if rerr := removeStagingDir(stageDir); rerr != nil {
		reportCleanupDebt(report, CleanupKindStagingResidue, stageDir, rerr)
	}
	return true, nil
}

// cacheStagePrefix names the job-private staging directory a local cache
// restore extracts into before publishing. The staging directory is created
// as a SIBLING of the workspace root (same parent directory, hence the same
// filesystem as every publish destination) so every publish rename is a
// same-filesystem atomic move while the live workspace stays untouched until
// publication.
const cacheStagePrefix = ".kiwi-cache-stage-"

// createCacheStage creates the restore staging directory as a SIBLING of
// workspaceCanonical and opens it as an extraction root. The parent must be a
// real directory: it is opened through the no-follow root API first, which
// rejects a symlinked parent and resolves the canonical path, and the staging
// directory is created there with os.MkdirTemp (its random suffix keeps the
// tree private to this restore). An unwritable or symlinked parent is a clean
// error: there is deliberately NO fallback that stages inside the live
// workspace, because that would break the "workspace is untouched until
// publication" invariant.
func createCacheStage(workspaceCanonical string) (string, *safefs.Root, error) {
	parent := filepath.Dir(workspaceCanonical)
	anchor, err := safefs.OpenRootNoFollow(parent)
	if err != nil {
		return "", nil, fmt.Errorf("cache restore: open staging parent %q: %w", parent, err)
	}
	canonicalParent := anchor.Canonical
	if err := anchor.Close(); err != nil {
		return "", nil, fmt.Errorf("cache restore: close staging parent %q: %w", parent, err)
	}
	dir, err := os.MkdirTemp(canonicalParent, cacheStagePrefix+"*")
	if err != nil {
		return "", nil, fmt.Errorf("cache restore: create staging directory in %q: %w", canonicalParent, err)
	}
	stage, err := safefs.OpenRootNoFollow(dir)
	if err != nil {
		if rerr := removeStagingDir(dir); rerr != nil {
			return "", nil, fmt.Errorf("cache restore: open staging directory %q: %w (leftover removal also failed: %v)", dir, err, rerr)
		}
		return "", nil, fmt.Errorf("cache restore: open staging directory %q: %w", dir, err)
	}
	return dir, stage, nil
}

// PublishRollbackError reports a failed publish whose rollback could not
// remove every path the publish had already created. Remaining lists exactly
// the workspace-relative paths that survived the rollback pass: the live
// workspace therefore contains partially restored files and the job must fail
// rather than run against a hybrid tree. PublishErr is the original publish
// failure; RollbackErr aggregates every removal error (errors.Join).
type PublishRollbackError struct {
	PublishErr  error
	RollbackErr error
	Remaining   []string
}

func (e *PublishRollbackError) Error() string {
	return fmt.Sprintf("publish failed (%v); rollback could not remove %d path(s) [%s] (%v); the workspace may contain partially restored files",
		e.PublishErr, len(e.Remaining), strings.Join(e.Remaining, ", "), e.RollbackErr)
}

// Unwrap exposes the original publish failure to errors.Is/As callers.
func (e *PublishRollbackError) Unwrap() error { return e.PublishErr }

// stagedEntry is one directory or regular file extracted into the staging
// tree, identified by its workspace-relative slash path.
type stagedEntry struct {
	rel   string
	isDir bool
}

// collectStagedEntries walks the staging tree without following symlinks and
// returns every entry parent-first (a directory always precedes its
// children, so publishing creates parents before their contents). Extraction
// only ever writes real directories and O_EXCL regular files, so any other
// entry type is rejected as an invariant violation instead of being
// published.
func collectStagedEntries(stageDir string) ([]stagedEntry, error) {
	var out []stagedEntry
	var walk func(rel string) error
	walk = func(rel string) error {
		dir := stageDir
		if rel != "" {
			dir = filepath.Join(stageDir, filepath.FromSlash(rel))
		}
		items, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name() < items[j].Name() })
		for _, item := range items {
			child := item.Name()
			if rel != "" {
				child = rel + "/" + item.Name()
			}
			info, err := item.Info()
			if err != nil {
				return err
			}
			mode := info.Mode()
			if mode&os.ModeSymlink != 0 {
				return fmt.Errorf("staging entry %q is a symlink", child)
			}
			if mode.IsDir() {
				out = append(out, stagedEntry{rel: child, isDir: true})
				if err := walk(child); err != nil {
					return err
				}
				continue
			}
			if !mode.IsRegular() {
				return fmt.Errorf("staging entry %q is not a regular file", child)
			}
			out = append(out, stagedEntry{rel: child})
		}
		return nil
	}
	if err := walk(""); err != nil {
		return nil, err
	}
	return out, nil
}

// publishStaged moves every staged entry into the destination workspace,
// which must be the opened extract root whose sibling holds the staging tree.
//
// Merge-safe, overwrite-hostile semantics: a cache is routinely restored OVER
// an existing repository checkout, so an existing destination DIRECTORY is
// merged (the staged directory reuses it and the restore continues inside).
// Everything else is a collision detected up front, before a single entry
// moves: an existing regular file/symlink/special where the archive stages a
// file or a directory, and an existing regular file where the archive stages
// a directory. Nothing ever overwrites a pre-existing path, and the
// workspace stays byte-for-byte unchanged on any error whose rollback
// completes.
//
// Entries are published parent-first: files are renamed from the staging tree
// (atomic within one filesystem) and only the directories extraction created
// are recreated at the destination with their extracted mode. Every
// destination path this publish CREATES is tracked, and any failure rolls
// those paths back in reverse order; pre-existing directories are never
// tracked, so a mid-publish failure cannot delete workspace content that was
// already there.
//
// Rollback is FIRST CLASS: every removal error is captured (never `_ =`), a
// path is reported as residue only if it still exists after the whole
// rollback pass (a parent's RemoveAll can have removed a child whose own
// removal failed), and if anything survives, the returned error is a
// *PublishRollbackError naming exactly those paths.
//
// Every destination parent is re-verified through safefs.OpenRootBeneath,
// which walks each component relative to the held root descriptor with
// O_NOFOLLOW and rejects a symlink anywhere in the chain exactly like
// extraction does.
func publishStaged(dst *safefs.Root, stageDir string, entries []stagedEntry) error {
	// Pre-check: reject overwrites before anything moves. Existing
	// directories are legal merge points only for staged directories; every
	// other pre-existing destination is a collision.
	for _, e := range entries {
		p := filepath.Join(dst.Canonical, filepath.FromSlash(e.rel))
		fi, err := os.Lstat(p)
		switch {
		case err == nil:
			if e.isDir && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
				continue // merge into the existing real directory
			}
			return fmt.Errorf("publish destination %q already exists", e.rel)
		case !os.IsNotExist(err):
			return fmt.Errorf("publish destination %q: %w", e.rel, err)
		}
	}
	created := make([]stagedEntry, 0, len(entries))
	// rollback removes every path this publish created, newest first. It
	// returns the relative paths that STILL EXIST afterwards together with
	// the aggregate removal error, so no removal failure is discarded and
	// the residue list is exact.
	rollback := func() ([]string, error) {
		var remaining []string
		var errs []error
		for i := len(created) - 1; i >= 0; i-- {
			p := filepath.Join(dst.Canonical, filepath.FromSlash(created[i].rel))
			var err error
			if created[i].isDir {
				// Only directories this publish created are tracked, so
				// RemoveAll cannot delete pre-existing workspace content.
				err = removeAllFn(p)
			} else {
				err = removeFn(p)
			}
			if err != nil && !os.IsNotExist(err) {
				remaining = append(remaining, created[i].rel)
				errs = append(errs, fmt.Errorf("rollback %q: %w", created[i].rel, err))
			}
		}
		// A later RemoveAll of a created parent can have removed a child
		// whose individual removal failed; verify what actually survived so
		// the residue list names exactly the live paths.
		if len(remaining) > 0 {
			survived := remaining[:0]
			for _, rel := range remaining {
				if _, err := os.Lstat(filepath.Join(dst.Canonical, filepath.FromSlash(rel))); err == nil || !os.IsNotExist(err) {
					survived = append(survived, rel)
				}
			}
			remaining = survived
		}
		return remaining, errors.Join(errs...)
	}
	fail := func(cause error) error {
		remaining, rerr := rollback()
		if len(remaining) == 0 {
			return cause
		}
		return &PublishRollbackError{PublishErr: cause, RollbackErr: rerr, Remaining: remaining}
	}
	for _, e := range entries {
		parent, err := safefs.OpenRootBeneath(dst, path.Dir(e.rel))
		if err != nil {
			return fail(fmt.Errorf("publish %q: %w", e.rel, err))
		}
		if err := parent.Close(); err != nil {
			return fail(fmt.Errorf("publish %q: %w", e.rel, err))
		}
		dest := filepath.Join(dst.Canonical, filepath.FromSlash(e.rel))
		if e.isDir {
			// The pre-check established that dest is either absent or an
			// existing real directory. Re-check under the no-follow parent:
			// a racing or swapped entry is a collision, never a merge.
			if fi, err := os.Lstat(dest); err == nil {
				if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
					continue
				}
				return fail(fmt.Errorf("publish destination %q already exists", e.rel))
			} else if !os.IsNotExist(err) {
				return fail(fmt.Errorf("publish %q: %w", e.rel, err))
			}
			if err := os.Mkdir(dest, 0o755); err != nil {
				return fail(fmt.Errorf("publish %q: %w", e.rel, err))
			}
		} else {
			src := filepath.Join(stageDir, filepath.FromSlash(e.rel))
			if err := renameFn(src, dest); err != nil {
				return fail(fmt.Errorf("publish %q: %w", e.rel, err))
			}
		}
		created = append(created, e)
	}
	return nil
}

// openExtractRoot opens the cache extraction destination without following a
// symlink in any component from the first existing ancestor down to the
// destination, creating the missing components one at a time relative to a
// held descriptor (safefs.OpenRootBeneath). OpenRootNoFollow alone only
// rejects a symlink in the FINAL component, so a destination reached through
// a symlinked parent (for example `link -> /tmp/outside` and a workspace of
// `link/ws`) would otherwise open a root outside the intended tree. Existing
// symlinks in the resolved prefix above the first missing component are
// followed as ordinary path resolution (matching the OS and the rest of the
// codebase).
func openExtractRoot(workspace string) (*safefs.Root, error) {
	clean := filepath.Clean(workspace)
	if clean == "" || clean == "." {
		return nil, fmt.Errorf("cache restore: empty workspace destination")
	}
	var missing []string
	for {
		fi, err := os.Lstat(clean)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("cache restore: destination %q is a symlink", clean)
			}
			if !fi.IsDir() {
				return nil, fmt.Errorf("cache restore: destination component %q is not a directory", clean)
			}
			break
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		parent := filepath.Dir(clean)
		if parent == clean {
			return nil, err
		}
		missing = append([]string{filepath.Base(clean)}, missing...)
		clean = parent
	}
	anchor, err := safefs.OpenRootNoFollow(clean)
	if err != nil {
		return nil, fmt.Errorf("cache restore: open destination root: %w", err)
	}
	root, err := safefs.OpenRootBeneath(anchor, strings.Join(missing, "/"))
	if cerr := anchor.Close(); err != nil {
		return nil, fmt.Errorf("cache restore: %w", err)
	} else if cerr != nil {
		return nil, cerr
	}
	return root, nil
}

// Save is SaveContext with the Store's default context. That context carries
// no total wall-clock deadline: the upload may run for as long as it keeps
// making progress. A direct call cannot hang because the default client's
// transport bounds every control phase and the sliding storeStallTimeout
// watchdog cancels a body that stops making progress with ErrTransferStalled.
// Callers that need an absolute wall-clock bound supply their own context to
// SaveContext.
func (s *Store) Save(key, workspace string, paths []string) error {
	ctx, cancel := s.defaultContext()
	defer cancel()
	return s.SaveContext(ctx, key, workspace, paths)
}

// SaveContext captures workspace paths into the local store and, when
// RemoteURL is set, uploads the archive. The bound is the SAME
// maxStoredBytes() contract the restore path and the remote push enforce
// (configured MaxCacheBytes, else the 8 GiB default), so a locally produced
// archive can never exceed what Kiwi itself will upload or restore. The
// context bounds the local archive traversal/writes as well as every remote
// (HTTP) phase: a job deadline stops a long compression pass promptly and
// the partial file is removed instead of finishing an archive whose upload
// can no longer happen.
func (s *Store) SaveContext(ctx context.Context, key, workspace string, paths []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validKey(key) {
		return fmt.Errorf("cache: invalid cache key")
	}
	bound := s.maxStoredBytes()
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return err
	}
	// Aggregate admission first: the manager evicts cold entries until the
	// worst-case archive fits, so the published tree can never exceed the
	// runner-wide budget even when every job uses its own Store. The charge
	// is released only after the archive is published (or the save failed),
	// and retained bytes are measured from the directory itself, so a failed
	// cleanup keeps occupying the budget.
	var reservation *Reservation
	if s.Manager != nil {
		res, rerr := s.Manager.Reserve(ctx, bound)
		if rerr != nil {
			return rerr
		}
		reservation = res
		defer reservation.Release()
	}
	if err := safefs.FitsAvailable(s.Root, bound); err != nil {
		return err
	}
	root, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return err
	}
	defer root.Close()
	dst := s.archivePath(key)
	// Stage into a UNIQUE temp file in the store root, fsync and
	// checked-close it, rename it into place, fsync the directory and only
	// then record the stored digest: the same crash-durability sequence as
	// fsutil.AtomicWriteFile for a streamed archive. A fixed ".tmp" name
	// would let concurrent saves clobber each other's scratch file.
	f, err := os.CreateTemp(s.Root, "."+key+".tar.gz-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(f, h)}
	// Order matters: the cap wraps the context writer so the recorded bytes
	// are exactly those that reached the file, and the context is checked
	// before each write (per tar entry/chunk).
	w := safefs.NewCappedWriter(safefs.NewContextWriter(ctx, cw), bound)
	if err := safefs.WriteTarGzFromRoot(w, root, paths); err != nil {
		_ = f.Close()
		s.discardTemp(tmp, reservation)
		return err
	}
	syncErr := syncCacheFile(f)
	closeErr := closeCacheFile(f)
	if syncErr != nil || closeErr != nil {
		s.discardTemp(tmp, reservation)
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	// The rename and every step that makes the entry durable happen under
	// the manager lock (when configured): the entry becomes visible and
	// retained before any concurrent reservation can evict it, and the
	// worst-case reservation is retired at the same instant instead of
	// double-counting against it.
	publish := func() error {
		if err := renameCacheFile(tmp, dst); err != nil {
			return err
		}
		if err := fsutil.SyncDir(s.Root); err != nil {
			_ = os.Remove(dst)
			return fmt.Errorf("cache save: sync archive directory: %w", err)
		}
		if err := s.writeStoredDigest(key, hex.EncodeToString(h.Sum(nil))); err != nil {
			_ = os.Remove(dst)
			return err
		}
		return nil
	}
	var publishErr error
	if s.Manager != nil {
		publishErr = s.Manager.Publish(reservation, publish)
	} else {
		publishErr = publish()
	}
	if publishErr != nil {
		s.discardTemp(tmp, reservation)
		return publishErr
	}
	// Enforce the aggregate retention policy after every committed save: the
	// local tree must not wait for the periodic maintenance pass to notice
	// that the caps are exceeded. Pruning is best-effort (a removal failure
	// stays accounted for the next pass) and never fails the save. It runs
	// under the JOB context, never a fresh Background one: if the deadline
	// already ended, the dedicated maintenance pass finishes retention later
	// instead of holding the runner slot.
	if s.Manager == nil && s.Retention.Active() {
		_, _ = s.Prune(ctx)
	}
	if s.RemoteURL != "" {
		if err := s.pushRemoteContext(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

// discardTemp removes an aborted operation's temp file. With a manager
// configured, a failed removal keeps the reservation as cleanup debt (the
// file still occupies disk and stays counted against the budget) instead of
// returning the charge; Manager.RetryTempCleanup retries it from the
// runner's maintenance pass.
func (s *Store) discardTemp(tmp string, res *Reservation) {
	if tmp == "" {
		return
	}
	if err := removeCacheTemp(tmp); err != nil && !os.IsNotExist(err) {
		if s.Manager != nil {
			s.Manager.RetainTempCleanup(res, tmp)
		}
	}
}

func (s *Store) client() *http.Client {
	if s.Client != nil {
		c := *s.Client
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &c
	}
	return &http.Client{
		Transport:     defaultTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (s *Store) fetchRemote(key string) error {
	ctx, cancel := s.defaultContext()
	defer cancel()
	return s.fetchRemoteContext(ctx, key)
}

func (s *Store) fetchRemoteContext(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validKey(key) {
		return fmt.Errorf("cache: invalid cache key")
	}
	// The watchdog is the Store's own enforcement: it is layered over the
	// caller's context and whatever bounds the client has, so a stalled
	// download fails even when the client carries no total timeout.
	reqCtx, guard := newStoreStallGuard(ctx, storeStallTimeout)
	defer guard.release()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, s.RemoteURL+"/api/v1/cache/"+key, nil)
	if err != nil {
		return err
	}
	s.auth(req)
	resp, err := s.client().Do(req)
	if err != nil {
		return stallError(ctx, guard, err)
	}
	body := &stallGuardedBody{ReadCloser: resp.Body, guard: guard}
	defer body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errRemoteNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, rerr := io.ReadAll(io.LimitReader(body, 4096))
		if rerr != nil {
			return stallError(ctx, guard, rerr)
		}
		return fmt.Errorf("cache download %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return err
	}
	// The download is bounded to the same compressed-size bound the local
	// store enforces, so a hostile or broken endpoint cannot make the runner
	// stream unbounded bytes to disk. The bytes are hashed while they are
	// copied, and when the endpoint advertises X-Kiwi-Cache-SHA256 the digest
	// must match before the archive is published under the key. (The runner's
	// cacheTransport already verifies inside cache.Client; verifying again
	// here defends callers that talk to the legacy route directly. An absent
	// header is not an integrity claim for this "decode key, then authorize
	// payload" endpoint.)
	// Aggregate admission BEFORE the download writes bytes: the manager
	// evicts cold entries until the worst case fits, which is exactly what
	// keeps a sequence of remote restores (up to 16 per job) from blowing
	// past the runner cache budget between maintenance passes. The exact
	// Content-Length is used when the endpoint advertises it.
	bound := s.maxStoredBytes()
	var reservation *Reservation
	if s.Manager != nil {
		expected := bound
		if resp.ContentLength > 0 {
			expected = resp.ContentLength
		}
		res, rerr := s.Manager.Reserve(ctx, expected)
		if rerr != nil {
			return rerr
		}
		reservation = res
		defer reservation.Release()
	}
	f, err := os.CreateTemp(s.Root, "."+key+".remote-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	h := sha256.New()
	n, cp := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, bound+1))
	if cp == nil && n > bound {
		cp = fmt.Errorf("cache download exceeds %d compressed bytes", bound)
	}
	syncErr := syncCacheFile(f)
	cl := closeCacheFile(f)
	if cp != nil {
		s.discardTemp(tmp, reservation)
		return stallError(ctx, guard, cp)
	}
	if syncErr != nil {
		s.discardTemp(tmp, reservation)
		return syncErr
	}
	if cl != nil {
		s.discardTemp(tmp, reservation)
		return cl
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if want := strings.TrimSpace(resp.Header.Get(HeaderCacheSHA256)); want != "" && want != digest {
		s.discardTemp(tmp, reservation)
		return fmt.Errorf("cache download digest mismatch: got %s, want %s", digest, want)
	}
	// Publish under the manager lock (when configured) so the fetched entry
	// is visible/retained before any concurrent reservation can evict it and
	// so the worst-case reservation is retired atomically with publication.
	publish := func() error {
		if err := renameCacheFile(tmp, s.archivePath(key)); err != nil {
			return err
		}
		if err := fsutil.SyncDir(s.Root); err != nil {
			_ = os.Remove(s.archivePath(key))
			return fmt.Errorf("cache download: sync archive directory: %w", err)
		}
		if err := s.writeStoredDigest(key, digest); err != nil {
			_ = os.Remove(s.archivePath(key))
			return err
		}
		return nil
	}
	var publishErr error
	if s.Manager != nil {
		publishErr = s.Manager.Publish(reservation, publish)
	} else {
		publishErr = publish()
	}
	if publishErr != nil {
		s.discardTemp(tmp, reservation)
		return publishErr
	}
	return nil
}

func (s *Store) pushRemote(key string) error {
	ctx, cancel := s.defaultContext()
	defer cancel()
	return s.pushRemoteContext(ctx, key)
}

func (s *Store) pushRemoteContext(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validKey(key) {
		return fmt.Errorf("cache: invalid cache key")
	}
	archive := filepath.Join(s.Root, key+".tar.gz")
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	// The watchdog wraps the upload body, so the transfer is canceled when
	// the transport stops pulling bytes (peer backpressure) or the server
	// stops responding.
	reqCtx, guard := newStoreStallGuard(ctx, storeStallTimeout)
	defer guard.release()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPut, s.RemoteURL+"/api/v1/cache/"+key, &stallGuardReader{r: f, guard: guard})
	if err != nil {
		return err
	}
	// The wrapped body defeats net/http's *os.File length detection, so set
	// the length explicitly to keep the upload a fixed-length body (a chunked
	// body would make the server reserve the full cap before staging).
	req.ContentLength = fi.Size()
	s.auth(req)
	resp, err := s.client().Do(req)
	if err != nil {
		return stallError(ctx, guard, err)
	}
	body := &stallGuardedBody{ReadCloser: resp.Body, guard: guard}
	defer body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, rerr := io.ReadAll(io.LimitReader(body, 4096))
		if rerr != nil {
			return stallError(ctx, guard, rerr)
		}
		return fmt.Errorf("cache upload %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (s *Store) auth(req *http.Request) {
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
}

// cleanRoots validates and normalizes cache restore path restrictions. It
// rejects empty entries, portable absolute paths (Unix "/..." and Windows
// "C:..." shapes), any ".." component, backslashes and NUL bytes, and
// returns the cleaned slash form otherwise. "." is the deliberate whole-root
// choice: it is returned as the sole element so the caller can opt into
// safefs AllowAll explicitly. An empty input yields an empty (non-nil) list,
// which extraction treats as "write nothing". Invalid restrictions are an
// error; they are never silently dropped into an empty list.
func cleanRoots(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p == "" {
			return nil, fmt.Errorf("cache restore: empty path restriction")
		}
		if strings.ContainsRune(p, '\x00') {
			return nil, fmt.Errorf("cache restore: NUL byte in path restriction %q", p)
		}
		if strings.Contains(p, "\\") {
			return nil, fmt.Errorf("cache restore: backslash in path restriction %q", p)
		}
		if portableAbsPath(p) {
			return nil, fmt.Errorf("cache restore: absolute path restriction %q", p)
		}
		// Reject every raw ".." component, not just the ones that survive
		// path.Clean: an input that merely hides one behind a preceding
		// component is still an invalid restriction.
		for _, comp := range strings.Split(p, "/") {
			if comp == ".." {
				return nil, fmt.Errorf("cache restore: parent traversal in path restriction %q", p)
			}
		}
		clean := path.Clean(p)
		if clean == "." {
			return []string{"."}, nil
		}
		out = append(out, clean)
	}
	return out, nil
}

// portableAbsPath reports whether p is absolute in the portable path shapes
// this codebase accepts: a leading slash, or a Windows drive designator
// ("C:") followed by a separator. Backslash forms are rejected separately.
func portableAbsPath(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '/' || p[2] == '\\') {
		c := p[0]
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	return false
}
