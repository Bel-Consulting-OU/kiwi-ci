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
}

func Default() *Store {
	home, _ := os.UserHomeDir()
	return &Store{Root: filepath.Join(home, ".kiwi", "cache")}
}

// defaultAPITimeout is the finite total bound the legacy Store.Restore/Save
// wrappers (and the unexported fetchRemote/pushRemote entry points) apply
// when the Store has no caller-supplied HTTP client. It is a total deadline
// for the convenience path only: callers that need bulk transfers or their
// own lifetime must use RestoreContext/SaveContext (or configure Client, as
// the runner does). It is layered UNDER the sliding storeStallTimeout
// watchdog, which bounds every remote body in both paths.
const defaultAPITimeout = 30 * time.Second

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

// defaultContext is the context the legacy wrapper methods use. The bound is
// layered, and no layer imposes a total-duration cap on a transfer that keeps
// making progress:
//
//   - With no caller-supplied Client the wrapper carries the explicit finite
//     defaultAPITimeout (30s) for the convenience path, and the default
//     client bounds every transport phase (dial, TLS, response headers,
//     idle).
//   - With a caller-supplied Client the client's own bounds (and the
//     defaultTransport phases when it has none) apply; the context is
//     deliberately unbounded so the client owns the total policy.
//   - In BOTH cases every remote request/response body is wrapped by the
//     sliding storeStallTimeout watchdog, which is the Store's own
//     enforcement and cancels a transfer that stops making progress with
//     ErrTransferStalled.
func (s *Store) defaultContext() (context.Context, context.CancelFunc) {
	if s.Client != nil {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), defaultAPITimeout)
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
type stallGuardReader struct {
	r     io.Reader
	guard *storeStallGuard
}

func (r *stallGuardReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.guard.progress()
	}
	return n, err
}

// stallGuardedBody wraps a response body so every read re-arms the watchdog
// and Close disarms it and releases the transfer context.
type stallGuardedBody struct {
	io.ReadCloser
	guard *storeStallGuard
}

func (b *stallGuardedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.guard.progress()
	}
	return n, err
}

func (b *stallGuardedBody) Close() error {
	b.guard.release()
	return b.ReadCloser.Close()
}

// Key computes the cache key for base and the workspace's hashFiles. Every
// file is read through a held safefs.WorkspaceRoot: matches are opened
// relative to the root handle with a no-follow discipline, so a hash file
// swapped for a symlink fails the key computation instead of hashing
// content outside the workspace.
func (s *Store) Key(base string, workspace string, hashFiles []string) (string, error) {
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
		matches, _ := filepath.Glob(filepath.Join(root.Canonical, p))
		files = append(files, matches...)
	}
	sort.Strings(files)
	for _, f := range files {
		rel, _ := filepath.Rel(root.Canonical, f)
		fh, err := root.OpenRel(filepath.ToSlash(rel))
		if err != nil {
			return "", err
		}
		io.WriteString(h, rel)
		_, cpErr := copyCacheDigest(h, fh)
		fh.Close()
		if cpErr != nil {
			return "", cpErr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Restore is RestoreContext with the Store's default context: a caller-owned
// Client supplies its own bounds, otherwise an explicit finite
// defaultAPITimeout applies so a direct call cannot hang forever. In every
// case the remote body is bounded by the sliding storeStallTimeout watchdog,
// so a stalled transfer fails with ErrTransferStalled instead of hanging. Use
// RestoreContext to supply the caller's context.
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
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !validKey(key) {
		return false, fmt.Errorf("cache: invalid cache key")
	}
	hit, err := s.restoreLocal(key, workspace, paths)
	if hit {
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
	return s.restoreLocal(key, workspace, paths)
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
	copyCacheDigest = io.Copy
)

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
// configured: 8 GiB, matching the control-plane cache endpoint's upload cap,
// so a locally saved archive can never be unbounded on restore/download.
const defaultCacheArchiveBytes int64 = 8 << 30

// maxStoredBytes resolves the compressed-size bound for a cache archive:
// MaxCacheBytes when configured, otherwise defaultCacheArchiveBytes.
func (s *Store) maxStoredBytes() int64 {
	if s.MaxCacheBytes > 0 {
		return s.MaxCacheBytes
	}
	return defaultCacheArchiveBytes
}

func (s *Store) restoreLocal(key, workspace string, paths []string) (bool, error) {
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
	h := sha256.New()
	n, err := copyCacheDigest(h, io.LimitReader(f, bound+1))
	if err != nil {
		return false, fmt.Errorf("cache restore: hash archive: %w", err)
	}
	if n > bound {
		return false, fmt.Errorf("cache restore: archive exceeds the %d-byte bound", bound)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return false, fmt.Errorf("cache restore: archive digest %s does not match stored digest %s", got, want)
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
	if _, err := safefs.Extract(root, f, limits); err != nil {
		return false, fmt.Errorf("cache restore: %w", err)
	}
	return true, nil
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

// Save is SaveContext with the Store's default context: a caller-owned Client
// supplies its own bounds, otherwise an explicit finite defaultAPITimeout
// applies so a direct call cannot hang forever. In every case the remote body
// is bounded by the sliding storeStallTimeout watchdog, so a stalled upload
// fails with ErrTransferStalled instead of hanging.
func (s *Store) Save(key, workspace string, paths []string) error {
	ctx, cancel := s.defaultContext()
	defer cancel()
	return s.SaveContext(ctx, key, workspace, paths)
}

// SaveContext captures workspace paths into the local store and, when
// RemoteURL is set, uploads the archive. The context bounds every remote
// (HTTP) phase; the local archive write itself is bounded by MaxCacheBytes.
func (s *Store) SaveContext(ctx context.Context, key, workspace string, paths []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validKey(key) {
		return fmt.Errorf("cache: invalid cache key")
	}
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return err
	}
	if err := safefs.FitsAvailable(s.Root, s.MaxCacheBytes); err != nil {
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
	var w io.Writer = cw
	if s.MaxCacheBytes > 0 {
		w = safefs.NewCappedWriter(cw, s.MaxCacheBytes)
	}
	if err := safefs.WriteTarGzFromRoot(w, root, paths); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	syncErr := syncCacheFile(f)
	closeErr := closeCacheFile(f)
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	if err := renameCacheFile(tmp, dst); err != nil {
		_ = os.Remove(tmp)
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
	if s.RemoteURL != "" {
		if err := s.pushRemoteContext(ctx, key); err != nil {
			return err
		}
	}
	return nil
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
	bound := s.maxStoredBytes()
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
		_ = os.Remove(tmp)
		return stallError(ctx, guard, cp)
	}
	if syncErr != nil {
		_ = os.Remove(tmp)
		return syncErr
	}
	if cl != nil {
		_ = os.Remove(tmp)
		return cl
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if want := strings.TrimSpace(resp.Header.Get(HeaderCacheSHA256)); want != "" && want != digest {
		_ = os.Remove(tmp)
		return fmt.Errorf("cache download digest mismatch: got %s, want %s", digest, want)
	}
	if err := renameCacheFile(tmp, s.archivePath(key)); err != nil {
		_ = os.Remove(tmp)
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
