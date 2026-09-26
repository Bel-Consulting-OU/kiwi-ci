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

// defaultAPITimeout is the finite bound the legacy Store.Restore/Save
// wrappers (and the unexported fetchRemote/pushRemote entry points) apply
// when the Store has no caller-supplied HTTP client. It is a total deadline
// for the convenience path only: callers that need bulk transfers or their
// own lifetime must use RestoreContext/SaveContext (or configure Client, as
// the runner does with its streaming+stall transport).
const defaultAPITimeout = 30 * time.Second

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

// defaultContext is the context the legacy wrapper methods use. A
// caller-supplied Client owns its own bounds (the runner configures a
// streaming transport with per-request stall guards), so the wrappers defer
// to it with a background context; otherwise they apply the explicit finite
// defaultAPITimeout so direct use can never hang forever.
func (s *Store) defaultContext() (context.Context, context.CancelFunc) {
	if s.Client != nil {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), defaultAPITimeout)
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
// defaultAPITimeout applies so a direct call cannot hang forever. Use
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

// Save is SaveContext with the Store's default context: a caller-owned
// Client supplies its own bounds, otherwise an explicit finite
// defaultAPITimeout applies so a direct call cannot hang forever.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.RemoteURL+"/api/v1/cache/"+key, nil)
	if err != nil {
		return err
	}
	s.auth(req)
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errRemoteNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
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
	n, cp := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, bound+1))
	if cp == nil && n > bound {
		cp = fmt.Errorf("cache download exceeds %d compressed bytes", bound)
	}
	syncErr := syncCacheFile(f)
	cl := closeCacheFile(f)
	if cp != nil {
		_ = os.Remove(tmp)
		return cp
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.RemoteURL+"/api/v1/cache/"+key, f)
	if err != nil {
		return err
	}
	s.auth(req)
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
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
