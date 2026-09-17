package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

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

func (s *Store) Restore(key, workspace string, paths []string) (bool, error) {
	if !validKey(key) {
		return false, fmt.Errorf("cache: invalid cache key")
	}
	hit, err := s.restoreLocal(key, workspace, paths)
	if err != nil || hit {
		return hit, err
	}
	if s.RemoteURL == "" {
		return false, nil
	}
	if err := s.fetchRemote(key); err != nil {
		if err == errRemoteNotFound {
			return false, nil
		}
		return false, err
	}
	return s.restoreLocal(key, workspace, paths)
}

var errRemoteNotFound = fmt.Errorf("cache entry not found on remote")

// closeCacheFile and copyCacheDigest are test-only seams over os.File.Close
// and io.Copy. Production behavior is unchanged; they let the checked
// close-failure and copy-failure branches be exercised.
var (
	closeCacheFile  = (*os.File).Close
	copyCacheDigest = io.Copy
)

func (s *Store) restoreLocal(key, workspace string, paths []string) (bool, error) {
	f, err := os.Open(filepath.Join(s.Root, key+".tar.gz"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return false, fmt.Errorf("cache restore: %w", err)
	}
	root, err := safefs.OpenRootNoFollow(workspace)
	if err != nil {
		return false, fmt.Errorf("cache restore: %w", err)
	}
	defer root.Close()
	limits := safefs.DefaultLimits()
	limits.Allowed = cleanRoots(paths)
	if _, err := safefs.Extract(root, f, limits); err != nil {
		return false, fmt.Errorf("cache restore: %w", err)
	}
	return true, nil
}

func (s *Store) Save(key, workspace string, paths []string) error {
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
	tmp := filepath.Join(s.Root, key+".tmp")
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	var w io.Writer = f
	if s.MaxCacheBytes > 0 {
		w = safefs.NewCappedWriter(f, s.MaxCacheBytes)
	}
	if err := safefs.WriteTarGzFromRoot(w, root, paths); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := closeCacheFile(f); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.Root, key+".tar.gz")); err != nil {
		return err
	}
	if s.RemoteURL != "" {
		if err := s.pushRemote(key); err != nil {
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
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (s *Store) fetchRemote(key string) error {
	if !validKey(key) {
		return fmt.Errorf("cache: invalid cache key")
	}
	req, err := http.NewRequest(http.MethodGet, s.RemoteURL+"/api/v1/cache/"+key, nil)
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
	tmp := filepath.Join(s.Root, key+".remote.tmp")
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, cp := io.Copy(f, resp.Body)
	cl := closeCacheFile(f)
	if cp != nil {
		_ = os.Remove(tmp)
		return cp
	}
	if cl != nil {
		_ = os.Remove(tmp)
		return cl
	}
	return os.Rename(tmp, filepath.Join(s.Root, key+".tar.gz"))
}

func (s *Store) pushRemote(key string) error {
	if !validKey(key) {
		return fmt.Errorf("cache: invalid cache key")
	}
	path := filepath.Join(s.Root, key+".tar.gz")
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	req, err := http.NewRequest(http.MethodPut, s.RemoteURL+"/api/v1/cache/"+key, f)
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

func cleanRoots(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = filepath.ToSlash(filepath.Clean(p))
		if p != "." && !strings.HasPrefix(p, "../") {
			out = append(out, p)
		}
	}
	return out
}
