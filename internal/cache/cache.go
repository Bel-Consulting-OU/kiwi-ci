package cache

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Store is a content-addressed cache archive store. When RemoteURL is set the
// local cache transparently falls back to (restore) and mirrors (save) the
// control plane's cache endpoints, authenticated with the runner token.
type Store struct {
	Root      string
	RemoteURL string
	Token     string
	Client    *http.Client
}

func Default() *Store {
	home, _ := os.UserHomeDir()
	return &Store{Root: filepath.Join(home, ".kiwi", "cache")}
}

func (s *Store) Key(base string, workspace string, hashFiles []string) (string, error) {
	h := sha256.New()
	io.WriteString(h, base)
	io.WriteString(h, "\x00")
	var files []string
	for _, p := range hashFiles {
		matches, _ := filepath.Glob(filepath.Join(workspace, p))
		files = append(files, matches...)
	}
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		rel, _ := filepath.Rel(workspace, f)
		io.WriteString(h, rel)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Store) Restore(key, workspace string, paths []string) (bool, error) {
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

func (s *Store) restoreLocal(key, workspace string, paths []string) (bool, error) {
	f, err := os.Open(filepath.Join(s.Root, key+".tar.gz"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	allowed := cleanRoots(paths)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}
		target := filepath.Join(workspace, filepath.Clean(h.Name))
		if !within(target, workspace) {
			return false, fmt.Errorf("unsafe cache path %q", h.Name)
		}
		if !underAllowed(h.Name, allowed) {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0o755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(target), 0o755)
			out, e := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode))
			if e != nil {
				return false, e
			}
			_, e = io.Copy(out, tr)
			out.Close()
			if e != nil {
				return false, e
			}
		}
	}
	return true, nil
}

func (s *Store) Save(key, workspace string, paths []string) error {
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(s.Root, key+".tmp")
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	fail := func(e error) error { tw.Close(); gz.Close(); f.Close(); os.Remove(tmp); return e }
	for _, p := range paths {
		abs := filepath.Join(workspace, p)
		info, err := os.Stat(abs)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fail(err)
		}
		root := abs
		err = filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(workspace, path)
			if err != nil {
				return err
			}
			if strings.HasPrefix(rel, "..") {
				return nil
			}
			h, err := tar.FileInfoHeader(fi, "")
			if err != nil {
				return err
			}
			h.Name = filepath.ToSlash(rel)
			if err := tw.WriteHeader(h); err != nil {
				return err
			}
			if fi.Mode().IsRegular() {
				rf, err := os.Open(path)
				if err != nil {
					return err
				}
				_, err = io.Copy(tw, rf)
				rf.Close()
				return err
			}
			return nil
		})
		_ = info
		if err != nil {
			return fail(err)
		}
	}
	if err := tw.Close(); err != nil {
		return fail(err)
	}
	if err := gz.Close(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		return fail(err)
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
		return s.Client
	}
	return http.DefaultClient
}

func (s *Store) fetchRemote(key string) error {
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
	cl := f.Close()
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
func underAllowed(name string, roots []string) bool {
	name = filepath.ToSlash(filepath.Clean(name))
	for _, r := range roots {
		if name == r || strings.HasPrefix(name, r+"/") {
			return true
		}
	}
	return false
}
func within(target, root string) bool {
	r, err := filepath.Rel(root, target)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}
