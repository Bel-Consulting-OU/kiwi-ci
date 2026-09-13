package artifact

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Store struct{ Root string }

func Default() *Store {
	home, _ := os.UserHomeDir()
	return &Store{Root: filepath.Join(home, ".kiwi", "artifacts")}
}

func (s *Store) Save(runID, jobID, name, workspace string, paths []string) (string, error) {
	dir := filepath.Join(s.Root, safe(runID), safe(jobID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, safe(name)+".tar.gz")
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	for _, p := range paths {
		matches, _ := filepath.Glob(filepath.Join(workspace, p))
		for _, m := range matches {
			err := filepath.Walk(m, func(path string, fi os.FileInfo, e error) error {
				if e != nil {
					return e
				}
				rel, e := filepath.Rel(workspace, path)
				if e != nil || strings.HasPrefix(rel, "..") {
					return e
				}
				h, e := tar.FileInfoHeader(fi, "")
				if e != nil {
					return e
				}
				h.Name = filepath.ToSlash(rel)
				if e = tw.WriteHeader(h); e != nil {
					return e
				}
				if fi.Mode().IsRegular() {
					rf, e := os.Open(path)
					if e != nil {
						return e
					}
					_, e = io.Copy(tw, rf)
					rf.Close()
					return e
				}
				return nil
			})
			if err != nil {
				return "", err
			}
		}
	}
	return dst, nil
}
func safe(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "..", "_")
	if s == "" {
		return "unnamed"
	}
	return s
}

// Extract restores a tar.gz artifact under dest, rejecting any entry that
// resolves outside the destination directory.
func Extract(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, filepath.Clean(h.Name))
		rel, err := filepath.Rel(dest, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe artifact path %q", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode))
			if err != nil {
				return err
			}
			_, err = io.Copy(out, tr)
			out.Close()
			if err != nil {
				return err
			}
		}
	}
}
