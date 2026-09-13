package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

type Store struct {
	Root             string
	MaxArtifactBytes int64
}

func Default() *Store {
	home, _ := os.UserHomeDir()
	return &Store{Root: filepath.Join(home, ".kiwi", "artifacts")}
}

// Save writes a deterministic tar.gz artifact plus a sidecar manifest
// containing the archive digest and per-entry digests. Symlinks and special
// files are never captured.
func (s *Store) Save(runID, jobID, name, workspace string, paths []string) (string, error) {
	dir := filepath.Join(s.Root, safe(runID), safe(jobID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := safefs.FitsAvailable(dir, s.MaxArtifactBytes); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, safe(name)+".tar.gz")
	f, err := os.Create(dst + ".tmp")
	if err != nil {
		return "", err
	}
	entries, err := collectEntries(workspace, paths)
	if err != nil {
		f.Close()
		_ = os.Remove(dst + ".tmp")
		return "", err
	}
	if err := safefs.WriteTarGz(f, workspace, paths, false); err != nil {
		f.Close()
		_ = os.Remove(dst + ".tmp")
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(dst + ".tmp")
		return "", err
	}
	if err := os.Rename(dst+".tmp", dst); err != nil {
		return "", err
	}
	archive, err := os.Open(dst)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	size, cpErr := io.Copy(h, archive)
	archive.Close()
	if cpErr != nil {
		return "", cpErr
	}
	m := ArtifactManifest{
		Version:   1,
		Name:      name,
		RunID:     runID,
		JobID:     jobID,
		SHA256:    hex.EncodeToString(h.Sum(nil)),
		Size:      size,
		Entries:   entries,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := s.SaveManifest(dst, m); err != nil {
		return "", err
	}
	return dst, nil
}

func collectEntries(workspace string, paths []string) ([]ArtifactEntry, error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return nil, err
	}
	var out []ArtifactEntry
	for _, p := range paths {
		abs := root
		if p != "" && p != "." {
			abs = filepath.Join(root, p)
		}
		fi, err := os.Lstat(abs)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		err = walkEntries(root, abs, fi, &out)
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func walkEntries(root, abs string, fi os.FileInfo, out *[]ArtifactEntry) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if fi.Mode().IsRegular() {
		rel, err := filepath.Rel(root, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("artifact: path escapes workspace: %q", abs)
		}
		h := sha256.New()
		f, err := os.Open(abs)
		if err != nil {
			return err
		}
		size, cpErr := io.Copy(h, f)
		f.Close()
		if cpErr != nil {
			return cpErr
		}
		*out = append(*out, ArtifactEntry{Path: filepath.ToSlash(rel), Mode: uint32(fi.Mode().Perm()), Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
		return nil
	}
	if !fi.IsDir() {
		return nil
	}
	ents, err := os.ReadDir(abs)
	if err != nil {
		return err
	}
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			return err
		}
		if err := walkEntries(root, filepath.Join(abs, e.Name()), info, out); err != nil {
			return err
		}
	}
	return nil
}

// Extract restores a tar.gz artifact under dest using the hardened safefs
// extractor: only regular files and directories, no symlink following, and
// hard resource limits.
func Extract(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := safefs.Extract(f, dest, safefs.DefaultLimits()); err != nil {
		return fmt.Errorf("artifact extract: %w", err)
	}
	return nil
}

func safe(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "..", "_")
	if s == "" {
		return "unnamed"
	}
	return s
}
