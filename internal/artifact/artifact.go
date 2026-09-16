package artifact

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
// files are never captured, capture roots that resolve outside the workspace
// are rejected, and the archive output is hard-capped at MaxArtifactBytes.
// Every workspace read goes through a held safefs.WorkspaceRoot: files are
// opened relative to the root handle (no-follow) and hashed from the
// returned descriptors, never re-opened by name, so a file swapped for a
// symlink mid-capture can never exfiltrate host content.
func (s *Store) Save(runID, jobID, name, workspace string, paths []string) (string, error) {
	wsRoot, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return "", fmt.Errorf("artifact: open workspace root: %w", err)
	}
	defer wsRoot.Close()
	if err := verifyCaptureRoots(wsRoot.Canonical, paths); err != nil {
		return "", err
	}
	dir := filepath.Join(s.Root, encodeArtifactName(runID), encodeArtifactName(jobID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := safefs.FitsAvailable(dir, s.MaxArtifactBytes); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, encodeArtifactName(name)+".tar.gz")
	f, err := os.Create(dst + ".tmp")
	if err != nil {
		return "", err
	}
	entries, err := collectEntries(wsRoot, paths)
	if err != nil {
		f.Close()
		_ = os.Remove(dst + ".tmp")
		return "", err
	}
	var w io.Writer = f
	if s.MaxArtifactBytes > 0 {
		w = safefs.NewCappedWriter(f, s.MaxArtifactBytes)
	}
	if err := safefs.WriteTarGzFromRoot(w, wsRoot, paths); err != nil {
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

// verifyCaptureRoots resolves every requested capture path (directories
// included) relative to the canonical workspace root and rejects any root
// that resolves outside the workspace. Symlinks are resolved before walking,
// so a symlinked directory input pointing outside the workspace fails here,
// before any enumeration happens.
func verifyCaptureRoots(wsRoot string, paths []string) error {
	for _, p := range paths {
		joined := wsRoot
		if p != "" && p != "." {
			joined = filepath.Join(wsRoot, p)
		}
		resolved, err := filepath.EvalSymlinks(joined)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("artifact: resolve capture path %q: %w", p, err)
		}
		if !withinWorkspace(wsRoot, resolved) {
			return fmt.Errorf("artifact: capture path %q resolves outside the workspace", p)
		}
	}
	return nil
}

func withinWorkspace(root, resolved string) bool {
	rel, err := filepath.Rel(root, resolved)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

var artifactNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// encodeArtifactName maps an arbitrary run/job/artifact name onto a safe
// filesystem path component: names already in the safe alphabet
// [A-Za-z0-9._-]{1,128} pass through unchanged, anything else is encoded
// with unpadded URL-safe base64. The original name is preserved in the
// manifest.
func encodeArtifactName(s string) string {
	if artifactNameRE.MatchString(s) {
		return s
	}
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// collectEntries walks the requested capture paths beneath the held
// workspace root and records every regular file, hashing each one from the
// descriptor returned by OpenRel (no-follow, anchored to the root handle).
// Symlinked capture roots and nested symlinks are never captured; a file
// swapped for a symlink between enumeration and open fails the collection
// instead of following the link.
func collectEntries(root *safefs.WorkspaceRoot, paths []string) ([]ArtifactEntry, error) {
	var out []ArtifactEntry
	for _, p := range paths {
		rel := p
		if rel == "" || rel == "." {
			rel = ""
		}
		if rel != "" {
			rel = filepath.ToSlash(rel)
		}
		abs := root.Canonical
		if rel != "" {
			abs = filepath.Join(root.Canonical, filepath.FromSlash(rel))
		}
		fi, err := os.Lstat(abs)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			// Symlinked capture roots are never followed or archived.
			continue
		}
		err = filepath.WalkDir(abs, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			r, err := filepath.Rel(root.Canonical, p)
			if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
				return fmt.Errorf("artifact: path escapes workspace: %q", p)
			}
			f, err := root.OpenRel(filepath.ToSlash(r))
			if err != nil {
				return err
			}
			h := sha256.New()
			size, cpErr := io.Copy(h, f)
			f.Close()
			if cpErr != nil {
				return cpErr
			}
			out = append(out, ArtifactEntry{Path: filepath.ToSlash(r), Mode: uint32(info.Mode().Perm()), Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Extract restores a tar.gz artifact under dest using the hardened safefs
// extractor: only regular files and directories, no symlink following, and
// hard resource limits. The destination directory is created if missing and
// then opened as a held no-follow root handle so extraction stays anchored
// to it.
func Extract(path, dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	root, err := safefs.OpenRootNoFollow(dest)
	if err != nil {
		return fmt.Errorf("artifact extract: %w", err)
	}
	defer root.Close()
	if _, err := safefs.Extract(root, f, safefs.DefaultLimits()); err != nil {
		return fmt.Errorf("artifact extract: %w", err)
	}
	return nil
}
