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
// opened relative to the root handle (no-follow) and the manifest is built
// from the exact bytes written into the archive, so the manifest can never
// describe different content than the archive even when the workspace is
// mutated mid-capture.
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
	var w io.Writer = f
	if s.MaxArtifactBytes > 0 {
		w = safefs.NewCappedWriter(f, s.MaxArtifactBytes)
	}
	archived, err := safefs.WriteTarGzFromRootEntries(w, wsRoot, paths)
	if err != nil {
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
	entries := make([]ArtifactEntry, 0, len(archived))
	for _, e := range archived {
		entries = append(entries, ArtifactEntry{Path: e.Path, Mode: uint32(e.Mode), Size: e.Size, SHA256: e.SHA256})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
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
