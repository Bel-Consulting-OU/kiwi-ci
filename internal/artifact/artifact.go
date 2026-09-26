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

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

type Store struct {
	Root             string
	MaxArtifactBytes int64
}

// Test-only seams for otherwise unreachable OS failure branches. Production
// behavior is unchanged: the defaults are os.File.Close, os.File.Sync and
// os.Rename (copyDigest is the digest copy used by VerifyArchive).
var (
	closeArtifactFile  = (*os.File).Close
	syncArtifactFile   = (*os.File).Sync
	renameArtifactFile = os.Rename
	copyDigest         = io.Copy
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
	// Stage into a UNIQUE temp file in the destination directory, fsync and
	// checked-close it, rename it into place and fsync the directory: the
	// same crash-durability sequence as fsutil.AtomicWriteFile, applied to a
	// streamed archive that is far too large to buffer. A fixed ".tmp" name
	// would let two concurrent saves clobber each other's scratch file.
	f, err := os.CreateTemp(dir, "."+filepath.Base(dst)+"-*.tmp")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(f, h)}
	var w io.Writer = cw
	if s.MaxArtifactBytes > 0 {
		w = safefs.NewCappedWriter(cw, s.MaxArtifactBytes)
	}
	archived, err := safefs.WriteTarGzFromRootEntries(w, wsRoot, paths)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	syncErr := syncArtifactFile(f)
	closeErr := closeArtifactFile(f)
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		if syncErr != nil {
			return "", syncErr
		}
		return "", closeErr
	}
	if err := renameArtifactFile(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := fsutil.SyncDir(dir); err != nil {
		// The archive is visible but its rename may not survive a crash;
		// no manifest may be written for it.
		_ = os.Remove(dst)
		return "", fmt.Errorf("artifact: sync archive directory: %w", err)
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
		Size:      cw.n,
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

// Extract restores the tar.gz artifact at archivePath beneath the held
// workspace root at the workspace-relative directory rel, using the hardened
// safefs extractor: only regular files and directories, no symlink
// following, and hard resource limits.
//
// The destination is resolved by walking rel component by component from the
// held workspace root handle with a no-follow discipline (safefs.OpenRootBeneath),
// and the destination directory is created one component at a time. A
// symlinked ancestor can therefore never be traversed, even when the
// workspace contains a symlink left by a checkout (for example
// `evil -> $HOME` with rel `evil/.ssh`).
func Extract(archivePath string, workspace *safefs.Root, rel string) error {
	if workspace == nil || workspace.F == nil {
		return fmt.Errorf("artifact extract: nil workspace root")
	}
	root, err := safefs.OpenRootBeneath(workspace, rel)
	if err != nil {
		return fmt.Errorf("artifact extract: %w", err)
	}
	defer root.Close()
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	// Artifact extraction restores the whole archive: opt in explicitly.
	limits := safefs.DefaultLimits()
	limits.AllowAll = true
	if _, err := safefs.Extract(root, f, limits); err != nil {
		return fmt.Errorf("artifact extract: %w", err)
	}
	return nil
}
