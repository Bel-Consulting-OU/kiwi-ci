// Package snapshot captures and restores workspace snapshots: a
// deterministic tar.gz of the workspace plus a manifest of per-entry
// digests. Snapshots are the substrate for workspace replay (kiwi replay,
// which restores the exact snapshot then re-executes the resolved job) and
// for cross-job workspace handoff.
//
// Only regular files are captured; symlinks, devices and other special
// files are never archived, and extraction goes through the hardened safefs
// extractor with default resource limits.
package snapshot

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// ManifestVersion is the current snapshot manifest format version.
const ManifestVersion = 1

// Entry is one regular file in a snapshot.
type Entry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest describes a snapshot: every captured file plus a root digest
// binding the whole entry list.
type Manifest struct {
	Version    int     `json:"version"`
	RootSHA256 string  `json:"root_sha256"`
	Entries    []Entry `json:"entries"`
}

// ManifestFor walks the workspace and builds its manifest: regular files
// only, paths in sorted order, per-file SHA-256, and a root digest over the
// canonical entry list.
func ManifestFor(workspace string) (Manifest, error) {
	entries, err := collectEntries(workspace)
	if err != nil {
		return Manifest{}, err
	}
	return Manifest{Version: ManifestVersion, RootSHA256: rootSHA256(entries), Entries: entries}, nil
}

// collectEntries walks the workspace and records every regular file with a
// normalized mode (0o644, matching what WriteTarGz puts in the archive) so a
// manifest computed from the filesystem and one computed from the archive
// agree.
func collectEntries(workspace string) ([]Entry, error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return nil, err
	}
	var out []Entry
	err = filepath.WalkDir(root, func(abs string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if abs == root {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("snapshot: path escapes workspace: %q", abs)
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
		out = append(out, Entry{
			Path:   filepath.ToSlash(rel),
			Mode:   0o644,
			Size:   size,
			SHA256: hex.EncodeToString(h.Sum(nil)),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// rootSHA256 is the root digest of a snapshot: the SHA-256 of the canonical
// JSON form of its (sorted) entry list. It binds every entry path, digest
// and size in one value that can be compared across capture/restore cycles.
func rootSHA256(entries []Entry) string {
	b, err := json.Marshal(entries)
	if err != nil {
		// Entries are plain strings/numbers: marshal cannot fail.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Parse reads a snapshot archive and builds its manifest without writing
// anything to disk: tar headers supply paths/modes/sizes and each regular
// entry's body is hashed in the stream. Resource bounds from ParseWithLimits
// apply.
func Parse(r io.Reader) (Manifest, error) {
	return ParseWithLimits(r, safefs.ExtractLimits{})
}

// parseLimits are the hard bounds Parse enforces on untrusted snapshot
// archives: at most 16 GiB of expanded data, 1_000_000 entries, 1 GiB per
// entry, path length 2048 and depth 64.
func parseLimits(l safefs.ExtractLimits) safefs.ExtractLimits {
	if l.MaxExpandedBytes <= 0 {
		l.MaxExpandedBytes = 16 << 30
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = 1 << 30
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = 1_000_000
	}
	if l.MaxPathLength <= 0 {
		l.MaxPathLength = 2048
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = 64
	}
	return l
}

// countReader counts the compressed bytes consumed so an optional archive
// byte budget can be enforced.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ParseWithLimits is Parse with caller-supplied resource bounds; zero fields
// fall back to the hard defaults of parseLimits.
func ParseWithLimits(r io.Reader, limits safefs.ExtractLimits) (Manifest, error) {
	limits = parseLimits(limits)
	compressed := &countReader{r: r}
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot: gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var entries []Entry
	var expanded int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("snapshot: tar: %w", err)
		}
		if limits.MaxArchiveBytes > 0 && compressed.n > limits.MaxArchiveBytes {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if h.Size > limits.MaxFileBytes {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		if expanded+h.Size > limits.MaxExpandedBytes {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		expanded += h.Size
		if int64(len(entries)) >= limits.MaxEntries {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		if len(h.Name) > limits.MaxPathLength {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		if strings.Count(h.Name, "/")+1 > limits.MaxDepth {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		hasher := sha256.New()
		if _, err := io.Copy(hasher, tr); err != nil {
			return Manifest{}, fmt.Errorf("snapshot: hash entry %q: %w", h.Name, err)
		}
		entries = append(entries, Entry{
			Path:   h.Name,
			Mode:   uint32(h.Mode),
			Size:   h.Size,
			SHA256: hex.EncodeToString(hasher.Sum(nil)),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return Manifest{Version: ManifestVersion, RootSHA256: rootSHA256(entries), Entries: entries}, nil
}
