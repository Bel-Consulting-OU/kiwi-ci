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

// MaxArchiveBytes is the ONE compressed snapshot-archive budget shared by
// every layer of the snapshot path:
//
//   - the runner refuses to assemble a larger archive: its derived capture
//     cap is min(2 x declared workspace bound, MaxArchiveBytes)
//     (internal/runner/snapshots.go);
//   - the control plane's snapshot upload endpoints refuse a larger request
//     body (internal/server/snapshots.go);
//   - Parse/ParseWithLimits reject a larger compressed archive with
//     safefs.ErrLimits (parseLimits defaults MaxArchiveBytes to this value).
//
// Before this source existed the runner's fallback/2x cap was 8 GiB while
// the parser defaulted to 4 GiB, so the runner could assemble an archive the
// receiver necessarily rejected. 4 GiB is the practical compressed ceiling:
// it is far above a real workspace snapshot and keeps the receiver's
// worst-case gzip work bounded (MaxExpandedBytes is 16 GiB, a 1000x
// compression-ratio guard and a 1 GiB per-entry cap still apply on top).
const MaxArchiveBytes int64 = 4 << 30

// MaxManifestEntries is the default per-archive tar-header bound Parse
// enforces (one per header, regardless of type). It matches the safefs
// extraction default (safefs.DefaultLimits().MaxEntries = 100_000): a
// snapshot manifest can never describe more entries than extraction would
// accept, and the 1_000_000 default this replaced let a zero-byte-file flood
// build an unbounded in-memory entry slice/map.
const MaxManifestEntries int64 = 100_000

// MaxManifestMetadataBytes caps the AGGREGATE in-memory metadata Parse may
// allocate while describing an archive: every accepted header charges
// len(path) plus manifestEntryOverheadBytes against this budget, BEFORE its
// entry (or duplicate-tracking key) is appended to the slice/map. Path length
// alone is already bounded, but without this aggregate cap MaxEntries short
// paths could still allocate hundreds of MiB; with it the worst-case manifest
// footprint is bounded regardless of how the archive is shaped.
const MaxManifestMetadataBytes int64 = 64 << 20

// manifestEntryOverheadBytes is the per-entry bookkeeping charged on top of
// the path length (Entry struct fields, slice growth, the duplicate-tracking
// map key and its Go string/map overhead).
const manifestEntryOverheadBytes int64 = 256

// manifestHeaderBytes is the virtual expanded-size cost charged for every tar
// header, including non-regular and zero-byte ones. Counting only regular
// file bodies let an archive of zero-byte files consume unbounded metadata
// while contributing nothing to the expansion/ratio budgets; charging the
// header makes the flood visible to those budgets too.
const manifestHeaderBytes int64 = 512

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
// canonical entry list. Every file is read through a held safefs
// WorkspaceRoot (no-follow, anchored to the root handle), so a file swapped
// for a symlink mid-walk fails the manifest instead of hashing content
// outside the workspace.
func ManifestFor(workspace string) (Manifest, error) {
	root, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot: open workspace: %w", err)
	}
	defer root.Close()
	return manifestForRoot(root)
}

// manifestForRoot builds the manifest for an already-opened workspace root.
func manifestForRoot(root *safefs.WorkspaceRoot) (Manifest, error) {
	entries, err := collectEntries(root)
	if err != nil {
		return Manifest{}, err
	}
	return Manifest{Version: ManifestVersion, RootSHA256: rootSHA256(entries), Entries: entries}, nil
}

// collectEntries walks the workspace beneath the held root and records every
// regular file with a normalized mode (0o644, matching what
// WriteTarGzFromRoot puts in the archive) so a manifest computed from the
// filesystem and one computed from the archive agree. Each file is hashed
// from the descriptor returned by root.OpenRel.
// walkDir is a test-only seam over filepath.WalkDir. Production behavior is
// unchanged; it lets the per-entry error handling be exercised with synthetic
// entry shapes (symlinked directories, unreadable entries, escaping paths).
var walkDir = filepath.WalkDir

func collectEntries(root *safefs.WorkspaceRoot) ([]Entry, error) {
	var out []Entry
	err := walkDir(root.Canonical, func(abs string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if abs == root.Canonical {
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
		rel, err := filepath.Rel(root.Canonical, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("snapshot: path escapes workspace: %q", abs)
		}
		f, err := root.OpenRel(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		h := sha256.New()
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
// archives: at most MaxArchiveBytes of compressed input, 16 GiB of expanded
// data, MaxManifestEntries tar headers (counted per header regardless of
// type, including the virtual manifestHeaderBytes charged per header), 1 GiB
// per entry, path length 2048, depth 64 and a compression ratio of 1000 (the
// same envelope safefs extraction applies). A caller-supplied positive value
// overrides the corresponding default (the server parses with the defaults,
// so the upload body cap and the parser agree).
func parseLimits(l safefs.ExtractLimits) safefs.ExtractLimits {
	if l.MaxArchiveBytes <= 0 {
		l.MaxArchiveBytes = MaxArchiveBytes
	}
	if l.MaxExpandedBytes <= 0 {
		l.MaxExpandedBytes = 16 << 30
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = 1 << 30
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = MaxManifestEntries
	}
	if l.MaxPathLength <= 0 {
		l.MaxPathLength = 2048
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = 64
	}
	if l.MaxCompressionRatio <= 0 {
		l.MaxCompressionRatio = 1000
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
// fall back to the hard defaults of parseLimits. MaxEntries bounds every tar
// header the archive yields — regular files, directories, symlinks and any
// other type — before the type switch, so header processing and duplicate
// tracking stay bounded even for archives that carry no regular entries at
// all. Entry names are validated with the same discipline as safefs
// extraction (relative, clean, portable, no control characters) and
// duplicates — including case-fold and normalization collisions on
// case-insensitive filesystems — are rejected, so a manifest produced by
// Parse can only describe an archive that extraction would accept.
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
	seen := map[string]bool{}
	var expanded int64
	var metadata int64
	var headers int64
	// ONE reusable copy buffer for the whole parse: io.Copy allocates a fresh
	// 32 KiB buffer per call when neither side implements ReaderFrom/WriterTo
	// (tar.Reader and hash.Hash do not), so a many-entry archive would
	// otherwise allocate 32 KiB per entry — the dominant cost of the
	// zero-byte-flood footprint.
	copyBuf := make([]byte, 32*1024)
	for {
		h, err := tr.Next()
		// The archive budget is checked on every Next call, INCLUDING the
		// call that reports EOF: an archive whose last entry pushes it over
		// the limit (or one whose overage only becomes visible while the
		// reader drains the tail) is rejected instead of being accepted
		// because the loop broke before examining the counter.
		if limits.MaxArchiveBytes > 0 && compressed.n > limits.MaxArchiveBytes {
			return Manifest{}, fmt.Errorf("snapshot: archive exceeds the %d-byte compressed limit: %w", limits.MaxArchiveBytes, safefs.ErrLimits)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("snapshot: tar: %w", err)
		}
		headers++
		if headers > limits.MaxEntries {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		name, nerr := safefs.ValidateEntryName(h.Name)
		if nerr != nil {
			return Manifest{}, fmt.Errorf("snapshot: %w: %v", safefs.ErrUnsafeEntry, nerr)
		}
		key := safefs.FoldPath(name)
		if seen[key] {
			return Manifest{}, fmt.Errorf("snapshot: %w: %q", safefs.ErrDuplicateEntry, name)
		}
		// Charge the header's aggregate metadata and virtual expansion
		// BEFORE it can be added to the entry slice or the duplicate map,
		// so an archive of short or zero-byte entries is rejected as soon
		// as its in-memory footprint would exceed the budget instead of
		// after the slice/map have already grown.
		metadata += int64(len(name)) + manifestEntryOverheadBytes
		if metadata > MaxManifestMetadataBytes {
			return Manifest{}, fmt.Errorf("snapshot: manifest metadata exceeds the %d-byte limit: %w", MaxManifestMetadataBytes, safefs.ErrLimits)
		}
		if expanded+manifestHeaderBytes > limits.MaxExpandedBytes {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		if compressed.n > 0 && expanded+manifestHeaderBytes > int64(limits.MaxCompressionRatio)*compressed.n {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrCompression)
		}
		expanded += manifestHeaderBytes
		seen[key] = true
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if h.Size > limits.MaxFileBytes {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		if expanded+h.Size > limits.MaxExpandedBytes {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		if compressed.n > 0 && expanded+h.Size > int64(limits.MaxCompressionRatio)*compressed.n {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrCompression)
		}
		expanded += h.Size
		if int64(len(entries)) >= limits.MaxEntries {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		if len(name) > limits.MaxPathLength {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		if strings.Count(name, "/")+1 > limits.MaxDepth {
			return Manifest{}, fmt.Errorf("snapshot: %w", safefs.ErrLimits)
		}
		hasher := sha256.New()
		if h.Size > 0 {
			if _, err := io.CopyBuffer(hasher, tr, copyBuf); err != nil {
				return Manifest{}, fmt.Errorf("snapshot: hash entry %q: %w", name, err)
			}
		}
		entries = append(entries, Entry{
			Path:   name,
			Mode:   uint32(h.Mode),
			Size:   h.Size,
			SHA256: hex.EncodeToString(hasher.Sum(nil)),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return Manifest{Version: ManifestVersion, RootSHA256: rootSHA256(entries), Entries: entries}, nil
}
