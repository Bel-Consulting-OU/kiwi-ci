// Package safefs provides hardened archive and filesystem primitives for
// untrusted input. Extraction is a security boundary: only regular files and
// directories are ever written, symlink parents cannot redirect writes, and
// resource limits are enforced before allocation.
package safefs

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ExtractLimits struct {
	MaxArchiveBytes     int64
	MaxExpandedBytes    int64
	MaxFileBytes        int64
	MaxEntries          int64
	MaxPathLength       int
	MaxDepth            int
	MaxCompressionRatio float64
	// Allowed restricts extraction to entries within these workspace-relative
	// slash paths ("" or "." means the whole archive). Entries outside the
	// roots are validated but not written.
	Allowed []string
}

func DefaultLimits() ExtractLimits {
	return ExtractLimits{
		MaxArchiveBytes:     4 << 30,
		MaxExpandedBytes:    16 << 30,
		MaxFileBytes:        1 << 30,
		MaxEntries:          100_000,
		MaxPathLength:       2048,
		MaxDepth:            64,
		MaxCompressionRatio: 1000,
	}
}

type ExtractStats struct {
	Files   int64
	Dirs    int64
	Bytes   int64
	Skipped int64
}

var (
	ErrSymlinkParent  = errors.New("safefs: symlink component in destination path")
	ErrUnsafeEntry    = errors.New("safefs: unsafe archive entry")
	ErrDuplicateEntry = errors.New("safefs: duplicate archive entry")
	ErrLimits         = errors.New("safefs: archive exceeds configured limits")
	ErrCompression    = errors.New("safefs: compression ratio exceeded")
	ErrCapExceeded    = errors.New("safefs: output exceeds cap")
)

// Root is an opened, canonicalized extraction root: a held directory handle
// (opened with O_NOFOLLOW so a symlinked destination is rejected outright)
// plus the directory's canonical path resolved once at open time.
type Root struct {
	F         *os.File
	Canonical string
}

// Close releases the held directory handle.
func (r *Root) Close() error {
	if r == nil || r.F == nil {
		return nil
	}
	return r.F.Close()
}

// OpenRootNoFollow opens an existing directory as an extraction root. The
// directory must already exist and must not be a symlink; its canonical path
// (all symlink components resolved) is recorded once. Every later operation
// is anchored to the held handle, so renaming or replacing ancestors of the
// destination path cannot redirect extraction.
func OpenRootNoFollow(path string) (*Root, error) {
	f, err := openRootHandle(path)
	if err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Root{F: f, Canonical: canonical}, nil
}

// CappedWriter limits the total number of bytes written to the underlying
// writer. A limit <= 0 disables the cap. Once the budget is exhausted,
// Write returns ErrCapExceeded.
type CappedWriter struct {
	w         io.Writer
	limit     int64
	remaining int64
}

// NewCappedWriter returns a CappedWriter that allows at most limit bytes to
// reach w.
func NewCappedWriter(w io.Writer, limit int64) *CappedWriter {
	return &CappedWriter{w: w, limit: limit, remaining: limit}
}

func (c *CappedWriter) Write(p []byte) (int, error) {
	if c.limit <= 0 {
		return c.w.Write(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.remaining <= 0 {
		return 0, fmt.Errorf("%w: limit %d bytes", ErrCapExceeded, c.limit)
	}
	if int64(len(p)) > c.remaining {
		n, _ := c.w.Write(p[:c.remaining])
		c.remaining -= int64(n)
		return n, fmt.Errorf("%w: limit %d bytes", ErrCapExceeded, c.limit)
	}
	n, err := c.w.Write(p)
	c.remaining -= int64(n)
	return n, err
}

// Extract extracts a gzip-compressed tar stream beneath the held extraction
// root. All component traversal and creation happens relative to the root
// handle with a no-follow component discipline: every component is opened
// with O_NOFOLLOW|O_DIRECTORY, missing directories are created one component
// at a time (never MkdirAll) and immediately re-opened with O_NOFOLLOW, and
// final files are opened O_CREAT|O_EXCL|O_NOFOLLOW. Every component is thus
// re-verified at open time, and the root itself was opened no-follow and
// canonicalized once.
func Extract(root *Root, r io.Reader, limits ExtractLimits) (*ExtractStats, error) {
	if root == nil || root.F == nil {
		return nil, fmt.Errorf("safefs: nil extraction root")
	}
	limits = applyDefaults(limits)
	compressed := &countReader{r: r}
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, fmt.Errorf("safefs: gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	stats := &ExtractStats{}
	seen := map[string]bool{}
	var expanded int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return stats, nil
		}
		if err != nil {
			return stats, fmt.Errorf("safefs: tar: %w", err)
		}
		if compressed.n > limits.MaxArchiveBytes {
			return stats, ErrLimits
		}
		if expanded > limits.MaxExpandedBytes {
			return stats, ErrLimits
		}
		stats0 := int64(0)
		if h.Typeflag == tar.TypeReg {
			stats0 = h.Size
		}
		if stats0 > limits.MaxFileBytes {
			return stats, ErrLimits
		}
		if expanded+stats0 > limits.MaxExpandedBytes {
			return stats, ErrLimits
		}
		expanded += stats0
		if compressed.n > 0 && expanded > int64(limits.MaxCompressionRatio)*compressed.n {
			return stats, ErrCompression
		}
		if int64(len(seen)) >= limits.MaxEntries {
			return stats, ErrLimits
		}
		name, err := cleanEntryName(h.Name)
		if err != nil {
			return stats, fmt.Errorf("%w: %v", ErrUnsafeEntry, err)
		}
		if len(name) > limits.MaxPathLength {
			return stats, ErrLimits
		}
		depth := pathDepth(name)
		if depth > limits.MaxDepth {
			return stats, ErrLimits
		}
		key := foldPath(name)
		if seen[key] {
			return stats, fmt.Errorf("%w: %q", ErrDuplicateEntry, name)
		}
		seen[key] = true
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return stats, fmt.Errorf("%w: entry %q has type %v", ErrUnsafeEntry, name, h.Typeflag)
		}
		allowed := underAllowed(name, limits.Allowed)
		if !allowed {
			stats.Skipped++
			if h.Typeflag == tar.TypeReg {
				if _, err := io.CopyN(io.Discard, tr, h.Size); err != nil {
					return stats, fmt.Errorf("safefs: skip entry: %w", err)
				}
			}
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := mkdirNoFollow(root, name); err != nil {
				return stats, err
			}
			stats.Dirs++
		case tar.TypeReg:
			if err := writeFileNoFollow(root, name, tr, h.Size, limits); err != nil {
				return stats, err
			}
			stats.Files++
			stats.Bytes += h.Size
		}
	}
}

// ExtractPath is the deprecated path-based entry point: it opens the
// destination directory itself and extracts beneath it. The destination must
// already exist. New callers should hold the directory handle explicitly via
// OpenRootNoFollow and call Extract so extraction stays anchored to the
// opened directory even if the path's ancestors change underneath it.
//
// Deprecated: use OpenRootNoFollow plus Extract.
func ExtractPath(path string, r io.Reader, limits ExtractLimits) (*ExtractStats, error) {
	root, err := OpenRootNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return Extract(root, r, limits)
}

func applyDefaults(l ExtractLimits) ExtractLimits {
	if l.MaxArchiveBytes <= 0 {
		l.MaxArchiveBytes = 4 << 30
	}
	if l.MaxExpandedBytes <= 0 {
		l.MaxExpandedBytes = 16 << 30
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = 1 << 30
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = 100_000
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

func cleanEntryName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty name")
	}
	if strings.ContainsRune(name, '\x00') {
		return "", fmt.Errorf("NUL byte in name")
	}
	if strings.Contains(name, "\\") {
		return "", fmt.Errorf("backslash in name %q", name)
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute path %q", name)
	}
	if strings.ContainsRune(name, 0x7f) {
		return "", fmt.Errorf("control byte in name")
	}
	clean := path.Clean(name)
	if clean == "." || clean == "" {
		return "", fmt.Errorf("empty cleaned path")
	}
	for _, comp := range strings.Split(clean, "/") {
		if comp == ".." {
			return "", fmt.Errorf("parent traversal in %q", name)
		}
	}
	return clean, nil
}

func pathDepth(name string) int {
	return strings.Count(name, "/") + 1
}

func underAllowed(name string, roots []string) bool {
	if len(roots) == 0 {
		return true
	}
	for _, r := range roots {
		r = path.Clean(strings.TrimSpace(r))
		if r == "" || r == "." {
			return true
		}
		if name == r || strings.HasPrefix(name, r+"/") {
			return true
		}
	}
	return false
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// WriteTarGz writes a deterministic tar.gz of the given workspace-relative
// paths. Symlinks and special files are never written. Paths that resolve
// outside the workspace are an error.
//
// Deprecated: use OpenWorkspaceRoot plus WriteTarGzFromRoot so the archive
// is built from descriptors opened relative to the held root handle, never
// by path name. This shim keeps the historical path-based entry point for
// legacy callers (followSymlinks=false routes through the root-based writer
// anyway; followSymlinks=true retains the old path-following behavior).
func WriteTarGz(w io.Writer, workspace string, paths []string, followSymlinks bool) error {
	if !followSymlinks {
		root, err := OpenWorkspaceRoot(workspace)
		if err != nil {
			return err
		}
		defer root.Close()
		return WriteTarGzFromRoot(w, root, paths)
	}
	return writeTarGzFollowing(w, workspace, paths)
}

// writeTarGzFollowing is the legacy path-based archive writer, retained only
// for the followSymlinks=true branch of the deprecated WriteTarGz shim.
func writeTarGzFollowing(w io.Writer, workspace string, paths []string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	fail := func(e error) error {
		_ = tw.Close()
		_ = gz.Close()
		return e
	}
	entries, err := collect(workspace, paths, true)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	for _, e := range entries {
		if e.rel == "" || e.rel == "." || e.rel == "./" {
			continue
		}
		h := &tar.Header{Name: e.rel, Mode: e.mode, Size: e.size, ModTime: e.modTime, Typeflag: e.typeflag}
		if err := tw.WriteHeader(h); err != nil {
			return fail(err)
		}
		if e.typeflag == tar.TypeReg {
			f, err := os.Open(e.abs)
			if err != nil {
				return fail(err)
			}
			_, err = io.Copy(tw, f)
			f.Close()
			if err != nil {
				return fail(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		return fail(err)
	}
	return gz.Close()
}

// WriteTarGzFromRoot writes a deterministic tar.gz of the given
// workspace-relative paths, reading every file through the held
// WorkspaceRoot descriptor: each regular file is opened with OpenRel
// (no-follow, anchored to the root handle) and its content is copied from
// that descriptor only, never re-opened by name. A file swapped for a
// symlink after validation either yields the originally opened bytes or
// fails the archive — content from outside the workspace can never be
// written. Symlinks and special files are never written.
func WriteTarGzFromRoot(w io.Writer, root *WorkspaceRoot, paths []string) error {
	if root == nil || root.F == nil {
		return fmt.Errorf("safefs: nil workspace root")
	}
	entries, err := collectFromRoot(root, paths)
	if err != nil {
		return err
	}
	defer func() {
		for _, e := range entries {
			if e.f != nil {
				_ = e.f.Close()
			}
		}
	}()
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	fail := func(e error) error {
		_ = tw.Close()
		_ = gz.Close()
		return e
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	for _, e := range entries {
		if e.rel == "" || e.rel == "." || e.rel == "./" {
			continue
		}
		h := &tar.Header{Name: e.rel, Mode: e.mode, Size: e.size, ModTime: e.modTime, Typeflag: e.typeflag}
		if err := tw.WriteHeader(h); err != nil {
			return fail(err)
		}
		if e.typeflag == tar.TypeReg {
			n, err := io.CopyN(tw, e.f, e.size)
			if err != nil {
				return fail(err)
			}
			if n != e.size {
				return fail(fmt.Errorf("safefs: %q: short read: %d of %d bytes", e.rel, n, e.size))
			}
		}
	}
	if err := tw.Close(); err != nil {
		return fail(err)
	}
	return gz.Close()
}

// collectFromRoot walks the requested paths beneath the workspace root and
// records every regular file with its descriptor already opened via
// OpenRel. Symlink components are never followed; a symlink capture root is
// skipped (matching WriteTarGz's historical behavior) and nested symlinks
// are never archived.
func collectFromRoot(root *WorkspaceRoot, paths []string) ([]walkEntry, error) {
	seen := map[string]bool{}
	var out []walkEntry
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
			// never follow or archive a symlinked capture root
			continue
		}
		err = filepath.WalkDir(abs, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&os.ModeSymlink != 0 {
				// never follow or archive symlinks
				return nil
			}
			r, err := filepath.Rel(root.Canonical, p)
			if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
				return fmt.Errorf("safefs: path escapes workspace: %q", p)
			}
			r = filepath.ToSlash(r)
			if seen[r] {
				return fmt.Errorf("safefs: duplicate path %q", r)
			}
			seen[r] = true
			if d.IsDir() {
				info, err := d.Info()
				if err != nil {
					return err
				}
				out = append(out, walkEntry{abs: p, rel: r + "/", mode: 0o755, modTime: info.ModTime(), typeflag: tar.TypeDir})
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			f, err := root.OpenRel(r)
			if err != nil {
				return err
			}
			st, err := f.Stat()
			if err != nil {
				f.Close()
				return err
			}
			out = append(out, walkEntry{abs: p, rel: r, size: st.Size(), mode: 0o644, modTime: st.ModTime(), typeflag: tar.TypeReg, f: f})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

type walkEntry struct {
	abs, rel string
	size     int64
	mode     int64
	modTime  time.Time
	typeflag byte
	f        *os.File // held descriptor for regular files
}

func collect(workspace string, paths []string, followSymlinks bool) ([]walkEntry, error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []walkEntry
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
		if fi.Mode()&os.ModeSymlink != 0 && !followSymlinks {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			fi, err = os.Stat(abs)
			if err != nil {
				return nil, err
			}
		}
		err = walkAbs(root, abs, fi, func(abs string, fi os.FileInfo) error {
			rel, err := filepath.Rel(root, abs)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("safefs: path escapes workspace: %q", abs)
			}
			rel = filepath.ToSlash(rel)
			if seen[rel] {
				return fmt.Errorf("safefs: duplicate path %q", rel)
			}
			seen[rel] = true
			switch {
			case fi.Mode().IsRegular():
				out = append(out, walkEntry{abs: abs, rel: rel, size: fi.Size(), mode: 0o644, modTime: fi.ModTime(), typeflag: tar.TypeReg})
			case fi.IsDir():
				out = append(out, walkEntry{abs: abs, rel: rel + "/", mode: 0o755, modTime: fi.ModTime(), typeflag: tar.TypeDir})
			default:
				// symlinks and special files are never written
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func walkAbs(root, abs string, fi os.FileInfo, fn func(abs string, fi os.FileInfo) error) error {
	if err := fn(abs, fi); err != nil {
		return err
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
		if info.Mode()&os.ModeSymlink != 0 {
			// never follow or archive symlinks
			continue
		}
		childAbs := filepath.Join(abs, e.Name())
		if err := walkAbs(root, childAbs, info, fn); err != nil {
			return err
		}
	}
	return nil
}
