// Package safefs provides hardened archive and filesystem primitives for
// untrusted input. Extraction is a security boundary: only regular files and
// directories are ever written, symlink parents cannot redirect writes, and
// resource limits are enforced before allocation.
package safefs

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
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

// evalSymlinks is a test-only seam over filepath.EvalSymlinks. Production
// behavior is unchanged; it lets the post-open canonicalization failure be
// exercised deterministically.
var evalSymlinks = filepath.EvalSymlinks

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
	canonical, err := evalSymlinks(path)
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
	if err := checkNameRunes(name); err != nil {
		return "", err
	}
	clean := path.Clean(name)
	if clean == "." || clean == "" {
		return "", fmt.Errorf("empty cleaned path")
	}
	for _, comp := range strings.Split(clean, "/") {
		if comp == ".." {
			return "", fmt.Errorf("parent traversal in %q", name)
		}
		if err := checkNameComponent(comp); err != nil {
			return "", err
		}
	}
	return clean, nil
}

// ValidateEntryName exposes the archive entry-name discipline to packages
// that build manifests from untrusted tar streams (for example snapshot
// parsing) so what they accept can never diverge from what Extract will
// accept. It returns the cleaned relative path.
func ValidateEntryName(name string) (string, error) { return cleanEntryName(name) }

// FoldPath returns the duplicate-detection fold for an entry name: on
// case-insensitive filesystems it lowercases and Unicode-normalizes (NFC)
// so case-only and NFC/NFD-only collisions, which a case-insensitive
// filesystem would silently merge, are rejected before any write. On
// case-sensitive filesystems the name is returned unchanged.
func FoldPath(name string) string { return foldPath(name) }

// checkNameRunes rejects characters that would let an entry name spoof,
// inject into, or confuse terminal/log output: C0 controls, DEL, and the
// Unicode bidirectional formatting controls with no legitimate use in a
// file name.
func checkNameRunes(name string) error {
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("control character %#U in name %q", r, name)
		}
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F {
			return fmt.Errorf("unicode formatting control %#U in name %q", r, name)
		}
	}
	return nil
}

// checkNameComponent rejects path components that are not portable across
// the supported platforms: Windows reserved device names (CON, NUL,
// COM1..9, LPT1..9, CONIN$/CONOUT$), names with a trailing dot or space
// (Win32 silently strips them, so two distinct entries would merge), and
// colons (which address NTFS alternate data streams instead of a file).
// Rejecting them everywhere keeps extraction fail-closed and portable.
func checkNameComponent(comp string) error {
	if comp == "" {
		return fmt.Errorf("empty path component")
	}
	if strings.HasSuffix(comp, ".") || strings.HasSuffix(comp, " ") {
		return fmt.Errorf("component %q ends with a dot or space", comp)
	}
	if strings.ContainsRune(comp, ':') {
		return fmt.Errorf("component %q contains a colon", comp)
	}
	base := comp
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return fmt.Errorf("component %q is a reserved device name", comp)
	}
	if len(base) == 4 {
		u := strings.ToUpper(base)
		if (strings.HasPrefix(u, "COM") || strings.HasPrefix(u, "LPT")) && u[3] >= '1' && u[3] <= '9' {
			return fmt.Errorf("component %q is a reserved device name", comp)
		}
	}
	return nil
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

// ArchiveFile describes one regular file that was written into an archive,
// with the digest of the exact bytes that reached the tar stream. Callers use
// it to build a manifest that is consistent with the archive by
// construction: there is no second walk of the filesystem that a concurrent
// writer could race against.
type ArchiveFile struct {
	Path    string
	Mode    int64
	Size    int64
	SHA256  string
	ModTime time.Time
}

// WriteTarGzFromRoot writes a deterministic tar.gz of the given
// workspace-relative paths, reading every file through the held
// WorkspaceRoot descriptor: each regular file is opened with OpenRel
// (no-follow, anchored to the root handle) at write time and its content is
// copied from that descriptor only, never re-opened by name, and only one
// descriptor is held at a time so a large workspace cannot exhaust file
// descriptors. A file swapped for a symlink before it is opened fails the
// archive; a file deleted after its descriptor was opened is still archived
// from that descriptor (on POSIX). Symlinks and special files are never
// written.
func WriteTarGzFromRoot(w io.Writer, root *WorkspaceRoot, paths []string) error {
	_, err := WriteTarGzFromRootEntries(w, root, paths)
	return err
}

// closeEntryFile, copyEntryBytes, statArchiveEntry and walkDirFn are
// test-only seams over os.File.Close, io.CopyN, os.File.Stat and
// filepath.WalkDir. Production behavior is unchanged; they let the post-copy
// close failure, a short entry read, the writer's own post-open
// stat/regularity re-check and the root-anchored walk's entry-info race guard
// be exercised deterministically.
var (
	closeEntryFile   = (*os.File).Close
	copyEntryBytes   = io.CopyN
	statArchiveEntry = (*os.File).Stat
	walkDirFn        = filepath.WalkDir
)

// WriteTarGzFromRootEntries is WriteTarGzFromRoot and additionally returns
// the regular files whose bytes were written to the stream, in write order,
// with the digest of exactly those bytes. A manifest built from the result
// can never disagree with the archive, even if the workspace is mutated
// mid-capture.
func WriteTarGzFromRootEntries(w io.Writer, root *WorkspaceRoot, paths []string) ([]ArchiveFile, error) {
	if root == nil || root.Root == nil || root.Root.F == nil {
		return nil, fmt.Errorf("safefs: nil workspace root")
	}
	entries, err := collectFromRoot(root, paths)
	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	fail := func(e error) ([]ArchiveFile, error) {
		_ = tw.Close()
		_ = gz.Close()
		return nil, e
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	var files []ArchiveFile
	for _, e := range entries {
		if e.rel == "" || e.rel == "." || e.rel == "./" {
			continue
		}
		h := &tar.Header{Name: e.rel, Mode: e.mode, Size: e.size, ModTime: e.modTime, Typeflag: e.typeflag}
		var f *os.File
		if e.typeflag == tar.TypeReg {
			f, err = root.OpenRel(e.rel)
			if err != nil {
				return fail(fmt.Errorf("safefs: open %q: %w", e.rel, err))
			}
			st, statErr := statArchiveEntry(f)
			if statErr != nil {
				f.Close()
				return fail(statErr)
			}
			if !st.Mode().IsRegular() {
				f.Close()
				return fail(fmt.Errorf("%w: %q", ErrNotRegular, e.rel))
			}
			h.Size = st.Size()
			h.ModTime = st.ModTime()
		}
		if err := tw.WriteHeader(h); err != nil {
			if f != nil {
				f.Close()
			}
			return fail(err)
		}
		if f == nil {
			continue
		}
		hasher := sha256.New()
		n, copyErr := copyEntryBytes(io.MultiWriter(tw, hasher), f, h.Size)
		closeErr := closeEntryFile(f)
		if copyErr != nil {
			return fail(copyErr)
		}
		if closeErr != nil {
			return fail(closeErr)
		}
		if n != h.Size {
			return fail(fmt.Errorf("safefs: %q: short read: %d of %d bytes", e.rel, n, h.Size))
		}
		files = append(files, ArchiveFile{
			Path:    e.rel,
			Mode:    e.mode,
			Size:    n,
			SHA256:  hex.EncodeToString(hasher.Sum(nil)),
			ModTime: h.ModTime,
		})
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return files, nil
}

// collectFromRoot walks the requested paths beneath the workspace root and
// records every regular file and directory. No descriptor is held here:
// regular files are opened by the writer immediately before their bytes are
// read, so a capture never keeps one descriptor per workspace file open.
// Symlink components are never followed; a symlink capture root is skipped
// (matching WriteTarGz's historical behavior) and nested symlinks are never
// archived.
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
		err = walkDirFn(abs, func(p string, d os.DirEntry, err error) error {
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
			info, err := d.Info()
			if err != nil {
				return err
			}
			if d.IsDir() {
				out = append(out, walkEntry{rel: r + "/", mode: 0o755, modTime: info.ModTime(), typeflag: tar.TypeDir})
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			out = append(out, walkEntry{rel: r, size: info.Size(), mode: 0o644, modTime: info.ModTime(), typeflag: tar.TypeReg})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

type walkEntry struct {
	// abs is only populated by the legacy path-based collect (the
	// followSymlinks=true shim); root-anchored capture opens descriptors
	// through OpenRel and never needs a path.
	abs      string
	rel      string
	size     int64
	mode     int64
	modTime  time.Time
	typeflag byte
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
