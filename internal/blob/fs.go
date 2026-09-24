package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

var keyRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

// fsStat and fsRename are test-only seams over os.Stat and os.Rename.
// Production behavior is unchanged; they let the stat/rename race branches
// be exercised deterministically.
var (
	fsStat   = os.Stat
	fsRename = os.Rename
)

// FS is a filesystem-backed Store. Objects are immutable files laid out as
// <root>/sha256/<first-2>/<full-digest>. Puts are staged and atomically
// renamed; concurrent identical puts are idempotent.
type FS struct {
	Root string
}

func NewFS(root string) *FS { return &FS{Root: root} }

func (s *FS) Put(ctx context.Context, key string, r io.Reader, size int64) (Object, error) {
	if !keyRE.MatchString(key) {
		return Object{}, fmt.Errorf("blob: invalid key %q", key)
	}
	if size < 0 {
		return Object{}, fmt.Errorf("blob: negative size")
	}
	dir := filepath.Join(s.Root, "sha256", key[:2])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Object{}, err
	}
	// Make the shard directory itself durable before anything is published
	// into it: the directory entry a later object rename depends on must
	// survive a crash, or a durable manifest could reference an object whose
	// rename did not survive. MkdirAll may have created the store root, the
	// "sha256" level and the shard, so each level is fsynced.
	if root := filepath.Clean(s.Root); root != "" && root != "." {
		if err := fsutil.SyncDir(root); err != nil {
			return Object{}, fmt.Errorf("blob: sync store root: %w", err)
		}
	}
	if err := fsutil.SyncDir(filepath.Dir(dir)); err != nil {
		return Object{}, fmt.Errorf("blob: sync shard parent: %w", err)
	}
	if err := fsutil.SyncDir(dir); err != nil {
		return Object{}, fmt.Errorf("blob: sync shard: %w", err)
	}
	dst := filepath.Join(dir, key)
	if _, err := fsStat(dst); err == nil {
		// A deduplicated re-put refreshes the object's mtime. The payload
		// is immutable, but the age floor the CAS GC applies must reflect
		// the last time an upload made the object reachable again: without
		// the touch, a digest orphaned for longer than the floor and then
		// re-put concurrently with a GC pass could be deleted out from
		// under its new reference.
		now := time.Now()
		// A GC pass may delete the object between the stat and the touch.
		// The touch then fails with ErrNotExist; the re-check below sees the
		// object is gone and falls through to re-create it from r instead of
		// acknowledging a dedup to a missing object.
		if cherr := os.Chtimes(dst, now, now); cherr != nil && !errors.Is(cherr, os.ErrNotExist) {
			return Object{}, cherr
		}
		fi, statErr := fsStat(dst)
		if statErr == nil {
			return Object{Key: key, SHA256: key, Size: fi.Size()}, nil
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return Object{}, statErr
		}
		// The object vanished under us: fall through and rewrite it. The
		// residual race (GC deleting after this re-stat but before the
		// caller durably records its reference) is bounded by the CAS GC's
		// digest fence, which blob.FS cannot take from this package; a
		// re-put always recreates the object, so the reference converges.
	}
	f, err := os.CreateTemp(dir, "."+key+".tmp-*")
	if err != nil {
		return Object{}, err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	h := sha256.New()
	n, cpErr := io.Copy(io.MultiWriter(f, h), r)
	syncErr := f.Sync()
	closeErr := f.Close()
	if cpErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		return Object{}, firstErr(cpErr, syncErr, closeErr)
	}
	if size > 0 && n != size {
		_ = os.Remove(tmp)
		return Object{}, fmt.Errorf("blob: size mismatch: wrote %d, expected %d", n, size)
	}
	if hex.EncodeToString(h.Sum(nil)) != key {
		_ = os.Remove(tmp)
		return Object{}, fmt.Errorf("blob: content digest does not match key %s", key)
	}
	if err := fsRename(tmp, dst); err != nil {
		// A concurrent writer won the race: the existing object is identical.
		if _, statErr := fsStat(dst); statErr == nil {
			return Object{Key: key, SHA256: key, Size: n}, nil
		}
		_ = os.Remove(tmp)
		return Object{}, err
	}
	// The rename is only durable once the shard directory is fsynced. The
	// object is already visible at dst, so a failed directory fsync is a
	// published-but-uncertain write: it is returned as the typed
	// fsutil.AtomicWriteError (Renamed=true) so the CAS layer can treat the
	// object as possibly-durable rather than as never written, and must not
	// ack a durable manifest on the strength of a rename that may not have
	// survived.
	if err := fsutil.SyncDir(dir); err != nil {
		return Object{}, &fsutil.AtomicWriteError{Path: dst, Phase: fsutil.PhaseDirSync, Renamed: true, Err: err}
	}
	return Object{Key: key, SHA256: key, Size: n}, nil
}

// Open returns a stream for the object addressed by key. It verifies the
// object's existence and reports the stat'd size, but it does NOT verify
// the content digest: blob.FS trusts the key (Put hashed the content into
// the key before the atomic rename), and digest verification is the
// responsibility of the cas layer, which wraps this reader in a
// hash-while-stream verifying reader.
func (s *FS) Open(ctx context.Context, key string) (io.ReadCloser, Object, error) {
	if !keyRE.MatchString(key) {
		return nil, Object{}, fmt.Errorf("blob: invalid key %q", key)
	}
	dst := filepath.Join(s.Root, "sha256", key[:2], key)
	fi, err := os.Stat(dst)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, Object{}, ErrNotFound
		}
		return nil, Object{}, err
	}
	f, err := os.Open(dst)
	if err != nil {
		return nil, Object{}, err
	}
	return f, Object{Key: key, SHA256: key, Size: fi.Size()}, nil
}

func (s *FS) Delete(ctx context.Context, key string) error {
	if !keyRE.MatchString(key) {
		return fmt.Errorf("blob: invalid key %q", key)
	}
	dst := filepath.Join(s.Root, "sha256", key[:2], key)
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(filepath.Join(s.Root, "sha256", key[:2]))
	return nil
}

// List walks the store's <root>/sha256/<xx>/<digest> layout and reports every
// committed object. It implements Enumerator. Staging files (dot-prefixed
// ".tmp" scratch files) and any name that is not a canonical 64-hex digest
// are skipped, so the walk can never surface a partially written upload. A
// missing shard directory is not an error; a failed stat or the callback's
// error aborts the walk and is returned unchanged. ctx is checked between
// shards so a cancelled GC pass stops promptly.
func (s *FS) List(ctx context.Context, fn func(Object) error) error {
	root := filepath.Join(s.Root, "sha256")
	shards, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := os.ReadDir(filepath.Join(root, shard.Name()))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			key := e.Name()
			if !keyRE.MatchString(key) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				return err
			}
			if err := fn(Object{Key: key, SHA256: key, Size: info.Size(), ModTime: info.ModTime()}); err != nil {
				return err
			}
		}
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// Stat returns the object's current size and mtime without opening it.
func (s *FS) Stat(ctx context.Context, key string) (Object, error) {
	if !keyRE.MatchString(key) {
		return Object{}, fmt.Errorf("blob: invalid key %q", key)
	}
	dst := filepath.Join(s.Root, "sha256", key[:2], key)
	fi, err := os.Stat(dst)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Object{}, ErrNotFound
		}
		return Object{}, err
	}
	return Object{Key: key, SHA256: key, Size: fi.Size(), ModTime: fi.ModTime()}, nil
}
