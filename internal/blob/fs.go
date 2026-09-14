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
)

var keyRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

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
	dst := filepath.Join(dir, key)
	if _, err := os.Stat(dst); err == nil {
		fi, statErr := os.Stat(dst)
		if statErr != nil {
			return Object{}, statErr
		}
		return Object{Key: key, SHA256: key, Size: fi.Size()}, nil
	}
	tmp := filepath.Join(dir, "."+key+".tmp")
	f, err := os.CreateTemp(dir, "."+key+".tmp-*")
	if err != nil {
		return Object{}, err
	}
	tmp = f.Name()
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
	if err := os.Rename(tmp, dst); err != nil {
		// A concurrent writer won the race: the existing object is identical.
		if _, statErr := os.Stat(dst); statErr == nil {
			return Object{Key: key, SHA256: key, Size: n}, nil
		}
		_ = os.Remove(tmp)
		return Object{}, err
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

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
