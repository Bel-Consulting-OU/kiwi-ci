// Package cas provides a content-addressed object wrapper over a blob.Store.
// Objects are addressed by their SHA-256 digest; the store verifies integrity
// on both write and read: Put hashes the stream and names the object after
// its digest, and Open wraps the returned reader in a verifying reader that
// hashes while streaming and fails at EOF when the content does not match
// the requested digest. cas is the digest-verified layer; the underlying
// blob stores trust their object keys.
//
// Lifecycle: CAS writes are append/deduplicate only. Put never mutates,
// overwrites or reuses an object: a digest names a fixed byte sequence, so
// writing an object that already exists is an idempotent re-put of identical
// content. A failed Put or a failed metadata/commit step therefore leaves at
// most an unreferenced object, never a missing or corrupted one. Callers must
// not delete as rollback after a metadata/persistence failure: the object may
// be shared by other references and deleting it would corrupt them. Deletion
// happens only through the reference-aware garbage collector of the storage
// layer, which knows when the last reference is gone.
package cas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
)

// ErrDigestMismatch is reported by Open's reader when the streamed content
// does not hash to the requested digest. It surfaces at EOF (Read returning
// the error, or Close when the consumer never read to EOF).
var ErrDigestMismatch = errors.New("cas: content digest mismatch")

// ErrBlobTooLarge is returned by Put when the stream exceeds MaxBlobBytes.
var ErrBlobTooLarge = errors.New("cas: blob exceeds maximum size")

// DefaultMaxBlobBytes is the default per-object size bound (4 GiB) applied
// by Put when MaxBlobBytes is not configured.
const DefaultMaxBlobBytes int64 = 4 << 30

type CAS struct {
	Blobs blob.Store
	// MaxBlobBytes bounds a single Put stream. Zero/negative means the
	// DefaultMaxBlobBytes default.
	MaxBlobBytes int64
}

func New(b blob.Store) *CAS { return &CAS{Blobs: b} }

// maxBytes resolves the effective per-object size bound.
func (c *CAS) maxBytes() int64 {
	if c.MaxBlobBytes <= 0 {
		return DefaultMaxBlobBytes
	}
	return c.MaxBlobBytes
}

// countingReader is the bounded counting reader enforcing MaxBlobBytes: it
// counts every byte that passes and fails the stream with ErrBlobTooLarge
// as soon as the bound would be exceeded, so an oversized object is never
// written to the blob store.
type countingReader struct {
	r    io.Reader
	max  int64
	read int64
	err  error
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	room := c.max + 1 - c.read
	if int64(len(p)) > room {
		p = p[:room]
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	if c.read > c.max {
		c.err = ErrBlobTooLarge
		return n, ErrBlobTooLarge
	}
	return n, err
}

// fileSeek is a test-only seam for os.File.Seek. It exists so the error
// branch after rewriting the temp file can be exercised; production behavior
// is unchanged (os.File.Seek).
var fileSeek = (*os.File).Seek

func (c *CAS) Put(ctx context.Context, r io.Reader) (blob.Object, error) {
	tmp, err := os.CreateTemp("", "kiwi-cas-*")
	if err != nil {
		return blob.Object{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), &countingReader{r: r, max: c.maxBytes()})
	if err != nil {
		return blob.Object{}, err
	}
	key := hex.EncodeToString(h.Sum(nil))
	if _, err := fileSeek(tmp, 0, io.SeekStart); err != nil {
		return blob.Object{}, err
	}
	obj, err := c.Blobs.Put(ctx, key, tmp, n)
	if err != nil {
		return blob.Object{}, err
	}
	return blob.Object{Key: key, SHA256: obj.SHA256, Size: n}, nil
}

// Open returns a digest-verified stream for the object addressed by
// sha256hex: the reader hashes the bytes while they stream and reports
// ErrDigestMismatch at EOF (or on Close when the stream was not fully
// read) when the content does not match the requested digest.
func (c *CAS) Open(ctx context.Context, sha256hex string) (io.ReadCloser, blob.Object, error) {
	rc, obj, err := c.Blobs.Open(ctx, sha256hex)
	if err != nil {
		return nil, blob.Object{}, err
	}
	return &verifyingReader{r: rc, h: sha256.New(), want: sha256hex}, obj, nil
}

// Delete removes one object unconditionally. It is not part of the write
// lifecycle: never call it to roll back a failed Put or a failed commit of
// metadata that names the object, because the digest may be shared by other
// references (see the package doc). Reclaiming unreferenced objects is the
// reference-aware garbage collector's job.
func (c *CAS) Delete(ctx context.Context, sha256hex string) error {
	return c.Blobs.Delete(ctx, sha256hex)
}

// verifyingReader is the hash-while-stream reader: bytes pass through while
// being hashed, and the digest is compared at EOF. A mismatch turns the
// final read (or Close) into ErrDigestMismatch so consumers can never
// silently accept corrupted content.
type verifyingReader struct {
	r    io.ReadCloser
	h    hash.Hash
	want string
	done bool
	err  error
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	if v.err != nil {
		return 0, v.err
	}
	n, err := v.r.Read(p)
	if n > 0 {
		_, _ = v.h.Write(p[:n])
	}
	if err == io.EOF {
		v.err = v.verify()
		if v.err != nil {
			return n, v.err
		}
		v.err = io.EOF
	}
	if err != nil {
		v.err = err
	}
	return n, v.err
}

// verify compares the accumulated hash with the requested digest. It is
// idempotent: once verified (or failed) it reports the same outcome.
func (v *verifyingReader) verify() error {
	if v.done {
		if errors.Is(v.err, ErrDigestMismatch) {
			return v.err
		}
		return nil
	}
	v.done = true
	got := hex.EncodeToString(v.h.Sum(nil))
	if got != v.want {
		v.err = fmt.Errorf("%w: want %s, got %s", ErrDigestMismatch, v.want, got)
		return v.err
	}
	return nil
}

// Close releases the underlying reader and, when the stream was never read
// to EOF, reports a digest mismatch that would otherwise be lost.
func (v *verifyingReader) Close() error {
	if err := v.verify(); err != nil {
		_ = v.r.Close()
		return err
	}
	return v.r.Close()
}
