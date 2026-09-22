// Package cas provides a content-addressed object wrapper over a blob.Store.
// Objects are addressed by their SHA-256 digest; the store verifies integrity
// on both write and read: Put hashes the stream and names the object after
// its digest, and Open wraps the returned reader in a verifying reader that
// hashes while streaming and fails at EOF when the content does not match
// the requested digest. cas is the digest-verified layer; the underlying
// blob stores trust their object keys.
//
// Publication APIs (prefer the staged ones):
//
//   - PutFile publishes a file that the caller already staged (under the
//     bounded staging budget, or the artifact data dir) WITHOUT a second
//     copy: the bytes stream from the staged file into the backend while the
//     digest is verified, and the backend's returned object is validated
//     against the published key/digest/size.
//   - PutKnown publishes a reader whose digest and size the caller already
//     computed (small in-memory bodies: provenance envelopes, SBOM and
//     Sigstore sidecars). No scratch file is created at all.
//   - Put remains for callers that genuinely cannot pre-stage. It buffers
//     streams up to PutMemoryBytes in memory and spools larger streams
//     through the configured staging budget's directory (never the bare
//     system temp directory); without a configured budget an oversized
//     stream fails closed with ErrNoSpool.
//
// Every publication validates the object the BACKEND reports: a backend that
// answers with a different key, digest or size is a typed ErrBackendIntegrity
// failure and nothing is acknowledged. The CAS never substitutes locally
// computed values for the backend's answer.
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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// ErrDigestMismatch is reported by Open's reader when the streamed content
// does not hash to the requested digest, and by PutKnown/PutFile when the
// streamed content does not hash to the digest the caller advertised. It
// surfaces at EOF (Read returning the error, or Close when the consumer
// never read to EOF) on the read path, and as the publication result on the
// write path.
var ErrDigestMismatch = errors.New("cas: content digest mismatch")

// ErrBlobTooLarge is returned when the stream exceeds MaxBlobBytes.
var ErrBlobTooLarge = errors.New("cas: blob exceeds maximum size")

// ErrSizeMismatch is returned when the content does not have the size the
// caller advertised: a stream longer or shorter than size, or a staged file
// whose length is not the advertised size. Nothing is published.
var ErrSizeMismatch = errors.New("cas: content size does not match the advertised size")

// ErrBackendIntegrity is returned when the blob backend accepted a write but
// reported an object that disagrees with the key, digest or size the CAS
// published. Publication fails closed and the reported object is never
// overwritten with locally computed values and presented as verified.
var ErrBackendIntegrity = errors.New("cas: blob backend reported an inconsistent object")

// ErrNoSpool reports that Put must buffer a stream larger than
// PutMemoryBytes and no staging budget is configured for its scratch space.
// It fails closed instead of falling back to an unbounded system temp
// directory.
var ErrNoSpool = errors.New("cas: stream exceeds the in-memory bound and no staging budget is configured")

// DefaultMaxBlobBytes is the default per-object size bound (4 GiB) applied
// by the write APIs when MaxBlobBytes is not configured.
const DefaultMaxBlobBytes int64 = 4 << 30

// DefaultPutMemoryBytes is the default in-memory bound (1 MiB) of Put, the
// legacy non-pre-staged write path. Streams that fit are published straight
// from memory; larger streams spool through the configured staging budget.
const DefaultPutMemoryBytes int64 = 1 << 20

type CAS struct {
	Blobs blob.Store
	// MaxBlobBytes bounds a single object. Zero/negative means the
	// DefaultMaxBlobBytes default.
	MaxBlobBytes int64
	// Staging is the bounded scratch budget Put spools oversized (larger
	// than PutMemoryBytes) streams through: the spool file lives in the
	// budget's directory under the staging package's FilePrefix, so an
	// abandoned file is reclaimed by its Prune. Nil means oversized streams
	// fail closed (ErrNoSpool). The staged publication APIs (PutFile,
	// PutKnown) never need it.
	Staging *staging.Budget
	// PutMemoryBytes bounds Put's in-memory buffer for streams it has not
	// been told about. Zero/negative means the DefaultPutMemoryBytes default.
	PutMemoryBytes int64
}

func New(b blob.Store) *CAS { return &CAS{Blobs: b} }

// maxBytes resolves the effective per-object size bound.
func (c *CAS) maxBytes() int64 {
	if c.MaxBlobBytes <= 0 {
		return DefaultMaxBlobBytes
	}
	return c.MaxBlobBytes
}

// putMemoryBytes resolves the effective in-memory bound of Put, clamped to
// the per-object bound.
func (c *CAS) putMemoryBytes() int64 {
	mem := c.PutMemoryBytes
	if mem <= 0 {
		mem = DefaultPutMemoryBytes
	}
	if limit := c.maxBytes(); mem > limit {
		mem = limit
	}
	return mem
}

// countingReader is the bounded counting reader enforcing a byte bound: it
// counts every byte that passes and fails the stream with the over-limit
// error as soon as the bound would be exceeded, so over-limit content is
// never published. over defaults to ErrBlobTooLarge and is overridden by
// PutKnown/PutFile (ErrSizeMismatch) to report advertised-size violations.
type countingReader struct {
	r    io.Reader
	max  int64
	read int64
	err  error
	over error
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	room := c.max + 1 - c.read
	if room <= 0 {
		c.err = c.overError()
		return 0, c.err
	}
	if int64(len(p)) > room {
		p = p[:room]
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	if c.read > c.max {
		c.err = c.overError()
		return n, c.err
	}
	if err != nil {
		// Latch the source's terminal outcome (io.EOF included) so
		// putStream can tell "the stream ended early" from "the backend
		// stopped reading".
		c.err = err
	}
	return n, err
}

func (c *countingReader) overError() error {
	if c.over != nil {
		return c.over
	}
	return ErrBlobTooLarge
}

// validateKey rejects anything that is not a canonical SHA-256 hex digest.
func validateKey(key string) error {
	if len(key) != 64 {
		return fmt.Errorf("cas: invalid digest %q", key)
	}
	if _, err := hex.DecodeString(key); err != nil {
		return fmt.Errorf("cas: invalid digest %q", key)
	}
	return nil
}

// Put publishes a stream whose digest is unknown to the caller. The stream is
// buffered in memory up to PutMemoryBytes; a larger stream is spooled through
// the configured staging budget's directory (never a bare system temp
// directory) and streamed from there, and fails closed with ErrNoSpool when
// no staging budget is configured. Prefer PutFile/PutKnown on the upload
// paths: they publish bytes that are already staged and never copy them.
func (c *CAS) Put(ctx context.Context, r io.Reader) (blob.Object, error) {
	limit := c.maxBytes()
	mem := c.putMemoryBytes()
	h := sha256.New()
	var buf bytes.Buffer
	n, err := io.Copy(io.MultiWriter(&buf, h), &countingReader{r: r, max: mem})
	if err == nil {
		// The whole stream fit in memory: publish straight from the buffer.
		return c.putStream(ctx, hex.EncodeToString(h.Sum(nil)), n, bytes.NewReader(buf.Bytes()))
	}
	if !errors.Is(err, ErrBlobTooLarge) || mem >= limit {
		// Either a genuine reader error or a stream past the per-object
		// bound (the in-memory bound was clamped to it).
		return blob.Object{}, err
	}
	if c.Staging == nil {
		return blob.Object{}, fmt.Errorf("%w: %d bytes buffered, in-memory bound is %d", ErrNoSpool, n, mem)
	}
	// The bytes already buffered are hashed; the remaining stream is hashed
	// while SpoolFile writes it, so the digest covers the whole stream.
	src := io.MultiReader(bytes.NewReader(buf.Bytes()), io.TeeReader(r, h))
	path, total, spoolErr := staging.SpoolFile(c.Staging.Dir(), src, limit)
	if spoolErr != nil {
		if errors.Is(spoolErr, staging.ErrTooLarge) {
			return blob.Object{}, ErrBlobTooLarge
		}
		return blob.Object{}, spoolErr
	}
	defer os.Remove(path)
	f, openErr := os.Open(path)
	if openErr != nil {
		return blob.Object{}, openErr
	}
	defer f.Close()
	return c.putStream(ctx, hex.EncodeToString(h.Sum(nil)), total, f)
}

// PutFile publishes an already-staged file without a second copy: the bytes
// stream from path into the backend while the digest is verified, and the
// backend's reported object must match the published key, digest and size.
// The caller keeps ownership of path (the CAS never removes it) and remains
// responsible for holding its staging reservation until the publication and
// the durable record that references it no longer need the bytes.
func (c *CAS) PutFile(ctx context.Context, path string, digest string, size int64) (blob.Object, error) {
	if err := validateKey(digest); err != nil {
		return blob.Object{}, err
	}
	if size < 0 {
		return blob.Object{}, fmt.Errorf("%w: negative advertised size %d", ErrSizeMismatch, size)
	}
	if size > c.maxBytes() {
		return blob.Object{}, ErrBlobTooLarge
	}
	f, err := os.Open(path)
	if err != nil {
		return blob.Object{}, err
	}
	defer f.Close()
	if fi, serr := f.Stat(); serr != nil {
		return blob.Object{}, serr
	} else if fi.Size() != size {
		return blob.Object{}, fmt.Errorf("%w: staged file is %d bytes, advertised %d", ErrSizeMismatch, fi.Size(), size)
	}
	return c.putStream(ctx, digest, size, f)
}

// PutKnown publishes a reader whose digest and size the caller already
// computed (small in-memory bodies). The stream is verified against the
// advertised digest and size while it is written — a caller that lies about
// either fails closed — and no scratch file is created.
func (c *CAS) PutKnown(ctx context.Context, digest string, size int64, r io.Reader) (blob.Object, error) {
	if err := validateKey(digest); err != nil {
		return blob.Object{}, err
	}
	if size < 0 {
		return blob.Object{}, fmt.Errorf("%w: negative advertised size %d", ErrSizeMismatch, size)
	}
	if size > c.maxBytes() {
		return blob.Object{}, ErrBlobTooLarge
	}
	return c.putStream(ctx, digest, size, r)
}

// putStream is the one publication sequence shared by every write API: the
// content streams to the backend while it is counted and hashed, the byte
// count must be exactly the advertised size, the digest must hash to the
// published key, and the backend's returned object must agree with all
// three. Every disagreement is a typed error and nothing is acknowledged
// (a backend that already rejects the content for the same reason has its
// error replaced by the typed one so callers can branch deterministically).
//
// A backend that returns success WITHOUT reading the stream (blob.FS
// short-circuits to its deduplicating path when the object already exists)
// is accepted with the same object validation: the stored bytes are then
// proven by the caller's read-back re-hash (CAS.Open hashes while
// streaming), which is the defense in depth every publication path keeps.
func (c *CAS) putStream(ctx context.Context, key string, size int64, r io.Reader) (blob.Object, error) {
	h := sha256.New()
	cr := &countingReader{r: r, max: size, over: ErrSizeMismatch}
	obj, putErr := c.Blobs.Put(ctx, key, io.TeeReader(cr, h), size)
	// A stream that produced more than the advertised size fails the
	// counting reader itself: an over-long object is never published.
	if errors.Is(putErr, ErrSizeMismatch) || errors.Is(cr.err, ErrSizeMismatch) {
		return blob.Object{}, fmt.Errorf("%w: advertised size %d", ErrSizeMismatch, size)
	}
	// The whole stream was consumed: its digest must be the published key,
	// regardless of whether the backend verified it or rejected it.
	if cr.read == size {
		if got := hex.EncodeToString(h.Sum(nil)); got != key {
			if putErr != nil {
				return blob.Object{}, fmt.Errorf("%w: want %s, got %s: %v", ErrDigestMismatch, key, got, putErr)
			}
			return blob.Object{}, fmt.Errorf("%w: want %s, got %s", ErrDigestMismatch, key, got)
		}
	}
	if putErr != nil {
		// The source ended early (EOF before the advertised size): a typed
		// size mismatch, not an opaque backend error.
		if cr.read < size && errors.Is(cr.err, io.EOF) {
			return blob.Object{}, fmt.Errorf("%w: stream ended after %d bytes, advertised %d", ErrSizeMismatch, cr.read, size)
		}
		return blob.Object{}, putErr
	}
	switch {
	case cr.read == size:
		// Verified above.
	case cr.read == 0:
		// The backend short-circuited: an object with this key already
		// exists (a deduplicating backend never reads the stream then).
		// Its stored bytes are proven by the caller's read-back re-hash.
	default:
		// The backend reported success after consuming only part of the
		// stream: the published object cannot be the advertised content.
		return blob.Object{}, fmt.Errorf("%w: read %d bytes, advertised %d", ErrSizeMismatch, cr.read, size)
	}
	if err := checkBackendObject(obj, key, size); err != nil {
		return blob.Object{}, err
	}
	return obj, nil
}

// checkBackendObject validates the object the backend reported against what
// the CAS published. The reported object is returned unchanged by the write
// APIs: a disagreement is never masked by substituting computed values.
func checkBackendObject(obj blob.Object, key string, size int64) error {
	if obj.Key != key || obj.SHA256 != key || obj.Size != size {
		return fmt.Errorf("%w: published key %s size %d; backend reported key %q sha256 %q size %d",
			ErrBackendIntegrity, key, size, obj.Key, obj.SHA256, obj.Size)
	}
	return nil
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
