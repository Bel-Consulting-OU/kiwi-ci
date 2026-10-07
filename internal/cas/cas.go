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
// When the backend answers without consuming the caller's stream (a dedup
// hit, for example blob.FS's existing-object shortcut), the caller's stream
// proves nothing about the stored object: the CAS then opens and hashes the
// pre-existing object, returns it only when both digest and size match, and
// atomically heals a mismatch from the supplied (untouched) reader. A heal
// that cannot complete fails with ErrBackendIntegrity, so no caller — not
// even one that only consumes the returned metadata, as provenance does —
// can record an unverified dedup reference.
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
	"math"
	"os"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/progress"
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
//
// ctx, when set, is the request context of the publication: every successful
// read counts as a unit of real byte progress and pulses it (see
// internal/progress), so a backend that keeps consuming an 8 GiB stream is
// never mistaken for an idle streaming request. A nil ctx makes the reader
// silent (direct CAS callers pay nothing).
type countingReader struct {
	r    io.Reader
	max  int64
	read int64
	err  error
	over error
	ctx  context.Context
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	// Compute the room for one byte PAST the bound (the over-limit probe
	// byte) without overflowing int64 when max is math.MaxInt64: the naive
	// max+1-read wraps to a negative room and would fail a legal stream
	// immediately. With read <= max, max-read is non-negative and cannot
	// wrap; the +1 is skipped only in the MaxInt64 corner, where no
	// physically reachable stream can exceed the bound anyway.
	if c.read > c.max {
		c.err = c.overError()
		return 0, c.err
	}
	room := c.max - c.read
	if room < math.MaxInt64 {
		room++
	}
	if room <= 0 {
		c.err = c.overError()
		return 0, c.err
	}
	if int64(len(p)) > room {
		p = p[:room]
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	if n > 0 {
		progress.Pulse(c.ctx)
	}
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
	n, err := io.Copy(io.MultiWriter(&buf, h), &countingReader{r: r, max: mem, ctx: ctx})
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
	// Charge the spool's worst-case disk amount BEFORE writing a byte: the
	// spool file can hold the whole stream, up to the per-object bound, so
	// concurrent Put callers serialize on the budget instead of each staging
	// a full-size file unaccounted. The reservation is held until the
	// publication (and its read of the staged file) is done, and released on
	// every exit path, so Budget.Used() always accounts the in-flight spool.
	res, aerr := c.Staging.Acquire(ctx, limit)
	if aerr != nil {
		if errors.Is(aerr, staging.ErrBudgetExceeded) {
			return blob.Object{}, fmt.Errorf("%w: %d bytes can never fit the %d-byte staging budget",
				ErrBlobTooLarge, limit, c.Staging.MaxBytes())
		}
		return blob.Object{}, aerr
	}
	defer res.Release()
	// The bytes already buffered are hashed; the remaining stream is hashed
	// while SpoolFile writes it, so the digest covers the whole stream.
	src := io.MultiReader(bytes.NewReader(buf.Bytes()), io.TeeReader(r, h))
	path, total, spoolErr := c.Staging.SpoolFile(src, limit)
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
// either fails closed — and no scratch file is created. When the backend
// deduplicates (it consumes none of the stream), the pre-existing object is
// hashed in place and healed on mismatch before the returned metadata is
// acknowledged (see putStream).
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
// cannot prove the stored bytes from the accepted stream, so the CAS opens
// the pre-existing object, hashes it, and returns success for the dedup hit
// only when both the digest and the size match. A mismatch heals the object
// from the caller's still-untouched reader through the backend's
// atomic-replace path, and a heal that cannot be completed is a typed
// integrity failure rather than an acknowledged, unverified reference.
func (c *CAS) putStream(ctx context.Context, key string, size int64, r io.Reader) (blob.Object, error) {
	h := sha256.New()
	// ctx is carried into the counting reader so every byte the backend
	// consumes pulses the streaming progress callback: an S3 put of a huge
	// staged file is real progress even though the client socket is silent
	// for the whole publication.
	cr := &countingReader{r: r, max: size, over: ErrSizeMismatch, ctx: ctx}
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
	case cr.read == 0:
		// The backend consumed none of the caller's reader: it either
		// short-circuited to a pre-existing object (the FS dedup path) or
		// never read the stream at all. The stored bytes were therefore NOT
		// proven by this publication, so the CAS verifies them now and
		// heals a mismatch from the supplied (untouched) reader.
		return c.verifyDedupHit(ctx, key, size, r, obj)
	case cr.read == size:
		// The stream was fully consumed and hashed, so the bytes the
		// backend received are the advertised content (the digest check
		// above ran).
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

// verifyDedupHit is the dedup branch of putStream: the backend returned
// success without consuming the caller's reader, so the object it reports
// already existed and its stored bytes are unverified. The stored object is
// opened and hashed; when the digest and size match, the backend's report is
// validated and returned. On a mismatch (same-size bitrot included) the
// object is healed atomically from the caller's still-untouched reader and
// the healed object is returned. A heal that cannot be completed — no
// atomic-replace capability, or a supplied stream that does not hash to the
// key — is a typed ErrBackendIntegrity failure that forces the caller to
// rebuild; a bad object is never silently acknowledged, and the CAS never
// substitutes locally computed values for a verified backend answer.
func (c *CAS) verifyDedupHit(ctx context.Context, key string, size int64, r io.Reader, obj blob.Object) (blob.Object, error) {
	storedErr := c.verifyStoredObject(ctx, key, size)
	if storedErr == nil {
		if err := checkBackendObject(obj, key, size); err != nil {
			return blob.Object{}, err
		}
		return obj, nil
	}
	healed, healErr := c.healStoredObject(ctx, key, size, r)
	if healErr != nil {
		return blob.Object{}, fmt.Errorf("%w: stored object %s failed verification (%v) and could not be healed: %w",
			ErrBackendIntegrity, key, storedErr, healErr)
	}
	return healed, nil
}

// verifyStoredObject opens the object at key and proves its stored bytes are
// exactly the content the digest addresses: the CAS verifying reader hashes
// the stream while it is read, the backend-reported size and the actual byte
// count must both equal size, and the digest must equal key. Any
// disagreement (a missing object included) is returned as a plain mismatch
// for the dedup branch to heal.
func (c *CAS) verifyStoredObject(ctx context.Context, key string, size int64) error {
	rc, obj, err := c.Open(ctx, key)
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			return fmt.Errorf("stored object %s is missing", key)
		}
		return fmt.Errorf("stored object %s cannot be opened: %w", key, err)
	}
	defer rc.Close()
	if obj.Size != size {
		return fmt.Errorf("stored object %s is %d bytes, advertised %d", key, obj.Size, size)
	}
	n, err := io.Copy(io.Discard, rc)
	if err != nil {
		return fmt.Errorf("stored object %s failed verification: %w", key, err)
	}
	if n != size {
		return fmt.Errorf("stored object %s yielded %d bytes, advertised %d", key, n, size)
	}
	return nil
}

// healStoredObject replaces a dedup hit whose stored bytes failed verification
// using the caller's untouched reader. The stream is counted and hashed while
// it is written, exactly like putStream, so a reader that lies about its
// digest or size can never replace the destination with different bad bytes;
// the replacement itself must go through the backend's atomic-replace path
// (blob.Replacer), which stages and verifies before the rename. The returned
// object is the backend's validated replacement.
func (c *CAS) healStoredObject(ctx context.Context, key string, size int64, r io.Reader) (blob.Object, error) {
	replacer, ok := c.Blobs.(blob.Replacer)
	if !ok {
		return blob.Object{}, fmt.Errorf("%w: backend %T has no atomic-replace capability", ErrBackendIntegrity, c.Blobs)
	}
	h := sha256.New()
	cr := &countingReader{r: r, max: size, over: ErrSizeMismatch, ctx: ctx}
	obj, err := replacer.Replace(ctx, key, io.TeeReader(cr, h), size)
	if errors.Is(err, ErrSizeMismatch) || errors.Is(cr.err, ErrSizeMismatch) {
		return blob.Object{}, fmt.Errorf("%w: supplied stream is not the advertised %d bytes", ErrSizeMismatch, size)
	}
	if err != nil {
		return blob.Object{}, err
	}
	if cr.read != size {
		return blob.Object{}, fmt.Errorf("%w: supplied stream produced %d bytes, advertised %d", ErrSizeMismatch, cr.read, size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != key {
		return blob.Object{}, fmt.Errorf("%w: supplied stream hashes to %s, not %s", ErrDigestMismatch, got, key)
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
//
// The returned reader carries ctx: every successful read counts as a unit of
// real byte progress and pulses it (see internal/progress). A download that
// spends minutes streaming a large object out of CAS/S3 before the first
// client byte is written is therefore never mistaken for an idle streaming
// request by the app's inactivity guard.
func (c *CAS) Open(ctx context.Context, sha256hex string) (io.ReadCloser, blob.Object, error) {
	rc, obj, err := c.Blobs.Open(ctx, sha256hex)
	if err != nil {
		return nil, blob.Object{}, err
	}
	return &verifyingReader{r: rc, h: sha256.New(), want: sha256hex, ctx: ctx}, obj, nil
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
// silently accept corrupted content. ctx, when set, receives a progress
// pulse for every successful read (see internal/progress).
type verifyingReader struct {
	r    io.ReadCloser
	h    hash.Hash
	want string
	done bool
	err  error
	ctx  context.Context
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	if v.err != nil {
		return 0, v.err
	}
	n, err := v.r.Read(p)
	if n > 0 {
		_, _ = v.h.Write(p[:n])
		progress.Pulse(v.ctx)
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
