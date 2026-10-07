package cas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
)

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func casObjectPath(root, digest string) string {
	return filepath.Join(root, "sha256", digest[:2], digest)
}

func seedCAS(t *testing.T, c *CAS, data []byte) string {
	t.Helper()
	digest := digestBytes(data)
	if _, err := c.PutKnown(context.Background(), digest, int64(len(data)), bytes.NewReader(data)); err != nil {
		t.Fatalf("seed PutKnown: %v", err)
	}
	return digest
}

func readCAS(t *testing.T, c *CAS, digest string) []byte {
	t.Helper()
	rc, _, err := c.Open(context.Background(), digest)
	if err != nil {
		t.Fatalf("Open %s: %v", digest, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %s: %v", digest, err)
	}
	return b
}

// TestCASPutKnownHealsSameSizeBitrot is the core dedup-integrity regression:
// a stored object corrupted in place (same size, different bytes) must NOT be
// trusted by the FS dedup shortcut. CAS opens and hashes the pre-existing
// object, detects the mismatch, atomically heals it from the supplied reader,
// and returns verified metadata that provenance-like callers can record.
func TestCASPutKnownHealsSameSizeBitrot(t *testing.T) {
	root := t.TempDir()
	c := New(blob.NewFS(root))
	data := []byte("provenance envelope payload")
	digest := seedCAS(t, c, data)

	// Same-size bitrot: the stored bytes no longer hash to their key.
	corrupt := bytes.Repeat([]byte("X"), len(data))
	path := casObjectPath(root, digest)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	rc, _, err := c.Open(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(rc)
	_ = rc.Close()
	if !errors.Is(readErr, ErrDigestMismatch) {
		t.Fatalf("corrupt stored object read = %v, want ErrDigestMismatch", readErr)
	}

	// The dedup hit is now verified and healed instead of trusted.
	obj, err := c.PutKnown(context.Background(), digest, int64(len(data)), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("PutKnown over a corrupt dedup hit: %v", err)
	}
	// A caller that only consumes the returned metadata gets verified values.
	if obj.Key != digest || obj.SHA256 != digest || obj.Size != int64(len(data)) {
		t.Fatalf("healed metadata = %+v, want key/sha256 %s size %d", obj, digest, len(data))
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
		t.Fatalf("stored bytes after heal = %q, want %q", got, data)
	}
	if got := readCAS(t, c, digest); !bytes.Equal(got, data) {
		t.Fatalf("Open after heal = %q, want %q", got, data)
	}
}

// TestCASPutFileHealsSameSizeBitrot proves the contract lives in the shared
// publication path: the staged-file API heals a corrupt dedup hit too.
func TestCASPutFileHealsSameSizeBitrot(t *testing.T) {
	root := t.TempDir()
	c := New(blob.NewFS(root))
	data := []byte("staged heal payload")
	path, digest := stagedFile(t, data)
	if _, err := c.PutFile(context.Background(), path, digest, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Repeat([]byte("Z"), len(data))
	objectPath := casObjectPath(root, digest)
	if err := os.WriteFile(objectPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	obj, err := c.PutFile(context.Background(), path, digest, int64(len(data)))
	if err != nil {
		t.Fatalf("PutFile over a corrupt dedup hit: %v", err)
	}
	if obj.Key != digest || obj.Size != int64(len(data)) {
		t.Fatalf("healed metadata = %+v", obj)
	}
	if got := readCAS(t, c, digest); !bytes.Equal(got, data) {
		t.Fatalf("Open after heal = %q, want %q", got, data)
	}
}

// TestCASPutKnownWrongPayloadAgainstCorruptObjectFailsClosed proves a
// same-size DIFFERENT payload can never be installed as the replacement: the
// heal verifies the supplied stream against the digest before the rename, so
// a reader that does not hash to the key fails and the destination is left
// untouched rather than silently accepted.
func TestCASPutKnownWrongPayloadAgainstCorruptObjectFailsClosed(t *testing.T) {
	root := t.TempDir()
	c := New(blob.NewFS(root))
	data := []byte("original payload bytes")
	digest := seedCAS(t, c, data)

	corrupt := bytes.Repeat([]byte("X"), len(data))
	path := casObjectPath(root, digest)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte("Y"), len(data))
	if digestBytes(wrong) == digest {
		t.Fatal("test payload collides with the stored digest")
	}

	obj, err := c.PutKnown(context.Background(), digest, int64(len(data)), bytes.NewReader(wrong))
	if err == nil {
		t.Fatalf("same-size wrong payload was silently accepted: %+v", obj)
	}
	if !errors.Is(err, ErrDigestMismatch) && !errors.Is(err, ErrBackendIntegrity) {
		t.Fatalf("wrong-payload heal error = %v, want a digest or integrity failure", err)
	}
	if got, _ := os.ReadFile(path); bytes.Equal(got, wrong) {
		t.Fatal("failed heal installed the different payload")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, corrupt) {
		t.Fatalf("failed heal modified the destination: %q", got)
	}
}

// openCountingBackend counts the Opens the CAS performs on the underlying FS
// store, so a test can prove the dedup hit verifies the stored object.
type openCountingBackend struct {
	inner *blob.FS
	opens int
}

func (b *openCountingBackend) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	return b.inner.Put(ctx, key, r, size)
}

func (b *openCountingBackend) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	b.opens++
	return b.inner.Open(ctx, key)
}

func (b *openCountingBackend) Delete(ctx context.Context, key string) error {
	return b.inner.Delete(ctx, key)
}

// trackingReader records whether anything consumed the caller's stream.
type trackingReader struct {
	r     io.Reader
	reads int
}

func (r *trackingReader) Read(p []byte) (int, error) {
	r.reads++
	return r.r.Read(p)
}

// TestCASPutKnownDedupFastPathVerifiesStoredObjectWithoutReadingReader pins
// the valid dedup fast path: the pre-existing object is opened and hashed,
// while the caller's untouched reader is never consumed.
func TestCASPutKnownDedupFastPathVerifiesStoredObjectWithoutReadingReader(t *testing.T) {
	backend := &openCountingBackend{inner: blob.NewFS(t.TempDir())}
	c := New(backend)
	data := []byte("valid dedup payload")
	digest := seedCAS(t, c, data)
	opensBefore := backend.opens

	r := &trackingReader{r: bytes.NewReader(data)}
	obj, err := c.PutKnown(context.Background(), digest, int64(len(data)), r)
	if err != nil {
		t.Fatalf("valid dedup PutKnown: %v", err)
	}
	if r.reads != 0 {
		t.Fatalf("dedup fast path consumed the caller's reader (%d reads)", r.reads)
	}
	if backend.opens <= opensBefore {
		t.Fatal("dedup hit was accepted without opening the stored object")
	}
	if obj.Key != digest || obj.SHA256 != digest || obj.Size != int64(len(data)) {
		t.Fatalf("dedup metadata = %+v", obj)
	}
}

// vanishingBackend consumes nothing, reports success, and has no stored
// object: the dedup verification must fail closed rather than acknowledge an
// unverified reference, and with no atomic-replace capability it cannot heal
// either.
type vanishingBackend struct{}

func (vanishingBackend) Put(_ context.Context, key string, _ io.Reader, size int64) (blob.Object, error) {
	return blob.Object{Key: key, SHA256: key, Size: size}, nil
}

func (vanishingBackend) Open(context.Context, string) (io.ReadCloser, blob.Object, error) {
	return nil, blob.Object{}, blob.ErrNotFound
}

func (vanishingBackend) Delete(context.Context, string) error { return nil }

// TestCASDedupOnMissingObjectFailsClosed proves a backend that reports
// success while storing nothing is rejected with ErrBackendIntegrity.
func TestCASDedupOnMissingObjectFailsClosed(t *testing.T) {
	c := New(vanishingBackend{})
	data := []byte("nothing was stored")
	digest := digestBytes(data)
	if _, err := c.PutKnown(context.Background(), digest, int64(len(data)), bytes.NewReader(data)); !errors.Is(err, ErrBackendIntegrity) {
		t.Fatalf("missing-object dedup = %v, want ErrBackendIntegrity", err)
	}
}
