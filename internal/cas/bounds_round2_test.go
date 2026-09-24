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
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
)

// sizeSuccessBackend consumes the whole stream but returns success with an
// object consistent with the advertised key and size, so it bypasses the
// backend's own digest/size checks and lets the CAS verification run.
type sizeSuccessBackend struct{}

func (sizeSuccessBackend) Put(_ context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	_, _ = io.Copy(io.Discard, r)
	return blob.Object{Key: key, SHA256: key, Size: size}, nil
}
func (sizeSuccessBackend) Open(context.Context, string) (io.ReadCloser, blob.Object, error) {
	return nil, blob.Object{}, blob.ErrNotFound
}
func (sizeSuccessBackend) Delete(context.Context, string) error { return nil }

// TestValidateKeyRejectsNonHex pins the canonical-digest validation.
func TestValidateKeyRejectsNonHex(t *testing.T) {
	if err := validateKey(strings.Repeat("z", 64)); err == nil {
		t.Fatal("non-hex 64-char key accepted")
	}
	if err := validateKey(strings.Repeat("a", 63)); err == nil {
		t.Fatal("short key accepted")
	}
	if err := validateKey(strings.Repeat("a", 64)); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
}

// TestCountingReaderZeroRoom covers the sticky error arm taken when the room
// is already exhausted.
func TestCountingReaderZeroRoom(t *testing.T) {
	cr := &countingReader{r: bytes.NewReader([]byte("data")), max: 1, read: 2}
	if n, err := cr.Read(make([]byte, 4)); n != 0 || !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("exhausted read = (%d, %v), want (0, ErrBlobTooLarge)", n, err)
	}
}

// TestPutFileAndPutKnownInputErrors covers the validation arms of both staged
// publish APIs.
func TestPutFileAndPutKnownInputErrors(t *testing.T) {
	ctx := context.Background()
	c := New(sizeSuccessBackend{})
	valid := strings.Repeat("a", 64)

	if _, err := c.PutFile(ctx, "missing", valid, -1); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("PutFile negative size = %v, want ErrSizeMismatch", err)
	}
	c.MaxBlobBytes = 4
	if _, err := c.PutFile(ctx, "missing", valid, 8); !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("PutFile oversize = %v, want ErrBlobTooLarge", err)
	}
	c.MaxBlobBytes = 0
	if _, err := c.PutFile(ctx, "missing", valid, 2); err == nil {
		t.Fatal("PutFile missing file succeeded")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "staged")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutFile(ctx, path, valid, 5); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("PutFile stat mismatch = %v, want ErrSizeMismatch", err)
	}

	if _, err := c.PutKnown(ctx, "nothex", 1, bytes.NewReader([]byte("x"))); err == nil {
		t.Fatal("PutKnown invalid digest succeeded")
	}
	if _, err := c.PutKnown(ctx, valid, -1, bytes.NewReader(nil)); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("PutKnown negative size = %v, want ErrSizeMismatch", err)
	}
	c.MaxBlobBytes = 4
	if _, err := c.PutKnown(ctx, valid, 8, bytes.NewReader(nil)); !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("PutKnown oversize = %v, want ErrBlobTooLarge", err)
	}
	c.MaxBlobBytes = 0
}

// TestPutStreamDigestAndSizeArms covers the digest-mismatch and partial-read
// publication arms with a backend that consumes the stream but reports
// success.
func TestPutStreamDigestAndSizeArms(t *testing.T) {
	ctx := context.Background()
	c := New(sizeSuccessBackend{})
	content := []byte("payload")
	good := sha256.Sum256(content)
	wrong := strings.Repeat("b", 64)

	if _, err := c.PutKnown(ctx, wrong, int64(len(content)), bytes.NewReader(content)); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("digest mismatch = %v, want ErrDigestMismatch", err)
	}
	if _, err := c.PutKnown(ctx, hex.EncodeToString(good[:]), int64(len(content))+4, bytes.NewReader(content)); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("partial read = %v, want ErrSizeMismatch", err)
	}
}
