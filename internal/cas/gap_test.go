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

type stubStore struct {
	putErr    error
	openRC    io.ReadCloser
	openObj   blob.Object
	openErr   error
	deleteErr error
}

func (s *stubStore) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	if s.putErr != nil {
		return blob.Object{}, s.putErr
	}
	return blob.Object{Key: key, SHA256: key, Size: size}, nil
}

func (s *stubStore) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	return s.openRC, s.openObj, s.openErr
}

func (s *stubStore) Delete(ctx context.Context, key string) error { return s.deleteErr }

// TestCountingReaderStickyErrorAndClamp exercises the bounded counting
// reader directly: the byte bound clamps an oversized read, the over-limit
// read fails with ErrBlobTooLarge, and every later read keeps returning the
// same error without touching the source again.
func TestCountingReaderStickyErrorAndClamp(t *testing.T) {
	src := &countingSource{chunks: [][]byte{[]byte("ab"), []byte("cd")}}
	cr := &countingReader{r: src, max: 1}
	buf := make([]byte, 8)
	// First read asks for 8 bytes; room is max+1-read = 2 so the request is
	// clamped to 2 and overruns the bound.
	n, err := cr.Read(buf)
	if n != 2 || !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("first read = (%d, %v), want (2, ErrBlobTooLarge)", n, err)
	}
	// The sticky error short-circuits later reads; the source is untouched.
	before := src.reads
	if n, err := cr.Read(buf); n != 0 || !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("second read = (%d, %v), want (0, ErrBlobTooLarge)", n, err)
	}
	if src.reads != before {
		t.Fatalf("sticky error read from source: %d -> %d reads", before, src.reads)
	}
}

type countingSource struct {
	chunks [][]byte
	reads  int
}

func (c *countingSource) Read(p []byte) (int, error) {
	c.reads++
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := c.chunks[0]
	c.chunks = c.chunks[1:]
	return copy(p, chunk), nil
}

// TestCASPutStoreError proves a failing blob store surfaces its error from
// Put unchanged.
func TestCASPutStoreError(t *testing.T) {
	boom := errors.New("store exploded")
	c := New(&stubStore{putErr: boom})
	if _, err := c.Put(context.Background(), bytes.NewReader([]byte("x"))); !errors.Is(err, boom) {
		t.Fatalf("Put = %v, want %v", err, boom)
	}
}

// TestCASPutTempDirFailure proves a failing os.CreateTemp surfaces its error.
func TestCASPutTempDirFailure(t *testing.T) {
	// Create the temp dir before pointing TMPDIR at a nonexistent path.
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	t.Setenv("TMPDIR", missing)
	c := New(blob.NewFS(t.TempDir()))
	if _, err := c.Put(context.Background(), bytes.NewReader([]byte("x"))); err == nil {
		t.Fatal("Put with unusable TMPDIR succeeded, want error")
	}
	if os.Getenv("TMPDIR") != missing {
		t.Fatal("TMPDIR override did not apply")
	}
}

// TestCASPutSeekFailure proves a failing seek on the temp file surfaces its
// error instead of writing a corrupt object.
func TestCASPutSeekFailure(t *testing.T) {
	orig := fileSeek
	fileSeek = func(f *os.File, off int64, whence int) (int64, error) {
		return 0, errors.New("seek refused")
	}
	defer func() { fileSeek = orig }()
	c := New(blob.NewFS(t.TempDir()))
	if _, err := c.Put(context.Background(), bytes.NewReader([]byte("x"))); err == nil {
		t.Fatal("Put with failing seek succeeded, want error")
	}
}

// TestVerifyingReaderReadAfterError proves the verifying reader latches its
// error: after a digest mismatch or an EOF, later reads return the same
// outcome and never re-read the source.
func TestVerifyingReaderReadAfterError(t *testing.T) {
	data := []byte("verifying reader payload")
	sum := sha256.Sum256([]byte("something else"))
	v := &verifyingReader{
		r:    io.NopCloser(bytes.NewReader(data)),
		h:    sha256.New(),
		want: hex.EncodeToString(sum[:]),
	}
	buf := make([]byte, 4)
	for {
		if _, err := v.Read(buf); err != nil {
			if !errors.Is(err, ErrDigestMismatch) {
				t.Fatalf("read = %v, want ErrDigestMismatch", err)
			}
			break
		}
	}
	if _, err := v.Read(buf); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("read after mismatch = %v, want ErrDigestMismatch", err)
	}
	if err := v.Close(); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("close after mismatch = %v, want ErrDigestMismatch", err)
	}

	// Clean content: the terminal EOF latches as well.
	ok := sha256.Sum256(data)
	clean := &verifyingReader{r: io.NopCloser(bytes.NewReader(data)), h: sha256.New(), want: hex.EncodeToString(ok[:])}
	if _, err := io.ReadAll(clean); err != nil {
		t.Fatalf("clean read: %v", err)
	}
	if _, err := clean.Read(buf); err != io.EOF {
		t.Fatalf("read after EOF = %v, want io.EOF", err)
	}
}

// TestVerifyingReaderUnderlyingReadError proves a non-EOF error from the
// underlying reader propagates unchanged.
func TestVerifyingReaderUnderlyingReadError(t *testing.T) {
	boom := errors.New("transport gone")
	v := &verifyingReader{r: errReadCloser{err: boom}, h: sha256.New()}
	if _, err := v.Read(make([]byte, 4)); !errors.Is(err, boom) {
		t.Fatalf("read = %v, want %v", err, boom)
	}
	if _, err := v.Read(make([]byte, 4)); !errors.Is(err, boom) {
		t.Fatalf("latched read = %v, want %v", err, boom)
	}
}

type errReadCloser struct{ err error }

func (e errReadCloser) Read(p []byte) (int, error) { return 0, e.err }
func (e errReadCloser) Close() error               { return nil }

// TestCASOpenStoreError proves a failing store Open propagates.
func TestCASOpenStoreError(t *testing.T) {
	boom := errors.New("open failed")
	c := New(&stubStore{openErr: boom})
	if _, _, err := c.Open(context.Background(), "aa"); !errors.Is(err, boom) {
		t.Fatalf("Open = %v, want %v", err, boom)
	}
}

// TestCASDeleteStoreError proves Delete delegates to the store error.
func TestCASDeleteStoreError(t *testing.T) {
	boom := errors.New("delete failed")
	c := New(&stubStore{deleteErr: boom})
	if err := c.Delete(context.Background(), "aa"); !errors.Is(err, boom) {
		t.Fatalf("Delete = %v, want %v", err, boom)
	}
}
