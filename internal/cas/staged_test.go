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

// stagedFile writes data to a fresh file and returns its path and digest.
func stagedFile(t *testing.T, data []byte) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "staged")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return path, hex.EncodeToString(sum[:])
}

// TestCASPutFilePublishesStagedFile proves the staged-content API streams an
// already-staged file into the backend with no second copy and returns the
// exact object the backend reported.
func TestCASPutFilePublishesStagedFile(t *testing.T) {
	data := []byte("staged content addressed payload")
	path, digest := stagedFile(t, data)
	c := New(blob.NewFS(t.TempDir()))
	obj, err := c.PutFile(context.Background(), path, digest, int64(len(data)))
	if err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	if obj.Key != digest || obj.SHA256 != digest || obj.Size != int64(len(data)) {
		t.Fatalf("object = %+v, want key/sha256/size %s/%s/%d", obj, digest, digest, len(data))
	}
	rc, _, err := c.Open(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(rc)
	_ = rc.Close()
	if readErr != nil || !bytes.Equal(got, data) {
		t.Fatalf("read back = %q (%v), want %q", got, readErr, data)
	}
	// The caller keeps ownership of the staged file.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("PutFile removed the caller's staged file: %v", err)
	}
}

// TestCASPutFileRejectsAdvertisedMismatch proves a staged file that does not
// match the advertised digest or size is rejected with a typed error and
// never published.
func TestCASPutFileRejectsAdvertisedMismatch(t *testing.T) {
	data := []byte("staged mismatch payload")
	path, digest := stagedFile(t, data)

	t.Run("wrong digest", func(t *testing.T) {
		c := New(blob.NewFS(t.TempDir()))
		other := sha256.Sum256([]byte("different content"))
		_, err := c.PutFile(context.Background(), path, hex.EncodeToString(other[:]), int64(len(data)))
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("PutFile with a wrong digest = %v, want ErrDigestMismatch", err)
		}
	})
	t.Run("wrong size", func(t *testing.T) {
		c := New(blob.NewFS(t.TempDir()))
		if _, err := c.PutFile(context.Background(), path, digest, int64(len(data))+1); !errors.Is(err, ErrSizeMismatch) {
			t.Fatalf("PutFile with a too-large size = %v, want ErrSizeMismatch", err)
		}
		if _, err := c.PutFile(context.Background(), path, digest, int64(len(data))-1); !errors.Is(err, ErrSizeMismatch) {
			t.Fatalf("PutFile with a too-small size = %v, want ErrSizeMismatch", err)
		}
	})
	t.Run("over object bound", func(t *testing.T) {
		c := New(blob.NewFS(t.TempDir()))
		c.MaxBlobBytes = 4
		if _, err := c.PutFile(context.Background(), path, digest, int64(len(data))); !errors.Is(err, ErrBlobTooLarge) {
			t.Fatalf("PutFile over MaxBlobBytes = %v, want ErrBlobTooLarge", err)
		}
	})
	t.Run("invalid digest", func(t *testing.T) {
		c := New(blob.NewFS(t.TempDir()))
		if _, err := c.PutFile(context.Background(), path, "not-a-digest", int64(len(data))); err == nil {
			t.Fatal("PutFile with an invalid digest succeeded")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		c := New(blob.NewFS(t.TempDir()))
		if _, err := c.PutFile(context.Background(), filepath.Join(t.TempDir(), "absent"), digest, int64(len(data))); err == nil {
			t.Fatal("PutFile with a missing staged file succeeded")
		}
	})
}

// TestCASPutKnownPublishesInMemoryContent proves the known-digest API
// publishes content whose digest and size the caller computed, and rejects
// a caller that lies about either.
func TestCASPutKnownPublishesInMemoryContent(t *testing.T) {
	c := New(blob.NewFS(t.TempDir()))
	data := []byte(`{"statement":"known payload"}`)
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	obj, err := c.PutKnown(context.Background(), digest, int64(len(data)), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("PutKnown: %v", err)
	}
	if obj.Key != digest || obj.SHA256 != digest || obj.Size != int64(len(data)) {
		t.Fatalf("object = %+v", obj)
	}
	// Wrong digest: typed mismatch, nothing acknowledged.
	other := sha256.Sum256([]byte("other"))
	if _, err := c.PutKnown(context.Background(), hex.EncodeToString(other[:]), int64(len(data)), bytes.NewReader(data)); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("PutKnown with a wrong digest = %v, want ErrDigestMismatch", err)
	}
	// Wrong size (short stream), fresh store so the stream is actually
	// consumed: typed mismatch.
	fresh := New(blob.NewFS(t.TempDir()))
	if _, err := fresh.PutKnown(context.Background(), digest, int64(len(data))+8, bytes.NewReader(data)); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("PutKnown with a too-large size = %v, want ErrSizeMismatch", err)
	}
	// Wrong size (long stream): typed mismatch, and the over-long byte is
	// never published.
	long := append(append([]byte(nil), data...), 'x')
	fresh = New(blob.NewFS(t.TempDir()))
	if _, err := fresh.PutKnown(context.Background(), digest, int64(len(data)), bytes.NewReader(long)); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("PutKnown with a too-small size = %v, want ErrSizeMismatch", err)
	}
	// A deduplicating backend never reads the stream, so an advertised size
	// that disagrees with the existing object is caught by the
	// backend-object validation instead of the stream check.
	if _, err := c.PutKnown(context.Background(), digest, int64(len(data))+8, bytes.NewReader(data)); !errors.Is(err, ErrBackendIntegrity) {
		t.Fatalf("PutKnown size disagreement on a dedup hit = %v, want ErrBackendIntegrity", err)
	}
}

// lyingBackend wraps a real store and corrupts the object it reports, with
// the stored bytes left correct, so only the backend-result validation can
// catch the disagreement.
type lyingBackend struct {
	inner *blob.FS
	mode  string
}

func (b *lyingBackend) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	obj, err := b.inner.Put(ctx, key, r, size)
	if err != nil {
		return obj, err
	}
	switch b.mode {
	case "size":
		obj.Size = obj.Size + 1
	case "key":
		obj.Key = "0" + obj.Key[1:]
	case "sha":
		obj.SHA256 = "f" + obj.SHA256[1:]
	}
	return obj, nil
}

func (b *lyingBackend) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	return b.inner.Open(ctx, key)
}

func (b *lyingBackend) Delete(ctx context.Context, key string) error { return b.inner.Delete(ctx, key) }

// TestCASPublicationFailsClosedOnLyingBackend is the O1-C regression: a
// backend that reports the wrong size, key or digest for correctly stored
// bytes fails every write API with the typed ErrBackendIntegrity, and the
// CAS never rewrites the answer with locally computed values.
func TestCASPublicationFailsClosedOnLyingBackend(t *testing.T) {
	for _, mode := range []string{"size", "key", "sha"} {
		t.Run(mode, func(t *testing.T) {
			data := []byte("lying backend payload")
			path, digest := stagedFile(t, data)
			c := New(&lyingBackend{inner: blob.NewFS(t.TempDir()), mode: mode})

			_, err := c.PutFile(context.Background(), path, digest, int64(len(data)))
			if !errors.Is(err, ErrBackendIntegrity) {
				t.Fatalf("PutFile against a lying backend = %v, want ErrBackendIntegrity", err)
			}
			_, err = c.PutKnown(context.Background(), digest, int64(len(data)), bytes.NewReader(data))
			if !errors.Is(err, ErrBackendIntegrity) {
				t.Fatalf("PutKnown against a lying backend = %v, want ErrBackendIntegrity", err)
			}
			_, err = c.Put(context.Background(), bytes.NewReader(data))
			if !errors.Is(err, ErrBackendIntegrity) {
				t.Fatalf("Put against a lying backend = %v, want ErrBackendIntegrity", err)
			}
		})
	}
}

// TestCASPublicationsNeverTouchSystemTempDir proves the staged and known
// APIs create no scratch file at all: with TMPDIR pointed at a healthy,
// observable directory, maximum-size (in the test: the endpoint-sized)
// publications leave it empty — and they still succeed when TMPDIR is
// unusable, because nothing is written there.
func TestCASPublicationsNeverTouchSystemTempDir(t *testing.T) {
	systemTmp := t.TempDir()
	t.Setenv("TMPDIR", systemTmp)
	data := bytes.Repeat([]byte("pub"), 1<<16)
	path, digest := stagedFile(t, data)
	c := New(blob.NewFS(t.TempDir()))

	if _, err := c.PutFile(context.Background(), path, digest, int64(len(data))); err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	sum := sha256.Sum256([]byte("known payload"))
	if _, err := c.PutKnown(context.Background(), hex.EncodeToString(sum[:]), int64(len("known payload")), bytes.NewReader([]byte("known payload"))); err != nil {
		t.Fatalf("PutKnown: %v", err)
	}
	if entries, err := os.ReadDir(systemTmp); err != nil || len(entries) != 0 {
		t.Fatalf("publication touched the system temp dir (%d entries, %v)", len(entries), err)
	}
}

// TestCASPublicationsSucceedWithUnusableSystemTempDir proves the publication
// paths do not depend on TMPDIR at all: with TMPDIR pointing at a read-only
// directory, the staged and known APIs still succeed.
func TestCASPublicationsSucceedWithUnusableSystemTempDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permission bits")
	}
	// Every test-owned directory is created BEFORE TMPDIR is made unusable
	// (t.TempDir itself resolves TMPDIR).
	systemTmp := t.TempDir()
	fsRoot := t.TempDir()
	data := []byte("unusable tmpdir payload")
	path, digest := stagedFile(t, data)
	if err := os.Chmod(systemTmp, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(systemTmp, 0o700) })
	t.Setenv("TMPDIR", systemTmp)

	c := New(blob.NewFS(fsRoot))
	if _, err := c.PutFile(context.Background(), path, digest, int64(len(data))); err != nil {
		t.Fatalf("PutFile with an unwritable TMPDIR: %v", err)
	}
	sum := sha256.Sum256(data)
	if _, err := c.PutKnown(context.Background(), hex.EncodeToString(sum[:]), int64(len(data)), bytes.NewReader(data)); err != nil {
		t.Fatalf("PutKnown with an unwritable TMPDIR: %v", err)
	}
}
